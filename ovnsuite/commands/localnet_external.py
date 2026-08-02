"""
ovnctl localnet-external -- port of ovn-localnet-external.sh

Logical router POLICY that forces traffic to the ASA even when the ordinary
route table would have kept it inside OVN.

WHAT CHANGED FROM THE SHELL VERSION
The shell script still built a second physical uplink (br-asa on its own
NIC, ls-ext-asa, lrp-asa) and called require_cfg for keys that no longer
exist in ovn-settings.yaml -- [localnet_external].br_asa, .phys_nic,
.ln_asa, .lrp_asa, .ls_ext_asa, .policy_priority and the whole
[asa_addressing] section. The settings file documents that the second NIC
is gone and this section is POLICY ONLY. As written, the script aborted on
a clean checkout.

So: the policy tiers are the primary path and always run. The physical
uplink steps still exist and run ONLY if the legacy keys are present, so a
deployment that still has the second NIC keeps working unchanged.

Priority tiers (higher is evaluated first):
  300 source-override : listed VMs go to the ASA regardless of destination
  250 engagement      : per-job client subnets
  200 shadow          : anything addressed into shadow space -> ASA
  150 external        : positively-declared external ranges -> ASA
  100 split           : "src subnet AND not internal"
"""

from __future__ import annotations

import argparse

from .. import identity, netcalc, ovn, paths
from ..config import load_legacy_ranges
from ..context import Abort, Ctx
from ..state import LOCALNET_EXTERNAL, Tracker, record
from ..steps import StepRunner, add_step_args

NAME = "localnet-external"
HELP = "ASA reroute policy tiers (+ legacy split-path uplink if configured)"

REQUIRED_CFG = (
    "engagement:priority_target",
    "localnet_external:split_subnet",
    "policy:fail_on_unresolved_overlap", "policy:priority_external",
    "policy:priority_shadow", "policy:priority_source_override",
    "policy:priority_split",
    "setup:lrp_ext", "setup:lrp_ext_mac", "topology:lr_core",
)

# Keys that only exist in the pre-single-NIC layout.
LEGACY_KEYS = ("br_asa", "phys_nic", "physnet_label", "ls_ext_asa",
               "ln_asa", "lrp_asa", "lrp_asa_mac")


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--remove", action="store_true",
                   help="tear down just this path (policies, and the legacy "
                        "uplink if present)")
    g.add_argument("--trace", nargs=2, metavar=("SRC", "DST"),
                   help="ovn-trace a packet through lr-core")
    g.add_argument("--add-target", metavar="CIDR",
                   help="record an engagement target subnet and re-apply policy")
    g.add_argument("--del-target", metavar="CIDR",
                   help="remove an engagement target subnet and re-apply policy")
    g.add_argument("--list-targets", action="store_true",
                   help="show the configured engagement targets")
    g.add_argument("--clear-targets", action="store_true",
                   help="remove every engagement target (end of engagement)")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class LocalnetExternal:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.lr_core = c.cfg("topology", "lr_core")
        self.split_subnet = c.cfg("localnet_external", "split_subnet")

        # --- the ASA next hop -----------------------------------------
        # Empty next_hop means "use [localnet_internal].lan_gateway", which
        # is the ASA. Set it only if the ASA is a different device sharing
        # the same transit link.
        self.transit_subnet = c.cfg_opt("localnet_internal", "transit_subnet", "")
        self.lan_gateway = c.cfg_opt("localnet_internal", "lan_gateway", "")
        explicit = (c.cfg_opt("asa_addressing", "next_hop", "")
                    or c.cfg_opt("localnet_external", "next_hop", ""))
        self.next_hop = explicit or self.lan_gateway
        self._explicit_next_hop = bool(explicit)

        # --- range lists ----------------------------------------------
        self.internal_ranges = self._load_internal_ranges()
        self.external_ranges = c.cfg_list("external_ranges", "ranges")
        self.shadow_ranges = c.cfg_list("shadow_ranges", "ranges")
        self.external_only_ips = c.cfg_list("policy", "external_only_ips")
        self.target_subnets = c.cfg_list("engagement", "target_subnets")
        self.snat_address = c.cfg_opt("engagement", "snat_address", "")

        # --- priorities -----------------------------------------------
        self.prio_src_override = c.cfg("policy", "priority_source_override")
        # The "internal destinations are not rerouted" half of the split.
        # Must outrank priority_split; it is what replaces the negated
        # destination match that used to live in that rule.
        self.prio_split_allow = c.cfg_opt("policy", "priority_split_allow",
                                          "110")
        self.prio_target = c.cfg("engagement", "priority_target")
        self.prio_shadow = c.cfg("policy", "priority_shadow")
        self.prio_external = c.cfg("policy", "priority_external")
        self.prio_split = c.cfg("policy", "priority_split")
        self.fail_on_overlap = c.cfg_bool("policy", "fail_on_unresolved_overlap",
                                          True)

        # --- legacy physical uplink (optional) -------------------------
        self.legacy = all(c.has("localnet_external", k) for k in LEGACY_KEYS)
        if self.legacy:
            self.phys_nic = c.cfg("localnet_external", "phys_nic")
            self.br_asa = c.cfg("localnet_external", "br_asa")
            self.asa_physnet = c.cfg("localnet_external", "physnet_label")
            self.ls_ext_asa = c.cfg("localnet_external", "ls_ext_asa")
            self.ln_asa = c.cfg("localnet_external", "ln_asa")
            self.lrp_asa = c.cfg("localnet_external", "lrp_asa")
            self.lrp_asa_mac = c.cfg("localnet_external", "lrp_asa_mac")
            self.asa_transit_ip = c.cfg_opt("asa_addressing", "transit_ip", "")
            self.gw_priority = c.cfg_opt("localnet_external",
                                         "gateway_chassis_priority", "10")

    # ------------------------------------------------------------------
    def _load_internal_ranges(self) -> list[str]:
        """yaml [internal_ranges] > the legacy conf > blanket RFC1918.

        This is NOT "all of RFC1918": the external-to-us network reachable
        through the ASA also uses RFC1918 addressing, so that
        classification is invalid here.
        """
        ctx = self.ctx
        ranges = ctx.config.cfg_array("internal_ranges", "ranges")
        if ranges:
            ctx.log("Internal ranges loaded from ovn-settings.yaml [internal_ranges].")
            return ranges

        legacy_path = paths.ranges_file()
        legacy = load_legacy_ranges(legacy_path)
        if legacy:
            ctx.log(f"Internal ranges loaded from {legacy_path} (legacy conf).")
            return legacy

        ctx.warn("no [internal_ranges] in yaml and no")
        ctx.warn(f"{legacy_path} found.")
        ctx.warn("Falling back to a blanket RFC1918 exclusion --")
        ctx.warn("this WILL misroute traffic to any RFC1918 range")
        ctx.warn("used by the external-to-us network. Fix by adding")
        ctx.warn("the ranges to ovn-settings.yaml [internal_ranges].")
        return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    # ------------------------------------------------------------------
    def check_lr_core(self) -> None:
        ctx = self.ctx
        if ovn.lr_exists(ctx, self.lr_core):
            return
        if ctx.dry_run:
            ctx.warn(f"Logical router '{self.lr_core}' does not exist "
                     "(dry-run: continuing).")
            return
        raise Abort(f"Logical router '{self.lr_core}' does not exist. "
                    "Run `ovnctl setup` first.")

    # -- 0 ---------------------------------------------------------------
    def validate_ranges(self) -> None:
        """Validate the range lists BEFORE touching anything.

        A single prefix cannot have two next-hops, so an unresolved overlap
        is a genuine configuration error -- say so instead of silently
        picking one.
        """
        ctx = self.ctx
        ctx.log("Validating range lists...")

        bad = False
        for label, ranges in (("[internal_ranges]", self.internal_ranges),
                              ("[external_ranges]", self.external_ranges),
                              ("[shadow_ranges]", self.shadow_ranges),
                              ("[engagement].target_subnets", self.target_subnets)):
            for entry in netcalc.validate_ranges(ranges, label):
                ctx.err(f"'{entry}' in {label} is not a valid IPv4 CIDR.")
                bad = True
        if bad:
            raise Abort("Fix the malformed CIDR(s) above in ovn-settings.yaml "
                        "and re-run.")

        self._validate_next_hop()

        if not self.external_ranges:
            ctx.log("No [external_ranges] declared -- using exclusion-only policy")
            ctx.log("(original behaviour; nothing to collide).")
            return

        overlaps = netcalc.find_overlaps(self.internal_ranges, self.external_ranges)
        if not overlaps:
            ctx.log("Internal and external ranges are disjoint -- no ambiguity.")
            return

        ctx.warn("OVERLAP DETECTED between [internal_ranges] and [external_ranges]:")
        for i, e, d in overlaps:
            ctx.warn(f"  internal {i}  vs  external {e}   -> collides on {d}")

        if self.shadow_ranges:
            ctx.log(f"Shadow space IS configured ({' '.join(self.shadow_ranges)}) "
                    "-- the overlap is")
            ctx.log("resolvable: reach the colliding external hosts via their shadow")
            ctx.log("addresses (ASA does the DNAT/SNAT), and the real addresses stay")
            ctx.log("reachable internally. Both realms usable, no internal re-IP.")
            ctx.log("REMINDER: the matching static NAT entries must exist on the ASA.")
            return

        ctx.warn("No [shadow_ranges] configured, so this overlap is UNRESOLVED:")
        ctx.warn("  the colliding addresses can be reached via ONE path only, and")
        ctx.warn("  which one wins is decided purely by policy priority.")
        ctx.warn("Options: (a) add a shadow range + ASA NAT mappings [recommended],")
        ctx.warn("  (b) narrow the ranges to more-specific non-colliding prefixes,")
        ctx.warn("  (c) add the affected VMs to [policy].external_only_ips so their")
        ctx.warn("      traffic skips destination matching entirely.")
        if self.fail_on_overlap:
            raise Abort("Refusing to apply an ambiguous policy\n"
                        "(set policy.fail_on_unresolved_overlap: false to override).")
        ctx.warn("fail_on_unresolved_overlap is false -- continuing anyway.")

    def _validate_next_hop(self) -> None:
        """The next hop must sit inside the transit subnet.

        A reroute to an off-link next hop cannot be resolved, so refuse
        rather than installing a black hole. (The settings file documents
        this rule; the shell version never actually enforced it.)
        """
        ctx = self.ctx
        if not self.next_hop:
            raise Abort(
                "No ASA next hop: [localnet_external].next_hop is empty and\n"
                "[localnet_internal].lan_gateway is not set either. One of them\n"
                "must name the ASA's address on the transit link."
            )
        if not netcalc.cidr_valid(self.next_hop):
            raise Abort(f"next_hop '{self.next_hop}' is not a valid IPv4 address.")
        if not self.transit_subnet:
            ctx.log("No [localnet_internal].transit_subnet -- cannot verify the "
                    "next hop is on-link.")
            return
        if netcalc.cidr_contains(self.transit_subnet, self.next_hop):
            ctx.log(f"Next hop {self.next_hop} is inside the transit subnet "
                    f"{self.transit_subnet}.")
            return
        message = (
            f"ASA next hop {self.next_hop} is NOT inside the transit subnet "
            f"{self.transit_subnet}.\n"
            "A reroute to an off-link next hop cannot be resolved -- the policy "
            "would be a black hole.\n"
            "Fix [localnet_external].next_hop, or leave it empty to use "
            "[localnet_internal].lan_gateway."
        )
        if self._explicit_next_hop:
            raise Abort(message)
        ctx.warn(message)

    # ------------------------------------------------------------------
    # legacy physical uplink -- only when the old keys are present
    # ------------------------------------------------------------------
    def legacy_bridge_nic(self) -> None:
        ctx = self.ctx
        if not self.legacy:
            ctx.log("Single-NIC deployment: no ASA bridge to build "
                    "(this section is policy only).")
            return
        ctx.dr_head("ASA bridge + NIC")
        ctx.log(f"Setting up {self.br_asa} with uplink {self.phys_nic}...")

        if not ctx.q("ip", "link", "show", self.phys_nic).ok:
            if ctx.dry_run:
                ctx.warn(f"Interface {self.phys_nic} does not exist "
                         "(dry-run: continuing).")
            else:
                raise Abort(f"Interface {self.phys_nic} does not exist on this host.")

        if ctx.have("nmcli"):
            if ctx.run("nmcli", "device", "set", self.phys_nic, "managed", "no"):
                ctx.log(f"Set {self.phys_nic} unmanaged in NetworkManager.")
            else:
                ctx.warn(f"Could not set {self.phys_nic} unmanaged "
                         "(may not be known to NetworkManager, that's fine).")
        else:
            ctx.log("nmcli not present, skipping NetworkManager unmanage step.")

        if not ovn.br_exists(ctx, self.br_asa):
            ctx.run("ovs-vsctl", "add-br", self.br_asa)
            ctx.log(f"Created bridge {self.br_asa}.")
        else:
            ctx.log(f"Bridge {self.br_asa} already exists.")

        if self.phys_nic not in ovn.list_ports(ctx, self.br_asa):
            ctx.run("ovs-vsctl", "add-port", self.br_asa, self.phys_nic)
            ctx.log(f"Added {self.phys_nic} to {self.br_asa}.")

        ctx.run("ip", "link", "set", self.br_asa, "up")

        if "inet " in ctx.qout("ip", "addr", "show", "dev", self.phys_nic):
            ctx.warn(f"{self.phys_nic} still has an IP address assigned. "
                     "Remove it manually --")
            ctx.warn("OVN, not the kernel, should own addressing on this path.")

    def legacy_bridge_mapping(self) -> None:
        ctx = self.ctx
        if not self.legacy:
            return
        ctx.dr_head("Bridge mapping")
        mapping = f"{self.asa_physnet}:{self.br_asa}"
        ctx.log(f"Adding {mapping} to ovn-bridge-mappings...")
        existing = ovn.external_id(ctx, "ovn-bridge-mappings")
        if not existing:
            ctx.run("ovs-vsctl", "set", "open", ".",
                    f"external-ids:ovn-bridge-mappings={mapping}")
        elif mapping in existing:
            ctx.log(f"Mapping already present in: {existing}")
        else:
            # Extend, never overwrite -- the internal path's mapping must survive.
            ctx.log(f"Extending existing bridge-mappings ({existing})...")
            ctx.run("ovs-vsctl", "set", "open", ".",
                    f"external-ids:ovn-bridge-mappings={existing},{mapping}")

    def legacy_transit_switch(self) -> None:
        ctx = self.ctx
        if not self.legacy:
            return
        ctx.dr_head("Transit switch + localnet port")
        ctx.log(f"Creating transit switch {self.ls_ext_asa} with localnet port "
                f"{self.ln_asa}...")
        ctx.run("ovn-nbctl", "--may-exist", "ls-add", self.ls_ext_asa)
        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.ls_ext_asa, self.ln_asa)
        ctx.run("ovn-nbctl", "lsp-set-type", self.ln_asa, "localnet")
        ctx.run("ovn-nbctl", "lsp-set-addresses", self.ln_asa, "unknown")
        ctx.run("ovn-nbctl", "lsp-set-options", self.ln_asa,
                f"network_name={self.asa_physnet}")

    def legacy_attach_router(self) -> None:
        ctx = self.ctx
        if not self.legacy:
            return
        ctx.dr_head("Router port + gateway chassis")
        ctx.log(f"Attaching {self.lr_core} to {self.ls_ext_asa} via "
                f"{self.lrp_asa} ({self.asa_transit_ip})...")

        if not ovn.lrp_present(ctx, self.lr_core, self.lrp_asa):
            ctx.run("ovn-nbctl", "lrp-add", self.lr_core, self.lrp_asa,
                    self.lrp_asa_mac, self.asa_transit_ip)
        else:
            ctx.log(f"{self.lrp_asa} already exists on {self.lr_core}.")

        peer = f"{self.ls_ext_asa}-to-lr"
        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.ls_ext_asa, peer)
        ctx.run("ovn-nbctl", "lsp-set-type", peer, "router")
        ctx.run("ovn-nbctl", "lsp-set-addresses", peer, "router")
        ctx.run("ovn-nbctl", "lsp-set-options", peer, f"router-port={self.lrp_asa}")

        # Same rule as the internal uplink: pin to the CONFIGURED identity,
        # never to "whatever chassis the SB db lists first". See
        # identity.pin_target().
        chassis = identity.pin_target(ctx)
        ctx.log(f"Using chassis: {chassis}")
        identity.repin_gateway(ctx, self.lrp_asa, chassis, self.gw_priority)

    # ------------------------------------------------------------------
    # the policy tiers
    # ------------------------------------------------------------------
    def _policy_replace(self, priority: str, signature: str, match: str,
                        action: str = "reroute") -> None:
        """Replace any policy at <priority> whose match contains <signature>.

        Keeps re-runs idempotent even when the range lists change between
        runs. `allow` policies take no next-hop -- they mean "stop policy
        evaluation and route normally".
        """
        ctx = self.ctx
        for uuid, existing_match in ovn.policies_with_match(ctx, priority):
            if signature in existing_match:
                ctx.run("ovn-nbctl", "lr-policy-del", self.lr_core, uuid)
        if action == "allow":
            ctx.run("ovn-nbctl", "lr-policy-add", self.lr_core, priority,
                    match, "allow")
        else:
            ctx.run("ovn-nbctl", "lr-policy-add", self.lr_core, priority,
                    match, "reroute", self.next_hop)

    def policy(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Reroute policy tiers")
        ctx.log(f"Building tiered reroute policies on {self.lr_core}...")
        ctx.log("(higher priority is evaluated first -- see [policy] in the yaml)")

        # --- Tier 1 (highest): source-based override -------------------
        # These VMs egress via the ASA regardless of destination. Because
        # destination isn't part of the match, ANY overlap between internal
        # and external ranges is irrelevant for them.
        if self.external_only_ips:
            ip_set = netcalc.set_literal(self.external_only_ips)
            ctx.log(f"  [{self.prio_src_override}] source-override: "
                    f"{len(self.external_only_ips)} VM(s) -> ASA (destination ignored)")
            self._policy_replace(self.prio_src_override, "ip4.src ==",
                                 f"ip4.src == {ip_set}")
        else:
            ctx.log(f"  [{self.prio_src_override}] source-override: "
                    "none configured, skipped.")

        # --- Tier 2: shadow space --------------------------------------
        # RFC6598 (or whatever is declared) always means "external, via the
        # ASA, which will DNAT to the real host". This is what makes a
        # genuinely overlapping destination reachable WITHOUT re-IPing our
        # internal infrastructure.
        if self.shadow_ranges:
            shadow_set = netcalc.set_literal(self.shadow_ranges)
            ctx.log(f"  [{self.prio_shadow}] shadow: "
                    f"{' '.join(self.shadow_ranges)} -> ASA")
            self._policy_replace(
                self.prio_shadow, f"ip4.dst == {shadow_set}",
                f"ip4.src == {self.split_subnet} && ip4.dst == {shadow_set}")
        else:
            ctx.log(f"  [{self.prio_shadow}] shadow: none configured, skipped.")

        # --- Tier 3: positively-declared external ranges ---------------
        if self.external_ranges:
            ext_set = netcalc.set_literal(self.external_ranges)
            ctx.log(f"  [{self.prio_external}] external: "
                    f"{' '.join(self.external_ranges)} -> ASA")
            self._policy_replace(
                self.prio_external, f"ip4.dst == {ext_set}",
                f"ip4.src == {self.split_subnet} && ip4.dst == {ext_set}")
        else:
            ctx.log(f"  [{self.prio_external}] external: none declared, skipped.")

        # --- Tier 2.5: engagement target subnets -----------------------
        # Positive match for client-supplied subnets, ABOVE the internal
        # exclusion. This is what lets an engagement run inside a subnet
        # that collides with our own addressing.
        if self.target_subnets:
            tgt_set = netcalc.set_literal(self.target_subnets)
            ctx.log(f"  [{self.prio_target}] engagement targets: "
                    f"{' '.join(self.target_subnets)} -> ASA")
            self._policy_replace(
                self.prio_target, f"ip4.dst == {tgt_set}",
                f"ip4.src == {self.split_subnet} && ip4.dst == {tgt_set}")
        else:
            ctx.log(f"  [{self.prio_target}] engagement targets: none listed "
                    "(unknown destinations")
            ctx.log(f"        are still covered by the priority-{self.prio_split} "
                    "rule below).")

        # --- Tier 4 (base): the original exclusion rule ----------------
        #
        # ONE negation against an address set, NOT one per range.
        #
        # This used to build "ip4.dst != A && ip4.dst != B && ..." with a
        # term per internal range. Each negated CIDR makes OVN's expression
        # engine compute the complement -- the set of prefixes covering the
        # whole of IPv4 except that one -- and ANDing six of those together
        # produces their CROSS PRODUCT. With five ranges this deployment
        # compiled to 345,000 OpenFlow rules on br-int and drove
        # ovn-controller to 14 GB resident while it expanded them; adding a
        # sixth range made it worse.
        #
        # An address set is one complement instead of six, and northd
        # handles it with a conjunctive match. Same semantics, and the
        # flow count stops being a function of how many ranges are declared.
        # NO NEGATION. Two positive policies instead of one negated match.
        #
        # This rule used to say "reroute everything from the VM subnet
        # EXCEPT our internal ranges", written as a negated destination.
        # Negation is where OVN's expression engine does its expensive
        # work: it computes the complement of each prefix -- every prefix
        # covering the rest of IPv4 -- and the intermediate result is
        # enormous even when the final flow count is not. Measured on this
        # deployment: FOUR logical flows cost 3 GB of ovn-controller
        # memory, and every logical port added afterwards multiplied it,
        # reaching 14 GB while producing no extra OpenFlow rules at all.
        # Moving from six negated terms to one address-set negation fixed
        # the flow count (345,000 -> 606) but not the cost of computing it.
        #
        # The same policy expressed positively:
        #
        #   higher priority: dst IS internal      -> allow (route normally)
        #   lower priority:  everything from src  -> reroute to the ASA
        #
        # `allow` means "stop evaluating policies and use the routing
        # table", so internal destinations fall through to their connected
        # routes exactly as the exclusions intended. Identical behaviour,
        # no complement to compute.
        as_ref = self._internal_address_set()

        ctx.log(f"  [{self.prio_split_allow}] internal destinations: route "
                f"normally (no reroute)")
        self._policy_replace(
            self.prio_split_allow, f"ip4.src == {self.split_subnet} &&",
            f"ip4.src == {self.split_subnet} && ip4.dst == {as_ref}",
            action="allow")

        ctx.log(f"  [{self.prio_split}] split (fall-through): everything else "
                f"from {self.split_subnet} -> ASA")
        self._policy_replace(self.prio_split,
                             f"ip4.src == {self.split_subnet}",
                             f"ip4.src == {self.split_subnet}")

        ctx.log("Policy tiers applied. Verify with: "
                f"ovn-nbctl lr-policy-list {self.lr_core}")

    def _internal_address_set(self) -> str:
        """Create or update the Address_Set holding [internal_ranges].

        Returns the "$name" reference to use in a match. Kept in sync on
        every run so a range added to the settings file cannot leave a
        stale set behind quietly widening the ASA bypass.
        """
        ctx = self.ctx
        name = ctx.config.cfg_opt("policy", "internal_address_set",
                                  "as_internal")
        addrs = ",".join(f'"{r}"' for r in self.internal_ranges)
        uuid = ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid", "find",
                        "Address_Set", f"name={name}").strip()
        if uuid:
            ctx.run("ovn-nbctl", "set", "Address_Set", uuid,
                    f"addresses=[{addrs}]")
        else:
            ctx.run("ovn-nbctl", "create", "Address_Set", f"name={name}",
                    f"addresses=[{addrs}]")
        return f"${name}"

    # ------------------------------------------------------------------
    def run_trace(self, src: str, dst: str) -> None:
        ctx = self.ctx
        ctx.require_cmd("ovn-trace")
        ctx.log(f"Tracing src={src} dst={dst} through {self.lr_core}...")
        print("")
        # inport + ttl matter: without an inport the router pipeline may not
        # evaluate admission/policy the way a real packet would, and a ttl
        # of 0 gets discarded at the routing stage.
        lrp_ext = ctx.cfg("setup", "lrp_ext")
        lrp_ext_mac = ctx.cfg("setup", "lrp_ext_mac")
        expr = (f'inport=="{lrp_ext}" && eth.dst=={lrp_ext_mac} && '
                f'ip4.src=={src} && ip4.dst=={dst} && ip.ttl==64 && icmp4')
        print(ovn.trace(ctx, self.lr_core, expr))

    # ------------------------------------------------------------------
    def teardown(self) -> None:
        ctx = self.ctx
        ctx.log("Removing ASA split-path config...")

        removed = 0
        for prio in (self.prio_src_override, self.prio_target, self.prio_shadow,
                     self.prio_external, self.prio_split):
            for uuid in ovn.policy_uuids(ctx, prio):
                if ctx.run("ovn-nbctl", "lr-policy-del", self.lr_core, uuid):
                    ctx.log(f"Removed policy {uuid} (priority {prio}).")
                    removed += 1
        if removed == 0:
            ctx.log("No matching policies found, skipping.")

        if not self.legacy:
            Tracker(ctx).unmark(LOCALNET_EXTERNAL)
            ctx.log("Removed 'localnet-external' from deployment tracker.")
            ctx.log("Done. Policy only -- there is no ASA bridge to remove.")
            return

        if ovn.lrp_present(ctx, self.lr_core, self.lrp_asa):
            if ctx.run("ovn-nbctl", "--if-exists", "lrp-del", self.lrp_asa):
                ctx.log(f"Removed router port {self.lrp_asa}.")

        if ctx.run("ovn-nbctl", "--if-exists", "ls-del", self.ls_ext_asa):
            ctx.log(f"Removed transit switch {self.ls_ext_asa}.")

        mapping = f"{self.asa_physnet}:{self.br_asa}"
        existing = ovn.external_id(ctx, "ovn-bridge-mappings")
        if mapping in existing:
            kept = [m for m in existing.split(",") if m and m != mapping]
            if kept:
                ctx.run("ovs-vsctl", "set", "open", ".",
                        f"external-ids:ovn-bridge-mappings={','.join(kept)}")
            else:
                ctx.run("ovs-vsctl", "remove", "open", ".", "external-ids",
                        "ovn-bridge-mappings")
            ctx.log(f"Removed {mapping} from ovn-bridge-mappings "
                    f"(kept: {','.join(kept) or 'none'}).")

        if self.phys_nic in ovn.list_ports(ctx, self.br_asa):
            if ctx.run("ovs-vsctl", "del-port", self.br_asa, self.phys_nic):
                ctx.log(f"Removed {self.phys_nic} from {self.br_asa}.")

        if ovn.br_exists(ctx, self.br_asa):
            if ctx.run("ovs-vsctl", "del-br", self.br_asa):
                ctx.log(f"Removed bridge {self.br_asa}.")

        if ctx.have("nmcli"):
            if ctx.run("nmcli", "device", "set", self.phys_nic, "managed", "yes"):
                ctx.log(f"Returned {self.phys_nic} to NetworkManager management.")

        Tracker(ctx).unmark(LOCALNET_EXTERNAL)
        ctx.log("Removed 'localnet-external' from deployment tracker.")
        ctx.log("Done. Note: the internal br-internal/physnet path is untouched.")

    # ------------------------------------------------------------------
    # engagement target management
    # ------------------------------------------------------------------
    def list_targets(self) -> int:
        ctx = self.ctx
        print("")
        print("=== Engagement targets ===")
        if not self.target_subnets:
            print("  (none listed)")
            print("")
            print("  Note: an empty list is NORMAL and usually correct.")
            print("  Anything not in [internal_ranges] already routes to the ASA")
            print(f"  via the priority-{self.prio_split} rule. Only list a subnet "
                  "here if it")
            print("  OVERLAPS one of our internal ranges.")
        else:
            for t in self.target_subnets:
                if netcalc.find_overlaps([t], self.internal_ranges):
                    print(f"  {t}   [overrides an internal range -- "
                          "this is why it is listed]")
                else:
                    print(f"  {t}   [no collision -- would route to the ASA anyway]")
        if self.snat_address:
            print("")
            print(f"  SNAT address issued to us: {self.snat_address}")
        print("")
        print(f"Internal ranges (ours): {' '.join(self.internal_ranges)}")
        print(f"ASA next hop:           {self.next_hop}")
        return 0

    def add_target(self, cidr: str) -> None:
        ctx = self.ctx
        if not netcalc.cidr_valid(cidr):
            raise Abort(f"'{cidr}' is not a valid IPv4 CIDR.")
        ctx.log(f"Adding engagement target {cidr}...")

        overlaps = netcalc.find_overlaps([cidr], self.internal_ranges)
        if overlaps:
            ctx.warn("This subnet OVERLAPS our internal ranges:")
            for a, b, d in overlaps:
                ctx.warn(f"  {a} vs internal {b} -> collides on {d}")
            ctx.warn(f"Effect: for VMs in {self.split_subnet}, those addresses "
                     "will now")
            ctx.warn("reach the CLIENT's hosts via the ASA, not ours. Machines on")
            ctx.warn("the internal switch are unaffected.")
            # The guest-side on-link trap.
            if netcalc.cidr_overlap(cidr, self.split_subnet):
                ctx.warn("")
                ctx.warn("SPECIAL CASE: it also overlaps the ext-vm subnet itself")
                ctx.warn(f"({self.split_subnet}). Guests treat their own subnet as "
                         "on-link and")
                ctx.warn("will ARP for those addresses instead of using the gateway --")
                ctx.warn("OVN never sees the packet, so this policy cannot redirect it.")
                ctx.warn("Those specific addresses need host routes inside each guest.")
        else:
            ctx.log("No collision with our internal ranges.")
            ctx.log(f"(This subnet would already route to the ASA via the "
                    f"priority-{self.prio_split}")
            ctx.log("rule, so listing it is harmless but not strictly required.)")

        ctx.config.list_add("engagement", "target_subnets", cidr)
        ctx.log("Recorded in ovn-settings.yaml. Re-applying policy...")

    def del_target(self, cidr: str) -> None:
        self.ctx.log(f"Removing engagement target {cidr}...")
        self.ctx.config.list_del("engagement", "target_subnets", cidr)
        self.ctx.log("Removed from ovn-settings.yaml. Re-applying policy...")

    def clear_targets(self) -> None:
        self.ctx.log("Clearing all engagement targets...")
        for t in list(self.target_subnets):
            self.ctx.config.list_del("engagement", "target_subnets", t)
            self.ctx.log(f"  removed {t}")
        self.ctx.log("Re-applying policy...")

    def reapply_after_target_change(self) -> None:
        """Reload and re-apply so the change takes effect immediately."""
        ctx = self.ctx
        self.target_subnets = ctx.config.cfg_list("engagement", "target_subnets")
        self.check_lr_core()
        self.policy()
        print("")
        ctx.log("Done. Current policies:")
        for line in ctx.q("ovn-nbctl", "lr-policy-list", self.lr_core).lines:
            print(f"  {line}")

    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        ctx = self.ctx
        print("")
        print("=== Split-path ASA gateway summary ===")
        if self.legacy:
            print(f"Bridge:          {self.br_asa} (uplink: {self.phys_nic})")
            print(f"Physnet label:   {self.asa_physnet}")
            print(f"Transit port:    {self.lrp_asa} ({self.asa_transit_ip}) "
                  f"on {self.ls_ext_asa}")
        else:
            print("Physical path:   none (single-NIC deployment -- everything "
                  "leaves via br-internal)")
        print(f"ASA next hop:    {self.next_hop}")
        print(f"Applies to:      traffic sourced from {self.split_subnet}")
        print(f"Excludes:        {' '.join(self.internal_ranges)}")
        print("")
        print(f"Current policies on {self.lr_core}:")
        for line in ctx.q("ovn-nbctl", "lr-policy-list", self.lr_core).lines:
            print(f"  {line}")
        print("")
        print("IMPORTANT -- manual step on the ASA:")
        print("  Add SNAT/DNAT rules bound to this interface, and confirm the ASA")
        print(f"  side is configured with {self.next_hop} on its end of the link.")
        print("  Reply traffic from a DNAT'd service naturally matches the same")
        print("  policy (dst was external on the way in, src is the VM's own IP")
        print("  on the way out, dst is external again) so this stays symmetric --")
        print("  no extra return-route juggling needed.")
        print("")
        print("Verify before testing live:")
        print(f"  ovn-nbctl lr-policy-list {self.lr_core}")
        print(f"  ovnctl localnet-external --trace <vm-ip-in-{self.split_subnet}> "
              f"8.8.8.8      # should show reroute to {self.next_hop}")
        print(f"  ovnctl localnet-external --trace <vm-ip-in-{self.split_subnet}> "
              "172.31.1.21  # should use normal route table")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-ext")
    ctx.require_cfg(*REQUIRED_CFG)

    ctx.require_root()
    ctx.require_cmd("ovs-vsctl", "ovn-nbctl", "ovn-sbctl", "ip")

    cmd = LocalnetExternal(ctx)

    if args.list_targets:
        return cmd.list_targets()

    if args.add_target or args.del_target or args.clear_targets:
        if args.add_target:
            cmd.add_target(args.add_target)
        elif args.del_target:
            cmd.del_target(args.del_target)
        else:
            cmd.clear_targets()
        cmd.reapply_after_target_change()
        return 0

    if args.remove:
        cmd.teardown()
        return 0

    if args.trace:
        cmd.run_trace(args.trace[0], args.trace[1])
        return 0

    runner = StepRunner(ctx, "localnet-external")
    runner.add("check-router", "verify lr-core exists", cmd.check_lr_core)
    runner.add("validate-ranges", "CIDR validity, overlap and next-hop checks",
               cmd.validate_ranges)
    runner.add("bridge-nic", "legacy: ASA bridge + NIC", cmd.legacy_bridge_nic)
    runner.add("bridge-mapping", "legacy: extend ovn-bridge-mappings",
               cmd.legacy_bridge_mapping)
    runner.add("transit-switch", "legacy: transit switch + localnet port",
               cmd.legacy_transit_switch)
    runner.add("attach-router", "legacy: router port + gateway chassis",
               cmd.legacy_attach_router)
    runner.add("policy", "the reroute policy tiers", cmd.policy)

    if not runner.run(args):
        return 0

    record(ctx, LOCALNET_EXTERNAL, runner)

    if ctx.verbose and not ctx.dry_run:
        cmd.print_summary()
    ctx.finish("ASA reroute policy tiers")
    return 0