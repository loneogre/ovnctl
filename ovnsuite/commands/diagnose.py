"""
ovnctl diagnose -- port of ovn-diagnose.sh

Walks the OVN/OVS stack layer by layer to find where connectivity is
breaking.

Deployment-tracker aware: checks are gated on what has actually been
deployed, so "gateway port missing" is only a FAIL if a localnet command
recorded itself as run, and a clean SKIP otherwise. Conversely, ambiguous
results become definitive: tracker says localnet-internal ran + no
chassisredirect port exists = hard FAIL, no hedging.

With NO tracker file, every check runs unconditionally -- the tracker is
advisory, the OVN db remains the source of truth.

FIXES CARRIED OVER FROM THE SHELL VERSION
  * check_isolation referenced $_iso_vms, which was never defined -- the
    live non-member proof silently picked the wrong VM (or none).
  * Three calls passed a default argument to cfg(), which takes two args
    and exits on a miss. Those are cfg_opt lookups here.
  * require_cfg demanded [localnet_external].br_asa / .phys_nic, which no
    longer exist in the settings file, so the whole script aborted before
    running a single check. Those are optional now.
"""

from __future__ import annotations

import argparse
import re

from .. import identity, netcalc, ovn
from ..context import Colour, Ctx
from ..inventory import Inventory
from ..state import (ACLS, LOCALNET_EXTERNAL, LOCALNET_INTERNAL, SETUP,
                     VM_CONFIG, VM_ISOLATION, Tracker)
from ..steps import StepRunner, add_step_args

NAME = "diagnose"
HELP = "layer-by-layer health check of the OVN/OVS stack"

PASS = "[ OK ]"
FAIL = "[FAIL]"
WARN = "[WARN]"
SKIP = "[SKIP]"


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class Diagnose:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.br_int = c.cfg_opt("topology", "br_int", "br-int")
        self.host_if = c.cfg_opt("topology", "host_if", "host-if")
        self.lr_core = c.cfg_opt("topology", "lr_core", "lr-core")
        self.ls_int = c.cfg_opt("topology", "ls_int", "ls-int-vm")
        self.ls_ext = c.cfg_opt("topology", "ls_ext", "ls-ext-vm")
        self.lrp_int = c.cfg_opt("diagnose", "lrp_int", "lrp-int-vm")
        self.gateway = c.cfg_opt("diagnose", "gateway", "172.31.1.10")
        self.host_ip = c.cfg_opt("setup", "host_if_ip", "")
        self.pg_name = c.cfg_opt("vm_isolation", "pg_name", "pg_isolated")
        # Set after the inventory is loaded -- see below. A hardcoded count
        # that has to be kept in step with a list by hand is a false
        # failure waiting to happen, and it duly happened when ext-vm1 was
        # added to [vm_isolation].isolated_vms.
        self._pg_expected_override = c.cfg_opt("diagnose",
                                               "pg_expected_members", "")

        # These two bridges may not exist at all in a single-NIC deployment.
        self.br_internal = c.cfg_opt("localnet_internal", "br_internal",
                                     "br-internal")
        self.br_asa = c.cfg_opt("localnet_external", "br_asa", "")
        self.nic_internal = c.cfg_opt("localnet_internal", "phys_nic", "")
        self.nic_asa = c.cfg_opt("localnet_external", "phys_nic", "")

        self.internal_ranges = c.cfg_list("internal_ranges", "ranges")
        self.external_ranges = c.cfg_list("external_ranges", "ranges")
        self.shadow_ranges = c.cfg_list("shadow_ranges", "ranges")
        self.external_only_ips = c.cfg_list("policy", "external_only_ips")
        self.target_subnets = c.cfg_list("engagement", "target_subnets")

        self.prio_src_override = c.cfg_opt("policy", "priority_source_override", "300")
        self.prio_target = c.cfg_opt("engagement", "priority_target", "250")
        self.prio_shadow = c.cfg_opt("policy", "priority_shadow", "200")
        self.prio_external = c.cfg_opt("policy", "priority_external", "150")
        self.prio_split = c.cfg_opt("policy", "priority_split", "100")

        self.inv = Inventory(c, self.ls_int, self.ls_ext)

        # DERIVED from [vm_isolation].isolated_vms, which is the list that
        # actually decides membership. The old [diagnose].pg_expected_members
        # key is honoured when set, for anyone who has a reason to assert a
        # different number, but it is no longer the default source of
        # truth -- two places to edit meant one of them was always stale.
        declared = len(self.inv.isolated_uuids)
        override = self._pg_expected_override.strip()
        if override.isdigit():
            self.pg_expected = int(override)
            if declared and self.pg_expected != declared:
                ctx.warn(f"[diagnose].pg_expected_members is {self.pg_expected} "
                         f"but [vm_isolation].isolated_vms lists {declared}.")
                ctx.warn("Using the configured override; remove the key to "
                         "follow the isolation list.")
        else:
            self.pg_expected = declared

        self.tracker = Tracker(ctx)
        self.has_tracker = self.tracker.exists()
        self.flags = self.tracker.flags()

        self.c = Colour()
        self.fail_count = 0
        self.warn_count = 0
        self.current_section = ""
        self.failed_sections: list[str] = []

        # Set by section 4. Later sections use it to decide whether
        # "restart ovn-controller" is sound advice or a way to make things
        # considerably worse -- with a drifted system-id a restart
        # registers a SECOND chassis and unbinds the gateway.
        self.identity_ok = True
        # Set by section 0 when the tracker predates the current boot.
        self.boot_stale = False
        # Set by section 7 so section 8 can name the cause instead of
        # reporting a second, derivative failure.
        self.host_if_down = False
        # The canonical name from the settings file, '' if unset.
        self.canonical_id = identity.configured_opt(ctx)

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------
    def section(self, title: str) -> None:
        self.current_section = title
        print(f"\n{self.c.bold}=== {title} ==={self.c.rst}")

    @staticmethod
    def detail(*lines: str) -> None:
        for line in lines:
            print(f"        {line}")

    @staticmethod
    def block(text: str) -> None:
        for line in str(text).splitlines():
            print(f"        {line}")

    def _tag(self, colour: str, tag: str, msg: str) -> None:
        """Only the tag is coloured.

        The message itself often wraps onto detail lines below it, and
        colouring a whole paragraph makes the escape codes outlive the line
        in anything that reflows the output.
        """
        print(f"{colour}{tag}{self.c.rst} {msg}")

    def ok(self, msg: str) -> None:
        self._tag(self.c.grn, PASS, msg)

    def bad(self, msg: str) -> None:
        self._tag(self.c.red + self.c.bold, FAIL, msg)
        self.fail_count += 1
        if self.current_section \
                and self.current_section not in self.failed_sections:
            self.failed_sections.append(self.current_section)

    def note(self, msg: str) -> None:
        self._tag(self.c.ylw, WARN, msg)
        self.warn_count += 1

    def skip(self, msg: str) -> None:
        self._tag(self.c.dim, SKIP, msg)

    def not_deployed(self, key: str) -> bool:
        """True if the tracker is active and says this was NOT deployed.

        With no tracker, always False -> every check runs (legacy behaviour).
        """
        return self.has_tracker and not self.flags.get(key, False)

    # ------------------------------------------------------------------
    # 0
    # ------------------------------------------------------------------
    def check_tracker(self) -> None:
        self.section("0. Deployment tracker")
        if not self.has_tracker:
            self.note("No tracker file found -- running ALL checks unconditionally.")
            self.note("(Deploy with the tracker in place to enable gating.)")
            return
        self.ok(f"Tracker active: {self.tracker.path}")
        self.block(self.tracker.show())
        f = self.flags
        self.detail(
            f"setup={f[SETUP]} localnet-internal={f[LOCALNET_INTERNAL]} "
            f"localnet-external={f[LOCALNET_EXTERNAL]}",
            f"vm-config={f[VM_CONFIG]} vm-isolation={f[VM_ISOLATION]} "
            f"acls={f[ACLS]}",
        )

        # Flags that violate the documented run order are suspicious.
        if not f[SETUP] and any(f[k] for k in (LOCALNET_INTERNAL,
                                               LOCALNET_EXTERNAL,
                                               VM_CONFIG, VM_ISOLATION)):
            self.note("Tracker inconsistency: components recorded but 'setup' is not.")
            self.note("Either the teardown partially ran or the tracker was hand-edited.")
        if f[VM_ISOLATION] and not f[VM_CONFIG]:
            self.note("Tracker inconsistency: vm-isolation recorded without vm-config.")

        # The tracker records INTENT and lives on disk, so it survives a
        # reboot untouched. Without this check a post-reboot run reads
        # "setup=True", gates away the sections that would have found the
        # problem, and reports a deployment that is no longer realised.
        earlier = self.tracker.any_from_earlier_boot()
        if earlier:
            self.boot_stale = True
            self.note("Every recorded component below was deployed during an "
                      "EARLIER boot:")
            self.detail(*[f"  {k}" for k in earlier])
            self.detail(
                "The OVN databases persist, but the runtime half does not:",
                "host-if's link/address/routes, ovn-controller's claim on each",
                "tap, and external-ids:system-id (which ovs-ctl rewrites at",
                "every boot) are all reapplied by nothing.",
                "-> ovnctl reconcile")

    # ------------------------------------------------------------------
    # 1
    # ------------------------------------------------------------------
    def _controller_memory(self) -> None:
        """Flag a controller whose memory use is not explicable.

        Reported in the very first section because it invalidates the
        reading of nearly every later one: an ovn-controller in this state
        produces unbound ports, unanswered appctl queries and slow claims,
        all of which then look like separate faults.
        """
        rss = ovn.controller_rss_mb(self.ctx)
        if not rss:
            return
        if rss <= ovn.CONTROLLER_RSS_WARN_MB:
            self.detail(f"resident memory: {rss} MB")
            return
        self.bad(f"ovn-controller is using {rss} MB of memory.")
        self.detail(
            "Tens of MB is normal for a single chassis of this size. At this",
            "level the daemon stops answering its control socket, claims",
            "ports slowly or not at all, and cannot be stopped cleanly.",
            "Later findings about unbound ports are most likely consequences",
            "of this rather than independent faults.")
        sizes = ovn.sb_table_sizes(self.ctx)
        self.detail("Southbound row counts: " + ", ".join(
            f"{k}={v}" for k, v in sizes.items()))
        if sizes.get("MAC_Binding", 0) > 1000:
            self.detail("MAC_Binding is large. It grows from observed traffic,",
                        "not from configuration -- the usual cause of memory",
                        "that does not match the topology.")
        else:
            self.detail("Nothing here explains it, which points at the daemon.")

        # The logical-flow cache is the usual answer when the row counts do
        # not account for the memory: it fills when a datapath's flows are
        # computed, and on OVN 22.x it has no limit unless one is set.
        limit = ovn.external_id(self.ctx, "ovn-memlimit-lflow-cache-kb").strip()
        self.detail(f"lflow cache limit (ovn-memlimit-lflow-cache-kb): "
                    f"{limit or 'UNSET -- unlimited'}")
        stats = ovn.lflow_cache_stats(self.ctx)
        if stats:
            for line in stats.splitlines()[:8]:
                self.detail(f"  {line}")
        elif not limit:
            self.detail(
                "Cache stats unavailable (the control socket is not"
                " answering).",
                "With no limit set, capping it is the cheapest thing to try:",
                "  ovs-vsctl set open . "
                "external-ids:ovn-memlimit-lflow-cache-kb=131072",
                "  systemctl restart ovn-controller")

    def check_controller_service(self) -> None:
        ctx = self.ctx
        self.section("1. ovn-controller service")
        if not ctx.have("systemctl"):
            self.note("systemctl not found, cannot check service status directly.")
            return
        if ctx.unit_active("ovn-controller"):
            self.ok("ovn-controller service is active.")
            self._controller_memory()
            return
        if self.not_deployed(SETUP):
            self.skip("ovn-controller not active -- expected, tracker shows "
                      "setup not run.")
            return
        self.bad("ovn-controller is NOT active.")
        self.detail("-> journalctl -u ovn-controller -e --no-pager | tail -30")
        logs = ctx.qout("journalctl", "-u", "ovn-controller", "-e", "--no-pager")
        if logs:
            self.block("\n".join(logs.splitlines()[-30:]))

    # ------------------------------------------------------------------
    # 2
    # ------------------------------------------------------------------
    def check_br_int(self) -> None:
        ctx = self.ctx
        self.section("2. br-int bridge")
        if ovn.br_exists(ctx, self.br_int):
            self.ok(f"{self.br_int} exists.")
            if "state UP" in ctx.qout("ip", "link", "show", self.br_int):
                self.ok(f"{self.br_int} link state is UP.")
            else:
                self.note(f"{self.br_int} link state is DOWN. Usually harmless for "
                          "OVS internal")
                self.detail("bridges with no physical uplink, but worth noting.")
            return
        if self.not_deployed(SETUP):
            self.skip(f"{self.br_int} does not exist -- expected, tracker shows "
                      "setup not run.")
            return
        self.bad(f"{self.br_int} does not exist. ovn-controller has never "
                 "successfully connected.")

    # ------------------------------------------------------------------
    # 3
    # ------------------------------------------------------------------
    def check_external_ids(self) -> None:
        ctx = self.ctx
        self.section("3. OVS external-ids")
        ids = ctx.qout("ovs-vsctl", "get", "open", ".", "external_ids") or "{}"
        self.detail(ids)
        if ovn.has_external_id(ctx, "ovn-remote"):
            self.ok("ovn-remote is set.")
            return
        if self.not_deployed(SETUP):
            self.skip("ovn-remote not set -- expected, tracker shows setup not run.")
            return
        self.bad("ovn-remote key is missing from external-ids (this is the root "
                 "cause")
        self.detail("if ovn-controller can't reach the SB db -- OVS always shows",
                    "hostname/rundir by default, so the map is never truly '{}').")

    # ------------------------------------------------------------------
    # 4
    # ------------------------------------------------------------------
    def check_chassis(self) -> None:
        ctx = self.ctx
        self.section("4. Chassis registration (Southbound db)")
        if self.not_deployed(SETUP):
            self.skip("Tracker shows setup not run -- no chassis expected yet.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        names = ovn.chassis_names(ctx)
        local_id = identity.local(ctx)
        conf_id = identity.conf_file_value()

        # Three names have to agree, and each drifts for its own reason:
        #   settings file   what the operator declared
        #   external-ids    what ovn-controller registers as, rewritten at
        #                   every boot by ovs-ctl from system-id.conf
        #   system-id.conf  what ovs-ctl will assert at the NEXT boot
        # Reporting only the first two hides the reason the drift keeps
        # coming back after being fixed by hand.
        self.detail(f"configured (settings) : {self.canonical_id or '<unset>'}",
                    f"external-ids:system-id: {local_id or '<unset>'}",
                    f"{identity.SYSTEM_ID_CONF}: {conf_id or '<absent>'}")

        if not self.canonical_id:
            self.bad("[setup].system_id is empty in the settings file.")
            self.identity_ok = False
            self.detail(
                "Nothing pins the chassis name, so it is whatever ovs-ctl or",
                "the hostname supplied at the last boot. Set a fixed value",
                "(e.g. ovn-host) and run: ovnctl reconcile --repair-identity")
        elif conf_id and conf_id != self.canonical_id:
            self.bad(f"{identity.SYSTEM_ID_CONF} says '{conf_id}', not "
                     f"'{self.canonical_id}'.")
            self.identity_ok = False
            self.detail(
                "ovs-ctl reads that file at every boot and writes it into",
                "external-ids:system-id, so any fix applied only to",
                "external-ids is undone by the next reboot.",
                "-> ovnctl reconcile")
        elif not conf_id:
            self.note(f"{identity.SYSTEM_ID_CONF} does not exist.")
            self.detail(
                "ovs-ctl will generate a random UUID there at the next boot",
                "and overwrite external-ids:system-id with it.",
                "-> ovnctl reconcile")

        if not names:
            self.bad("No Chassis registered in the Southbound db.")
            self.detail(
                "This means ovn-controller has not successfully connected to",
                "the SB db at the ovn-remote configured in external-ids.",
                "Check: ovs-vsctl get open . external_ids:ovn-remote",
                "Check: ls -l /var/run/ovn/ovnsb_db.sock")
            return

        if len(names) > 1:
            self.bad(f"MULTIPLE chassis registered ({len(names)}) on a "
                     "single-node deployment:")
            self.identity_ok = False
            self.block("\n".join(names))
            self.detail(
                "This is the classic system-id drift problem (e.g. hostname vs",
                "FQDN changing across reboots). Gateway ports pinned to the OLD",
                f"name will never bind. Local system-id right now: {local_id or '<unset>'}",
                "Fix: ovnctl reconcile --repair-identity",
                "(sets one canonical name in the settings file, external-ids AND",
                "system-id.conf, deletes the stale rows and re-points the pins).")
            return

        self.ok(f"Exactly one chassis is registered: {names[0]}")

        # Ghost chassis: a row left in the SB db by a controller that is no
        # longer running. Everything looks registered, nothing binds.
        if not ctx.q("pgrep", "-x", "ovn-controller").ok:
            self.bad("But NO ovn-controller process is running -- this is a GHOST "
                     "chassis")
            self.identity_ok = False
            self.detail(
                "row left behind by a previous controller. Port bindings will",
                "exist but never bind (cr-lrp-* unbound, VIFs DOWN).",
                "Fix: systemctl stop ovn-controller",
                "     ovn-sbctl --bare --columns=_uuid list Chassis "
                "| xargs -r -n1 ovn-sbctl destroy Chassis",
                "     ovn-sbctl --bare --columns=_uuid list Chassis_Private "
                "| xargs -r -n1 ovn-sbctl destroy Chassis_Private",
                "     systemctl start ovn-controller")
        elif ctx.have("ovn-appctl"):
            conn = ovn.appctl(ctx, "connection-status").stdout
            if conn and "connected" not in conn:
                self.bad(f"ovn-controller is running but its SB connection is "
                         f"'{conn}'.")
            elif conn:
                self.ok(f"ovn-controller SB connection: {conn}")

        if local_id and names[0] != local_id:
            self.bad(f"But local external-ids:system-id ({local_id}) does NOT "
                     "match it.")
            self.identity_ok = False
            self.detail(
                f"The registered chassis '{names[0]}' is a leftover identity.",
                "Nothing is running under it, so every Port_Binding.chassis and",
                "gateway pin that names it is stale -- and those columns are",
                "PERSISTENT, which is why ports elsewhere in this report can",
                "still look 'bound' while nothing actually forwards.",
                "",
                "Do NOT just restart ovn-controller. It would register a SECOND",
                "chassis under the current id, leaving the gateway pinned to the",
                "old one and taking the uplink down as well.",
                "-> ovnctl reconcile --repair-identity")
        elif self.canonical_id and names[0] != self.canonical_id:
            self.bad(f"Registered chassis '{names[0]}' is not the configured "
                     f"identity '{self.canonical_id}'.")
            self.identity_ok = False
            self.detail("external-ids agrees with the registered name, so the",
                        "controller is consistent -- but both disagree with the",
                        "settings file, and the next reconcile will rename it.",
                        "-> ovnctl reconcile --repair-identity")
        else:
            self.ok("Chassis name matches local external-ids:system-id.")

    # ------------------------------------------------------------------
    # 5
    # ------------------------------------------------------------------
    def check_port_bindings(self) -> None:
        ctx = self.ctx
        self.section(f"5. Port binding state (host-if, {self.lrp_int})")
        if self.not_deployed(SETUP):
            self.skip(f"Tracker shows setup not run -- {self.host_if} not "
                      "expected to exist.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        pb = ctx.qout("ovn-sbctl", "find", "Port_Binding",
                      f"logical_port={self.host_if}")
        if not pb:
            self.bad(f"No Port_Binding found for logical port '{self.host_if}'.")
            self.detail("The logical switch port may not have propagated from "
                        "NB to SB.")
            return

        # "Has a chassis" is not the question. Port_Binding.chassis is a
        # persistent column: a binding made before a reboot is still there
        # afterwards, pointing at whatever chassis claimed it then. Only
        # resolving the NAME and comparing it to the identity this host is
        # currently running under tells a live binding from a fossil.
        bound_to = ovn.port_binding_chassis_name(ctx, self.host_if)
        local_id = identity.local(ctx)
        if not bound_to:
            self.bad(f"{self.host_if} has no chassis bound -- it's not 'up'.")
        elif local_id and bound_to != local_id:
            self.bad(f"{self.host_if} is bound to chassis '{bound_to}', but this "
                     f"host runs as '{local_id}'.")
            self.detail(
                "This is a STALE binding, not a working one -- it was written by",
                "a controller running under the old identity and simply never",
                "cleaned up. Nothing is forwarding for this port.",
                "-> see section 4, then: ovnctl reconcile --repair-identity")
        else:
            self.ok(f"{self.host_if} is bound to the local chassis "
                    f"({bound_to}).")
        for line in pb.splitlines():
            if re.search(r"chassis|logical_port|mac", line):
                print(f"        {line}")

    # ------------------------------------------------------------------
    # 5b
    # ------------------------------------------------------------------
    def check_all_port_bindings(self) -> None:
        """Sweep ALL port bindings and flag any that should have a chassis.

        Not every unbound port is a fault: patch/router ports never bind,
        localnet/l2gateway bind differently, and a VIF for a powered-off VM
        is legitimately unbound. So:
          - patch/router/localnet/localport/l2gateway/chassisredirect: skipped
            (cr- ports get their own check in 5c)
          - VIF: FAIL only if the same iface-id is actually plugged into
            local OVS (the VM tap exists), WARN otherwise.
        """
        ctx = self.ctx
        self.section("5b. Full port_binding sweep (missing chassis detection)")
        if self.not_deployed(SETUP):
            self.skip("Tracker shows setup not run -- no port bindings expected.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        if self.has_tracker and not self.flags[VM_CONFIG]:
            self.detail(f"(tracker: vm-config not run -- only {self.host_if} and router",
                        " ports are expected; VM VIFs would be leftovers)")

        # One query for the whole table. The previous shape cost two
        # ovn-sbctl invocations per port (type, then chassis) plus an
        # ovs-vsctl per unbound VIF, which on a busy host is a hundred-odd
        # forks to answer a question the SB db can answer in one.
        rows = ovn.sb_json(ctx, "logical_port,type,chassis", "Port_Binding")
        if not rows:
            self.bad("No Port_Binding rows at all in the SB db -- NB config has not")
            self.detail("propagated (is ovn-northd running?).")
            return

        non_vif = {"patch", "router", "localnet", "localport", "l2gateway",
                   "chassisredirect"}
        total = bound = skipped = problems = 0
        off_vifs: list[str] = []
        stale_bound: list[tuple[str, str]] = []
        # Fetched on first use: a fully bound host never needs it.
        taps: dict[str, str] | None = None
        # Resolved once for the whole sweep -- a bound port is only really
        # bound if it is bound to THIS chassis.
        chassis_names = ovn.chassis_uuid_names(ctx)
        local_id = identity.local(ctx)

        for row in rows:
            if len(row) < 3:
                continue
            lp = str(row[0])
            ptype = str(row[1] or "")
            total += 1
            if ptype in non_vif:
                skipped += 1
                continue
            if ovn.ref_is_set(row[2]):
                refs = ovn.uuid_list(row[2])
                owner = chassis_names.get(refs[0], "") if refs else ""
                if local_id and owner and owner != local_id:
                    stale_bound.append((lp, owner))
                else:
                    bound += 1
                continue
            # Unbound VIF -- is a local OVS interface carrying this iface-id?
            if taps is None:
                taps = ovn.iface_id_map(ctx)
            tap = taps.get(lp, "")
            if tap:
                self.bad(f"VIF '{lp}' is plugged into local OVS (interface: {tap}) "
                         "but has NO chassis bound.")
                # Before blaming the race: does the interface even have a
                # datapath port? ovn-controller cannot claim a port with
                # ofport -1, and no number of restarts will change that.
                # Sending the operator to `reconcile` here is worse than
                # saying nothing -- it looks like a fix, does nothing, and
                # hides the real cause behind a plausible one.
                ofport, iface_error = ovn.iface_health(ctx, tap)
                if ofport <= 0:
                    self.detail(
                        f"Interface '{tap}' has no datapath port (ofport {ofport}),",
                        "so there is nothing for ovn-controller to claim. This is",
                        "NOT the reboot race and a controller restart will not fix",
                        "it -- the OVS port itself has to be rebuilt.")
                    if iface_error:
                        self.detail(f"ovs-vswitchd: {iface_error}")
                    kind = self._link_kind(tap)
                    if kind and kind != "openvswitch":
                        self.detail(
                            f"A {kind} device is holding the name '{tap}'.")
                    self.detail("-> ovnctl setup --only host-interface")
                    problems += 1
                    continue
                # The fix depends entirely on section 4. Restarting the
                # controller is the right move for a plain reboot race and
                # the wrong one when the identity has drifted, where it
                # registers a second chassis and unbinds the gateway too.
                if self.identity_ok:
                    self.detail(
                        "The tap exists but ovn-controller never claimed the port.",
                        "This is the reboot-race signature.",
                        "-> ovnctl reconcile   (or: systemctl restart ovn-controller)")
                else:
                    self.detail(
                        "The tap exists but ovn-controller never claimed the port.",
                        "Section 4 failed, so this is a symptom of the identity",
                        "problem, not a separate race -- the controller is not",
                        "claiming anything under the name the bindings expect.",
                        "Do NOT restart ovn-controller before fixing that; a",
                        "restart would register a second chassis and unbind the",
                        "gateway as well.",
                        "-> ovnctl reconcile --repair-identity")
                problems += 1
            else:
                off_vifs.append(lp)

        if off_vifs:
            self.note(f"{len(off_vifs)} VIF(s) unbound with no local tap -- "
                      "consistent with powered-off VMs; only a problem if one of "
                      "these should be running:")
            for v in off_vifs:
                self.detail(v)

        if stale_bound:
            self.bad(f"{len(stale_bound)} port(s) bound to a chassis this host "
                     f"is not running as ('{local_id}'):")
            for lp, owner in stale_bound:
                self.detail(f"{lp} -> {owner}")
            self.detail(
                "Port_Binding.chassis persists across reboots, so these rows",
                "outlived the controller that wrote them. They read as 'up' in",
                "any check that only asks whether a chassis is set, and they",
                "forward nothing.",
                "-> ovnctl reconcile --repair-identity")

        self.ok(f"Swept {total} port bindings: {bound} bound, {skipped} non-VIF "
                f"skipped, {len(off_vifs)} powered-off VIF(s), "
                f"{len(stale_bound)} stale-bound, {problems} problem(s).")
        if problems == 0 and not stale_bound:
            self.ok("No running-but-unbound VIFs detected.")

    # ------------------------------------------------------------------
    # 5c
    # ------------------------------------------------------------------
    def check_chassisredirect(self) -> None:
        """cr-lrp-* ports MUST have a chassis when a gateway is deployed.

        An unbound cr- port means the uplink path is dead even though VMs
        can still talk to each other -- the FreeIPA outage pattern.
        """
        ctx = self.ctx
        self.section("5c. Chassisredirect (gateway) port bindings")
        if self.has_tracker and not self.flags[LOCALNET_INTERNAL] \
                and not self.flags[LOCALNET_EXTERNAL]:
            self.skip("Tracker shows no localnet gateway deployed -- no cr- ports "
                      "expected.")
            return
        if not ctx.have("ovn-sbctl"):
            self.note("ovn-sbctl not found, skipping.")
            return

        rows = ovn.sb_records(ctx, "logical_port,chassis", "Port_Binding",
                              "type=chassisredirect")
        if not rows:
            if self.has_tracker:
                self.bad(f"Tracker records a localnet gateway "
                         f"(internal={self.flags[LOCALNET_INTERNAL]}, "
                         f"external={self.flags[LOCALNET_EXTERNAL]})")
                self.detail(
                    "but NO chassisredirect port exists in the SB db. The gateway",
                    "config was lost or never propagated. Check:",
                    f"  ovn-nbctl lrp-list {self.lr_core}     "
                    "(do the uplink lrps exist?)",
                    "  ovn-nbctl --bare --columns=name list Gateway_Chassis",
                    "If the lrp is missing, re-run the localnet command.")
            else:
                self.note("No chassisredirect ports exist. Fine if no localnet "
                          "gateway has")
                self.note("been set up yet; a problem if you expected an uplink "
                          "to exist.")
            return

        local_id = identity.local(ctx)
        chassis_names = ovn.chassis_uuid_names(ctx)
        for lp, chassis in rows:
            if chassis and chassis != "[]":
                owner = chassis_names.get(chassis, "")
                if local_id and owner and owner != local_id:
                    self.bad(f"{lp} is bound to '{owner}', but this host runs as "
                             f"'{local_id}' -- a stale binding, not a live one.")
                    self.detail(
                        "The gateway path is DOWN despite the binding row: no",
                        "running controller owns that chassis name.",
                        "-> ovnctl reconcile --repair-identity")
                    continue
                self.ok(f"{lp} is bound to a chassis.")
            else:
                self.bad(f"{lp} has NO chassis bound -- the gateway path through "
                         "this")
                self.detail(
                    "port is DOWN. VM-to-VM traffic will still work, but nothing",
                    "reaches the physical network (this is the FreeIPA outage).",
                    "Likely causes, in order:",
                    "  1) Gateway pinned to a chassis name that no longer exists",
                    "     (see sections 4 and 5d)",
                    "  2) ovn-controller started before the SB db at boot --",
                    "     try: systemctl restart ovn-controller",
                    "  3) ovn-bridge-mappings missing for the physnet",
                    "     (ovs-vsctl get open . external-ids:ovn-bridge-mappings)")

    # ------------------------------------------------------------------
    # 5d
    # ------------------------------------------------------------------
    def check_gateway_pins(self) -> None:
        """Cross-check every gateway-chassis pin against the registered chassis.

        A pin referencing a dead/renamed chassis silently never binds.
        """
        ctx = self.ctx
        self.section("5d. Gateway-chassis pins vs. registered chassis")
        if self.has_tracker and not self.flags[LOCALNET_INTERNAL] \
                and not self.flags[LOCALNET_EXTERNAL]:
            self.skip("Tracker shows no localnet gateway deployed -- no pins "
                      "expected.")
            return
        if not (ctx.have("ovn-nbctl") and ctx.have("ovn-sbctl")):
            self.note("ovn-nbctl/ovn-sbctl not found, skipping.")
            return

        rows = ovn.nb_json(ctx, "name,chassis_name", "Gateway_Chassis")
        pins = [(str(r[0] or ""), str(r[1] or "")) for r in rows]

        if not pins:
            if self.has_tracker:
                self.bad("Tracker records a localnet gateway but NO Gateway_Chassis "
                         "rows")
                self.detail("exist -- the lrp was never pinned or the pin was removed.",
                            "Fix: ovn-nbctl lrp-set-gateway-chassis <lrp> <chassis> 10")
            else:
                self.note("No Gateway_Chassis rows in the NB db. Fine if no uplink "
                          "gateway")
                self.note("is configured; otherwise the lrp was never pinned.")
            return

        registered = set(ovn.chassis_names(ctx))
        for pin_name, pin_chassis in pins:
            if pin_chassis in registered:
                # Registered is necessary, not sufficient. A pin naming a
                # stale-but-still-present chassis passes every check right
                # up until that row is cleaned up, at which point the
                # uplink drops for no apparent reason.
                if self.canonical_id and pin_chassis != self.canonical_id:
                    self.note(f"Pin '{pin_name}' -> '{pin_chassis}' is registered, "
                              f"but the configured identity is "
                              f"'{self.canonical_id}'.")
                    self.detail(
                        "The pin works only for as long as that stale chassis row",
                        "survives. Re-point it: ovnctl reconcile")
                    continue
                self.ok(f"Pin '{pin_name}' -> chassis '{pin_chassis}' (registered).")
            else:
                self.bad(f"Pin '{pin_name}' references chassis '{pin_chassis}', "
                         "which is")
                self.detail("NOT registered in the SB db. The cr- port for this lrp can",
                            "never bind. Registered chassis right now:")
                for name in sorted(registered):
                    print(f"          {name}")
                self.detail("Fix: ovn-nbctl lrp-set-gateway-chassis <lrp> "
                            "<current-chassis> 10",
                            "(and remove the stale pin / chassis if identity drifted).")

    # ------------------------------------------------------------------
    # 5e
    # ------------------------------------------------------------------
    def check_isolation(self) -> None:
        ctx = self.ctx
        self.section(f"5e. VM isolation ({self.pg_name})")
        if not self.has_tracker:
            self.skip("No tracker -- cannot tell whether isolation is expected; "
                      "not checked.")
            return
        if not self.flags[VM_ISOLATION]:
            self.skip(f"Tracker shows vm-isolation not run -- {self.pg_name} not "
                      "expected.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, skipping.")
            return

        if not ovn.pg_exists(ctx, self.pg_name):
            self.bad(f"Tracker records vm-isolation but port group "
                     f"{self.pg_name} does NOT exist.")
            self.detail(f"The {self.pg_expected} 'isolated' VMs are NOT isolated. "
                        "Re-run `ovnctl vm-isolation`.")
            return
        self.ok(f"Port group {self.pg_name} exists.")

        members = len(ovn.pg_members(ctx, self.pg_name))
        if members == self.pg_expected:
            self.ok(f"{self.pg_name} has the expected {self.pg_expected} "
                    f"member(s) (from [vm_isolation].isolated_vms).")
        else:
            self.bad(f"{self.pg_name} has {members} members, expected "
                     f"{self.pg_expected}.")
            self.detail("Membership drifted -- re-run `ovnctl vm-isolation` "
                        "(it recreates",
                        "the group with correct membership).")

        acls = ovn.acl_list(ctx, self.pg_name)
        drops = [a for a in acls if "drop" in a]
        if len(drops) >= 2:
            self.ok(f"{self.pg_name} has {len(drops)} drop ACLs "
                    "(expected 2: from-lport + to-lport).")
        else:
            self.bad(f"{self.pg_name} has only {len(drops)} drop ACL(s), expected 2.")
            self.detail("Isolation is partial or absent -- re-run `ovnctl vm-isolation`.")

        # SCOPE CHECK. Port-group ACLs are installed on every logical switch
        # the group's ports touch; if the match lacks "inport/outport ==
        # @group" it silently drops traffic for NON-members too. acl-list
        # looks perfectly fine in that state.
        scoped = [a for a in acls if f"@{self.pg_name}" in a]
        if len(scoped) < len(acls):
            self.bad(f"One or more ACLs on {self.pg_name} are NOT scoped to the "
                     "port group.")
            self.detail(
                f"Matches must contain 'inport == @{self.pg_name}' (from-lport) or",
                f"'outport == @{self.pg_name}' (to-lport). Without it the rule applies",
                "to EVERY port on the switch -- non-member VMs lose connectivity.",
                "Re-run `ovnctl vm-isolation` (it writes scoped matches).")
        else:
            self.ok(f"All {self.pg_name} ACLs are scoped to group members.")

        # Legacy hyphenated groups keep their unscoped ACLs alive.
        legacy_names = ctx.cfg_list("vm_isolation", "legacy_pg_names") \
            or ["pg-isolated"]
        for legacy in legacy_names:
            if not legacy or legacy == self.pg_name:
                continue
            if ovn.pg_exists(ctx, legacy):
                self.bad(f"Legacy port group '{legacy}' still exists alongside "
                         f"{self.pg_name}.")
                self.detail("Its ACLs are unscoped and will still drop non-member "
                            "traffic.",
                            f"Remove with: ovn-nbctl pg-del {legacy}")

        self._isolation_live_proof()

    def _isolation_live_proof(self) -> None:
        """Live proof: a non-member must not be dropped.

        The shell version tested membership against $_iso_vms, a variable it
        never defined -- so this check either picked the wrong victim or
        never ran. Membership comes from the inventory here.
        """
        ctx = self.ctx
        if not ctx.have("ovn-trace"):
            return
        from ..context import trace_verdict

        iso_uuids = set(self.inv.isolated_uuids)
        victim = next((vm for vm in self.inv.external
                       if vm.uuid not in iso_uuids), None)
        if victim is None:
            return

        lrp_mac = ctx.cfg_opt("setup", "lrp_ext_mac", "")
        if not lrp_mac:
            return
        expr = (f'inport=="{self.ls_ext}-to-lr" && eth.src=={lrp_mac} && '
                f'eth.dst=={victim.mac} && ip4.src=={self.gateway} && '
                f'ip4.dst=={victim.ip} && ip.ttl==63 && icmp4')
        out = ovn.trace(ctx, self.ls_ext, expr)
        verdict = trace_verdict(out)
        if verdict == "UNKNOWN":
            self.note("ovn-trace gave no usable verdict -- scope not proven "
                      "either way.")
            self.detail("Usually ovn-trace timing out on a large Southbound db.",
                        f"  ovn-trace {self.ls_ext} '{expr}'")
            return
        if verdict == "DROP":
            self.bad(f"LIVE PROOF: non-member {victim.name} ({victim.ip}) is "
                     "being DROPPED.")
            self.detail("This is a switch-wide outage for every non-isolated VM on",
                        "that switch. Re-run `ovnctl vm-isolation` to fix scoping.")
        else:
            self.ok(f"Live trace: non-member {victim.name} ({victim.ip}) is not "
                    "affected.")

    # ------------------------------------------------------------------
    # 5h
    # ------------------------------------------------------------------
    def check_acls(self) -> None:
        ctx = self.ctx
        from ..context import trace_verdict

        self.section("5h. Micro-segmentation ACLs")
        group_defs = ctx.cfg_list("acls", "port_groups")
        if not group_defs:
            self.skip("No [acls].port_groups defined.")
            return
        if self.not_deployed(ACLS):
            self.skip("Tracker shows the ACL command has not been run.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, skipping.")
            return

        for entry in group_defs:
            parts = entry.split(None, 1)
            pg = parts[0]
            sel = parts[1] if len(parts) > 1 else ""
            if not pg:
                continue
            if not ovn.pg_exists(ctx, pg):
                self.bad(f"Port group {pg} does not exist -- re-run `ovnctl acl`.")
                continue
            members = len(ovn.pg_members(ctx, pg))
            acls = ovn.acl_list(ctx, pg)
            scoped = [a for a in acls if f"@{pg}" in a]
            self.ok(f"{pg} ({sel}): {members} member(s), {len(acls)} ACL(s).")
            if acls and len(scoped) < len(acls):
                self.bad(f"  {len(acls) - len(scoped)} ACL(s) on {pg} are NOT "
                         f"scoped with @{pg}")
                self.detail("-- they apply to every port on the switch.")

        # Prove the lateral rule denies and management still works.
        if not ctx.have("ovn-trace") or len(self.inv.internal) < 2:
            return
        v1, v2 = self.inv.internal[0], self.inv.internal[1]
        hip = ctx.cfg_opt("setup", "host_if_ip", "")
        lmac = ctx.cfg_opt("setup", "lrp_int_mac", "")
        if not (hip and lmac):
            return

        out = ovn.trace(ctx, self.ls_int,
                        f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                        f'eth.dst=={v2.mac} && ip4.src=={v1.ip} && '
                        f'ip4.dst=={v2.ip} && ip.ttl==64 && tcp && tcp.dst==22')
        verdict = trace_verdict(out)
        if verdict == "DROP":
            self.ok(f"Lateral SSH {v1.name} -> {v2.name} is DENIED (correct).")
        elif verdict == "UNKNOWN":
            self.note(f"Lateral SSH {v1.name} -> {v2.name}: no verdict "
                      "(trace failed or timed out).")
        else:
            self.bad(f"Lateral SSH {v1.name} -> {v2.name} is ALLOWED -- "
                     "segmentation is not effective.")

        out = ovn.trace(ctx, self.ls_int,
                        f'inport=="{self.ls_int}-to-lr" && eth.src=={lmac} && '
                        f'eth.dst=={v1.mac} && ip4.src=={hip} && '
                        f'ip4.dst=={v1.ip} && ip.ttl==63 && tcp && tcp.dst==22')
        verdict = trace_verdict(out)
        if verdict == "DROP":
            self.bad(f"Management SSH {hip} -> {v1.name} is DENIED -- you have "
                     "locked yourself out.")
        elif verdict == "UNKNOWN":
            self.note(f"Management SSH {hip} -> {v1.name}: no verdict "
                      "(trace failed or timed out).")
        else:
            self.ok(f"Management SSH {hip} -> {v1.name} is allowed (correct).")

    # ------------------------------------------------------------------
    # 5i
    # ------------------------------------------------------------------
    def check_user_vms(self) -> None:
        """Do the allocated slots actually sit in their port group?

        This exists because of a specific silent failure: the port group
        had every ACL and ZERO members, so all of them compiled against
        nothing. The slots were neither isolated from each other nor
        reachable from the management source, and every other view --
        `show`, the ACL listing, the allocation file -- looked correct.
        Membership is the one thing that ties the two together, so it is
        the one thing worth checking.
        """
        import json
        from .. import paths

        ctx = self.ctx
        self.section("5j. User-VM segment")

        path = paths.state_dir() / "user-vms.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.skip("No user-VM allocations recorded.")
            return
        slots = data.get("slots") or {}
        pg_name = ctx.config.cfg_opt("user_vms", "pg_name", "pg_user_vms")

        if not slots:
            if ovn.pg_exists(ctx, pg_name):
                self.ok(f"No slots allocated; {pg_name} exists and is empty "
                        "(expected).")
            else:
                self.skip("No slots allocated and no port group -- the "
                          "segment has never been built.")
            return

        if not ovn.pg_exists(ctx, pg_name):
            self.bad(f"{len(slots)} slot(s) allocated but {pg_name} does not "
                     "exist.")
            self.detail("Nothing is isolating them. -> ovnctl user-vm --reapply")
            return

        # NAMES, not row uuids. Port_Group.ports holds Logical_Switch_Port
        # row uuids; the allocation file holds logical port names. Both
        # look like uuids, so comparing them directly produced two
        # disjoint sets and a confident, entirely wrong failure.
        members = set(ovn.pg_member_names(ctx, pg_name))
        wanted = {r["uuid"] for r in slots.values() if r.get("uuid")}
        missing = wanted - members
        extra = members - wanted

        if missing:
            self.bad(f"{len(missing)} allocated slot(s) are NOT in {pg_name}:")
            for uuid in sorted(missing):
                name = next((n for n, r in slots.items()
                             if r.get("uuid") == uuid), "?")
                self.detail(f"{name} ({uuid})")
            self.detail(
                "Their ACLs match a group they are not in, so they are",
                "neither isolated from each other nor reachable from the",
                "management source.",
                "-> ovnctl user-vm --reapply")
        else:
            self.ok(f"All {len(wanted)} allocated slot(s) are members of "
                    f"{pg_name}.")

        if extra:
            self.note(f"{len(extra)} port(s) in {pg_name} are not allocated "
                      "slots:")
            for uuid in sorted(extra):
                self.detail(uuid)
            self.detail("Left over from a slot released outside `user-vm "
                        "--delete`. -> ovnctl user-vm --reapply")

    def check_port_security(self) -> None:
        """lsp-set-port-security binds a port to its MAC+IP.

        Several controls match on ip4.src -- the priority-300 ASA override,
        the management-SSH allow -- so a VM able to spoof a source address
        can route around them. This check exists because the command was
        once misspelled AND error-suppressed, so it failed silently on every
        deployment and nobody noticed.
        """
        ctx = self.ctx
        self.section("5i. VM port security")
        if self.not_deployed(VM_CONFIG):
            self.skip("Tracker shows vm-config not run -- no VM ports expected.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, skipping.")
            return
        if not self.inv.all:
            self.skip("No VMs in [vm_config].")
            return

        missing = 0
        ok_count = 0
        for vm in self.inv.all:
            ps = ovn.port_security(ctx, vm.uuid)
            if not ps:
                missing += 1
            elif vm.ip in ps and vm.mac in ps:
                ok_count += 1
            else:
                self.bad(f"{vm.name}: port security is set but does not match "
                         "the inventory.")
                self.detail(f"expected: {vm.mac} {vm.ip}", f"actual:   {ps}")

        if missing > 0:
            self.bad(f"{missing} of {len(self.inv.all)} VM port(s) have NO port "
                     "security.")
            self.detail(
                "Those guests can forge their MAC and source IP. Because the",
                "ASA reroute policy and the management-SSH allow both match on",
                "ip4.src, a spoofing VM can bypass them.",
                "Fix: re-run `ovnctl vm-config`.")
        else:
            self.ok(f"All {ok_count} VM port(s) have port security matching the "
                    "inventory.")

    # ------------------------------------------------------------------
    # 5f
    # ------------------------------------------------------------------
    def check_range_overlap(self) -> None:
        ctx = self.ctx
        self.section("5f. Range overlap & policy tiers")

        if not self.internal_ranges:
            self.skip("No [internal_ranges] configured -- nothing to compare.")
            return

        self.detail(f"internal: {' '.join(self.internal_ranges)}")
        if not self.external_ranges:
            self.skip("No [external_ranges] declared -- exclusion-only policy, "
                      "no ambiguity possible.")
        else:
            self.detail(f"external: {' '.join(self.external_ranges)}")
            if self.shadow_ranges:
                self.detail(f"shadow:   {' '.join(self.shadow_ranges)}")

            overlaps = netcalc.find_overlaps(self.internal_ranges,
                                             self.external_ranges)
            if overlaps:
                for i, e, d in overlaps:
                    self.detail(f"collision: internal {i} vs external {e} on {d}")
                if self.shadow_ranges:
                    self.ok("Overlap present but RESOLVED via shadow space "
                            f"({' '.join(self.shadow_ranges)}).")
                    self.detail(
                        "Real addresses stay internal; shadow addresses reach the",
                        "ASA-side twin. Confirm the matching NAT entries exist on",
                        "the ASA -- OVN cannot verify the far side.")
                else:
                    self.bad("Overlap present and UNRESOLVED (no [shadow_ranges] "
                             "configured).")
                    self.detail(
                        "Colliding addresses are reachable via ONE path only.",
                        "Fix: add a shadow range + ASA NAT, narrow the prefixes,",
                        "or list affected VMs in [policy].external_only_ips.")
            else:
                self.ok("Internal and external ranges are disjoint.")

        if self.target_subnets:
            self.detail(f"engagement targets: {' '.join(self.target_subnets)}")
            colliding = False
            for t in self.target_subnets:
                if netcalc.find_overlaps([t], self.internal_ranges):
                    colliding = True
                    self.detail(f"{t} overrides an internal range "
                                "(expected for this engagement)")
            if not colliding:
                self.note(f"No listed target collides with our ranges -- the "
                          f"priority-{self.prio_split} rule would have covered "
                          "them anyway; listing them is harmless.")
        else:
            self.skip("No engagement targets listed (normal -- unknown "
                      "destinations are")
            self.detail(f"covered by the priority-{self.prio_split} "
                        "not-internal rule).")

        self._check_policy_tiers()

    def _check_policy_tiers(self) -> None:
        ctx = self.ctx
        if self.not_deployed(LOCALNET_EXTERNAL):
            self.skip("Tracker shows the ASA split path is not deployed -- "
                      "tiers not checked.")
            return
        if not ctx.have("ovn-nbctl"):
            self.note("ovn-nbctl not found, cannot verify policy tiers.")
            return

        tiers = (
            (self.prio_src_override, "source-override", len(self.external_only_ips)),
            (self.prio_target, "engagement-targets", len(self.target_subnets)),
            (self.prio_shadow, "shadow", len(self.shadow_ranges)),
            (self.prio_external, "external", len(self.external_ranges)),
            (self.prio_split, "split", 1),
        )
        for prio, label, expected in tiers:
            present = len(ovn.policy_uuids(ctx, prio))
            if expected > 0:
                if present > 0:
                    self.ok(f"Tier {prio} ({label}): present.")
                    if prio == self.prio_split:
                        self._check_split_negations()
                else:
                    self.bad(f"Tier {prio} ({label}): configured in yaml but NO "
                             "policy exists.")
                    self.detail("Re-run `ovnctl localnet-external` to apply it.")
            else:
                if present > 0:
                    self.note(f"Tier {prio} ({label}): a policy exists but nothing "
                              "is configured")
                    self.note("for it in the yaml -- possible leftover from an "
                              "earlier run.")
                else:
                    self.skip(f"Tier {prio} ({label}): not configured, none present.")

    def _check_split_negations(self) -> None:
        """Count the negated destination terms in the split policy.

        Each negated CIDR makes OVN compute the complement of that prefix,
        and ANDing several together computes their CROSS PRODUCT. It is the
        classic OVN flow-explosion shape, and it is invisible in the policy
        list -- the rule reads perfectly sensibly. The only outward signs
        are a br-int flow count in the hundreds of thousands and an
        ovn-controller whose memory has nothing to do with the topology.
        """
        ctx = self.ctx
        rows = ovn.nb_json(ctx, "priority,match", "Logical_Router_Policy")
        negations = 0
        for row in rows:
            if len(row) < 2 or str(row[0]) != str(self.prio_split):
                continue
            negations = max(negations, str(row[1] or "").count("ip4.dst !="))
        if negations <= 1:
            return
        self.bad(f"Tier {self.prio_split} uses {negations} separate "
                 "'ip4.dst !=' terms.")
        self.detail(
            "Each negated CIDR expands to the complement of that prefix, and",
            "ANDing them computes their cross product. Expect a very large",
            "br-int flow count (section 6) and an ovn-controller using far",
            "more memory than this topology can account for.",
            "Fix: re-run `ovnctl localnet-external` -- it now builds this as",
            "a single negation against an address set.")

    # ------------------------------------------------------------------
    # 6
    # ------------------------------------------------------------------
    def check_flows(self) -> None:
        ctx = self.ctx
        self.section(f"6. OpenFlow rules on {self.br_int}")
        if self.not_deployed(SETUP):
            self.skip("Tracker shows setup not run -- no flows expected.")
            return
        if not ctx.have("ovs-ofctl"):
            self.note("ovs-ofctl not found, skipping.")
            return
        out = ctx.qout("ovs-ofctl", "dump-flows", self.br_int)
        count = sum(1 for ln in out.splitlines() if "cookie=" in ln)
        if count == 0:
            self.bad(f"Zero flows programmed on {self.br_int}.")
            self.detail("This confirms ovn-controller isn't programming the pipeline --",
                        "almost always caused by #1 (service not running) or "
                        "#4 (no chassis).")
        else:
            self.ok(f"{count} flow entries present on {self.br_int}.")

    # ------------------------------------------------------------------
    # 7
    # ------------------------------------------------------------------
    def _link_kind(self, name: str) -> str:
        """The kernel's device kind for `name` ('' if it does not exist).

        `ip -d link show` names it on the third line: 'openvswitch' for a
        real OVS internal port, 'dummy' for a placeholder left behind by
        something else. Device names are a single global namespace, so a
        non-OVS device wearing this name is the reason ovs-vswitchd could
        not create its own.
        """
        res = self.ctx.q("ip", "-d", "link", "show", "dev", name)
        if not res.ok:
            return ""
        known = ("openvswitch", "dummy", "veth", "bridge", "bond", "vlan",
                 "tun", "vxlan", "macvlan", "team", "geneve")
        for line in res.stdout.splitlines()[1:]:
            for token in line.split():
                if token in known:
                    return token
        return "unknown"

    def check_host_if(self) -> None:
        ctx = self.ctx
        self.section(f"7. {self.host_if} OVS interface")
        if self.not_deployed(SETUP):
            self.skip(f"Tracker shows setup not run -- {self.host_if} not "
                      "expected to exist.")
            return
        iface_id = ctx.qout("ovs-vsctl", "get", "interface", self.host_if,
                            "external_ids:iface-id").strip('"')
        admin = ctx.qout("ovs-vsctl", "get", "interface", self.host_if,
                         "admin_state").strip('"')
        link = ctx.qout("ovs-vsctl", "get", "interface", self.host_if,
                        "link_state").strip('"')
        if iface_id == self.host_if:
            self.ok(f"iface-id is set correctly ({iface_id}).")
        else:
            self.bad(f"iface-id is '{iface_id}', expected '{self.host_if}'.")
        self.detail(f"admin_state={admin} link_state={link}")

        # ofport before anything else. Every other field in this row can be
        # exactly right while ovs-vswitchd has failed to open the netdev
        # behind it -- the classic cause being another device that already
        # owns the name, which makes add-port fail with "File exists" and
        # leaves the row with ofport -1. In that state admin_state and
        # link_state read as the empty set rather than "down", which is
        # easy to skim past, so the line above says [] and everything looks
        # fine. It is not fine: no ofport means ovn-controller has nothing
        # to bind, which is what section 5 is reporting.
        ofport, iface_error = ovn.iface_health(ctx, self.host_if)
        if ofport <= 0:
            self.bad(f"{self.host_if} has no datapath port (ofport {ofport}).")
            self.host_if_down = True
            if iface_error:
                self.detail(f"ovs-vswitchd: {iface_error}")
            kind = self._link_kind(self.host_if)
            if kind and kind != "openvswitch":
                self.detail(
                    f"A {kind} device is holding the name '{self.host_if}',",
                    "so ovs-vswitchd cannot create its internal port. Whatever",
                    "creates that device -- usually a NetworkManager profile of",
                    "that type -- will recreate it at every boot.",
                    f"-> nmcli -f NAME,TYPE,DEVICE connection show | grep {self.host_if}",
                    "-> ovnctl setup --only host-interface   (removes it and rebuilds)")
            else:
                self.detail(
                    "The port row is present but nothing is behind it. Restarting",
                    "ovn-controller will not help; the port has to be rebuilt.",
                    "-> ovnctl setup --only host-interface")
            return

        self.ok(f"{self.host_if} has a datapath port (ofport {ofport}).")

        # An internal port on br-int comes back after a reboot with the
        # port and its iface-id intact and the kernel side blank: down, no
        # address, no routes. Nothing in the OVN databases records that,
        # and the tracker says setup already ran, so this is where a
        # rebooted host quietly stops answering.
        if admin == "down":
            self.bad(f"{self.host_if} is administratively DOWN.")
            self.host_if_down = True
            self.detail(
                "The OVS port and its iface-id survive a reboot; `ip link set",
                "up`, the address and the routes do not, and nothing reapplies",
                "them. Everything routed through this interface is unreachable",
                "from the host until they are.",
                "-> ovnctl reconcile     (or: ovnctl setup --only host-interface)")
            return

        addrs = ctx.qout("ip", "-4", "-o", "addr", "show", "dev", self.host_if)
        if self.host_ip and self.host_ip not in addrs:
            self.bad(f"{self.host_if} is up but has no {self.host_ip} address.")
            self.host_if_down = True
            self.detail("Addresses and routes on an OVS internal port are kernel",
                        "state and are lost at every reboot.",
                        "-> ovnctl reconcile")

    # ------------------------------------------------------------------
    # 8
    # ------------------------------------------------------------------
    def check_live_arp(self) -> None:
        ctx = self.ctx
        self.section(f"8. Live ARP test for gateway {self.gateway}")
        if self.not_deployed(SETUP):
            self.skip(f"Tracker shows setup not run -- gateway {self.gateway} "
                      "not expected to answer.")
            return

        if ctx.have("arping"):
            cmd = ["arping", "-I", self.host_if, "-c", "2", "-w", "2",
                   self.gateway]
        else:
            self.note("arping not installed, falling back to ping "
                      "(less conclusive).")
            cmd = ["ping", "-c", "2", "-W", "1", self.gateway]

        res = ctx.q(*cmd, timeout=15)
        output = "\n".join(p for p in (res.stdout, res.stderr) if p)

        if re.search(r"1 received|1 packets received|reply from", output,
                     re.IGNORECASE):
            self.ok(f"Got a response from {self.gateway}.")
        else:
            self.bad(f"No response from {self.gateway}.")
            self.block(output)
            # Almost never a routing problem in its own right -- name the
            # section that actually explains it rather than leaving the
            # operator to correlate two failures by eye.
            if self.host_if_down:
                self.detail(
                    f"Section 7 found {self.host_if} down or unaddressed, which",
                    "is sufficient on its own to explain this. Fix that first.",
                    "-> ovnctl reconcile")
            elif not self.identity_ok:
                self.detail(
                    "Section 4 found the chassis identity inconsistent. With no",
                    "live claim on the port there is nothing to answer an ARP.",
                    "-> ovnctl reconcile --repair-identity")

    # ------------------------------------------------------------------
    def summary(self) -> None:
        c = self.c
        self.section("Summary / likely next step")
        fails = (f"{c.red}{c.bold}{self.fail_count}{c.rst}" if self.fail_count
                 else f"{c.grn}0{c.rst}")
        warns = (f"{c.ylw}{self.warn_count}{c.rst}" if self.warn_count
                 else f"{c.grn}0{c.rst}")
        print(f"Result: {fails} failure(s), {warns} warning(s).")
        if self.failed_sections:
            print(f"{c.red}{c.bold}Failing sections:{c.rst}")
            for name in self.failed_sections:
                print(f"  {name}")
        if self.has_tracker:
            print("Tracker gating was ACTIVE -- [SKIP] sections were not counted.")
        else:
            print("No tracker file -- all sections ran unconditionally.")

        # One line naming the command that addresses the whole class of
        # failure, rather than leaving three sections each pointing at a
        # different fragment of the same fix.
        if not self.identity_ok:
            print("Chassis identity is inconsistent -- start with: "
                  "ovnctl reconcile --repair-identity")
        elif self.host_if_down or self.boot_stale:
            print("Runtime state from before the last reboot was not "
                  "reapplied -- start with: ovnctl reconcile")
        print("")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-diagnose")
    # Deliberately NOT requiring the localnet_external keys: a single-NIC
    # deployment does not have them, and refusing to run any check because
    # of that is exactly the failure this port is fixing.
    ctx.require_cfg("localnet_internal:br_internal", "localnet_internal:phys_nic",
                    "setup:host_if_ip", "setup:lrp_ext_mac", "setup:lrp_int_mac",
                    "topology:ls_ext", "topology:ls_int")
    ctx.require_root()

    d = Diagnose(ctx)
    runner = StepRunner(ctx, "diagnose")
    runner.add("tracker", "deployment tracker state", d.check_tracker)
    runner.add("controller", "ovn-controller service", d.check_controller_service)
    runner.add("br-int", "the integration bridge", d.check_br_int)
    runner.add("external-ids", "OVS external-ids", d.check_external_ids)
    runner.add("chassis", "chassis registration in the SB db", d.check_chassis)
    runner.add("port-bindings", "host-if port binding", d.check_port_bindings)
    runner.add("port-binding-sweep", "every port binding, missing chassis",
               d.check_all_port_bindings)
    runner.add("chassisredirect", "gateway port bindings", d.check_chassisredirect)
    runner.add("gateway-pins", "gateway-chassis pins vs registered chassis",
               d.check_gateway_pins)
    runner.add("isolation", "isolation port group and its scope",
               d.check_isolation)
    runner.add("acls", "micro-segmentation ACLs", d.check_acls)
    runner.add("port-security", "VM port security", d.check_port_security)
    runner.add("user-vms", "user-VM segment membership", d.check_user_vms)
    runner.add("range-overlap", "range overlap and policy tiers",
               d.check_range_overlap)
    runner.add("flows", "OpenFlow rules on br-int", d.check_flows)
    runner.add("host-if", "the host-facing OVS interface", d.check_host_if)
    runner.add("live-arp", "live ARP/ping test of the gateway", d.check_live_arp)
    runner.add("summary", "the failure/warning tally", d.summary)

    if not runner.run(args):
        return 0
    return 1 if d.fail_count else 0