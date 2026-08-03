"""
ovnctl vm-isolation -- port of ovn-vm-isolation.sh

Fully isolates the listed VMs from ALL internal infrastructure -- no other
internal host, VM, or the gateway itself can reach them, and they can't
reach anything internal either. Their only path anywhere is out through
lr-core's reroute policy to the ASA, and console access stays available via
VNC/KVM regardless of network state.

Mechanism: an OVN port group with two drop ACLs (from-lport and to-lport)
matching the ranges in [internal_ranges] -- NOT all of RFC1918, because the
external-to-us network these VMs are allowed to reach also uses RFC1918
addressing and blocking all of it would cut off their one legitimate path.

Same-subnet (L2) traffic is caught too, since from-lport/to-lport ACLs
apply before routing decisions -- lateral movement to a non-member on the
same broadcast domain is blocked exactly like anything else internal.

ARP is NOT touched (the match is scoped to ip4), so L2 resolution of the
gateway's MAC still works -- it just never results in permitted IP traffic.

Run this AFTER `ovnctl vm-config`.
"""

from __future__ import annotations

import argparse
import re

from .. import netcalc, ovn, paths
from ..config import load_legacy_ranges
from ..context import (Abort, Ctx, acl_priority_of,
                       trace_acl_priorities, trace_verdict)
from ..inventory import Inventory
from ..state import VM_ISOLATION, Tracker, record
from ..steps import StepRunner, add_step_args

NAME = "vm-isolation"
HELP = "isolation port group and its scoped ACLs"

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--remove", action="store_true",
                   help="remove the port group and its ACLs")
    g.add_argument("--trace", nargs=2, metavar=("SRC", "DST"),
                   help="ovn-trace a packet through the external switch")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class VMIsolation:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.ls_ext = c.cfg("topology", "ls_ext")
        self.pg_name = c.cfg("vm_isolation", "pg_name")
        self.acl_priority = c.cfg_int("vm_isolation", "acl_priority")

        # The ACL match MUST scope itself to the group with "@<name>", and
        # OVN's match lexer only accepts [A-Za-z0-9_.] in an identifier. A
        # hyphenated name cannot be referenced, which historically meant the
        # scoping was omitted and the ACL silently applied to EVERY port on
        # the switch. Refuse to run rather than repeat that.
        if not _IDENT_RE.match(self.pg_name):
            raise Abort(
                f"port group name '{self.pg_name}' is not a valid OVN identifier\n"
                "(letters, digits, underscore, dot; no hyphens).\n"
                f"It could not be referenced as @{self.pg_name} in an ACL match,\n"
                "which would make the drop rules apply to the WHOLE switch.\n"
                "Fix vm_isolation.pg_name in ovn-settings.yaml (e.g. pg_isolated)."
            )

        # Port groups left over from earlier runs (e.g. the hyphenated name)
        # that must be removed, or their unscoped ACLs keep applying.
        self.legacy_pg_names = c.cfg_list("vm_isolation", "legacy_pg_names") \
            or ["pg-isolated"]

        self.inv = Inventory(c, ls_ext=self.ls_ext)
        self.isolated = self.inv.isolated_entries
        if not self.isolated:
            raise Abort("No [vm_isolation].isolated_vms configured -- "
                        "nothing to isolate.")

        self.internal_ranges = self._load_internal_ranges()

        # If an external (ASA-side) range overlaps one of ours, a plain drop
        # on the internal ranges would also block the isolated VMs' ONLY
        # legitimate path. So declare the external/shadow destinations
        # positively and permit them at a HIGHER priority than the drop.
        self.external_ranges = c.cfg_list("external_ranges", "ranges")
        self.shadow_ranges = c.cfg_list("shadow_ranges", "ranges")
        self.allow_ranges = self.external_ranges + self.shadow_ranges
        # Allow must outrank the drop or it has no effect.
        self.allow_priority = self.acl_priority + 100

        self.internal_match_set = netcalc.set_literal(self.internal_ranges)

    # ------------------------------------------------------------------
    def _load_internal_ranges(self) -> list[str]:
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
        ctx.warn("Falling back to a blanket RFC1918 block --")
        ctx.warn("this WOULD BLOCK the isolated VMs' only")
        ctx.warn("legitimate path if the external-to-us network")
        ctx.warn("also uses RFC1918. Fix by adding the ranges")
        ctx.warn("to ovn-settings.yaml [internal_ranges].")
        return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    # ------------------------------------------------------------------
    def check_ports_exist(self) -> None:
        ctx = self.ctx
        for name, uuid, _ip in self.isolated:
            if ovn.lsp_exists(ctx, uuid):
                continue
            if ctx.dry_run:
                ctx.warn(f"port {uuid} ({name}) does not exist "
                         "(dry-run: continuing).")
                continue
            raise Abort(f"Logical switch port {uuid} ({name}) does not exist.\n"
                        "Run `ovnctl vm-config` first.")

    # -- 1 ---------------------------------------------------------------
    def create_port_group(self) -> None:
        """Create the port group with all members in one shot.

        This deliberately does NOT use 'ovn-nbctl add Port_Group <g> ports
        <uuid>' to add members incrementally -- that needs the port's actual
        OVSDB row UUID, not its 'name'. Our VM ports are NAMED after the
        VM's own UUID, which looks like a UUID but is not the row's _uuid,
        so 'add' silently resolves to nothing and the reference is dropped:
        the group's ports column stays empty while the command reports
        success.

        pg-add resolves ports by name correctly, so: delete and recreate the
        group with all members specified at creation time. pg-del also
        clears the group's ACLs, which the next step re-adds immediately.
        """
        ctx = self.ctx
        ctx.dr_head("Port group")

        for legacy in self.legacy_pg_names:
            if not legacy or legacy == self.pg_name:
                continue
            if ovn.pg_exists(ctx, legacy):
                ctx.warn(f"Removing legacy port group '{legacy}' and its "
                         "unscoped ACLs.")
                if ctx.run("ovn-nbctl", "pg-del", legacy):
                    ctx.log(f"Removed legacy port group {legacy}.")
                else:
                    ctx.warn(f"Failed to remove legacy port group {legacy}.")

        ctx.log(f"Ensuring port group {self.pg_name} exists with correct "
                "membership...")
        if ovn.pg_exists(ctx, self.pg_name):
            ctx.log(f"Port group {self.pg_name} already exists -- recreating to "
                    "guarantee membership is correct.")
            ctx.run("ovn-nbctl", "pg-del", self.pg_name)

        port_names = [uuid for _n, uuid, _ip in self.isolated]
        ctx.run("ovn-nbctl", "pg-add", self.pg_name, *port_names)
        ctx.log(f"Created port group {self.pg_name} with {len(port_names)} members.")

        if ctx.dry_run:
            return

        # Verify membership actually took -- don't just trust the exit code.
        actual = ovn.pg_members(ctx, self.pg_name)
        if len(actual) != len(port_names):
            raise Abort(
                f"Port group {self.pg_name} has {len(actual)} members, "
                f"expected {len(port_names)}.\n"
                "Membership did not take -- check "
                f"'ovn-nbctl --bare --columns=ports list Port_Group {self.pg_name}'"
            )
        ctx.log(f"Verified: {len(actual)} members present in {self.pg_name}.")
        for name, uuid, _ip in self.isolated:
            ctx.log(f"  member: {name} ({uuid})")

    # -- 2 ---------------------------------------------------------------
    def add_acls(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Isolation ACLs")

        # --- allow tier (only when external/shadow ranges are declared) --
        # Added FIRST and at a higher priority so a destination in BOTH
        # lists is permitted out to the ASA rather than dropped.
        if self.allow_ranges:
            allow_set = netcalc.set_literal(self.allow_ranges)
            overlaps = netcalc.find_overlaps(self.internal_ranges,
                                             self.allow_ranges)
            if overlaps:
                ctx.warn("Internal and external/shadow ranges OVERLAP:")
                for i, e, d in overlaps:
                    ctx.warn(f"  internal {i} vs allowed {e} -> collides on {d}")
                ctx.warn("For these isolated VMs the collision resolves to ALLOW")
                ctx.warn(f"(priority {self.allow_priority} beats drop "
                         f"{self.acl_priority}) --")
                ctx.warn("i.e. overlapping addresses are treated as external.")
                ctx.warn("That is intended here, but confirm it is what you want:")
                ctx.warn("these VMs will reach the ASA-side twin of that address,")
                ctx.warn("never the internal one.")

            ctx.log("Adding from-lport allow (outbound to external/shadow) at "
                    f"priority {self.allow_priority}...")
            ovn.add_acl(ctx, self.pg_name, "from-lport", self.allow_priority,
                        f"inport == @{self.pg_name} && ip4 && "
                        f"ip4.dst == {allow_set}",
                        "allow-related", name="isolated-allow-out",
                        log=True, severity="info")

            ctx.log("Adding to-lport allow (inbound from external/shadow) at "
                    f"priority {self.allow_priority}...")
            ovn.add_acl(ctx, self.pg_name, "to-lport", self.allow_priority,
                        f"outport == @{self.pg_name} && ip4 && "
                        f"ip4.src == {allow_set}",
                        "allow-related", name="isolated-allow-in",
                        log=True, severity="info")
        else:
            ctx.log("No [external_ranges]/[shadow_ranges] declared -- "
                    "no allow tier needed.")

        # CRITICAL: the "inport/outport == @<group>" scoping is what limits
        # these drops to group MEMBERS. OVN installs port-group ACLs on every
        # logical switch the group's ports belong to, but it does NOT scope
        # the match for you -- without this, the rule drops traffic for every
        # port on the switch, including non-members and the router port.
        ctx.log(f"Adding from-lport drop (member -> internal) at priority "
                f"{self.acl_priority}...")
        ovn.add_acl(ctx, self.pg_name, "from-lport", self.acl_priority,
                    f"inport == @{self.pg_name} && ip4 && "
                    f"ip4.dst == {self.internal_match_set}", "drop",
                    name="isolated-drop-out", log=True, severity="info")

        ctx.log(f"Adding to-lport drop (internal -> member) at priority "
                f"{self.acl_priority}...")
        ovn.add_acl(ctx, self.pg_name, "to-lport", self.acl_priority,
                    f"outport == @{self.pg_name} && ip4 && "
                    f"ip4.src == {self.internal_match_set}", "drop",
                    name="isolated-drop-in", log=True, severity="info")

        self._name_existing_acls()

        ctx.log("Traffic to anything NOT in [internal_ranges] is unaffected --")
        ctx.log("OVN's default with no matching ACL is allow, so it falls through")
        ctx.log("to lr-core and the ASA reroute policy untouched.")

    def _name_existing_acls(self) -> None:
        """Backfill names on ACLs created before they carried one.

        --may-exist makes acl-add a no-op when the (direction, priority,
        match) triple is already there, so it will not apply a name to an
        existing row. Every deployment built before named ACLs is in that
        state; reconcile the column rather than requiring a teardown to
        get readable output from `ovnctl show`.
        """
        ctx = self.ctx
        if ctx.dry_run:
            return
        wanted = {
            ("from-lport", str(self.acl_priority),
             f"inport == @{self.pg_name} && ip4 && "
             f"ip4.dst == {self.internal_match_set}"): "isolated-drop-out",
            ("to-lport", str(self.acl_priority),
             f"outport == @{self.pg_name} && ip4 && "
             f"ip4.src == {self.internal_match_set}"): "isolated-drop-in",
        }
        index = ovn.acl_index(ctx)
        for key, name in wanted.items():
            entry = index.get(key)
            if not entry:
                continue
            if entry.get("name") == name:
                continue
            uuid = entry["uuid"]
            if not ctx.run("ovn-nbctl", "set", "acl", uuid, f"name={name}"):
                ctx.warn(f"Could not set name '{name}' on ACL {uuid}.")

    # -- 3 ---------------------------------------------------------------
    def verify_scope(self) -> None:
        """Prove the ACLs affect ONLY group members.

        This exists because of a real outage: port-group ACLs are installed
        on every logical switch the group's ports touch, and if the match
        isn't scoped with inport/outport == @group it silently drops traffic
        for EVERY port on that switch. The failure is invisible in
        `acl-list` -- the rules look right -- and shows up only as unrelated
        VMs losing connectivity. So ask OVN directly.
        """
        ctx = self.ctx
        if ctx.dry_run:
            return
        ctx.log("Verifying ACL scope (non-members must be unaffected)...")

        # ovn-trace reads the SOUTHBOUND db. The ACLs above were written to
        # the NORTHBOUND db moments ago and northd compiles between the two
        # asynchronously, so tracing straight away can report the pipeline
        # as it was before those ACLs existed. Wait for northd first --
        # otherwise this reports "member was NOT blocked" on a deployment
        # that is completely correct, which is what it used to do on every
        # first run.
        ovn.sync_sb(ctx)

        if not ctx.have("ovn-trace"):
            ctx.warn("ovn-trace not available -- cannot verify scope automatically.")
            ctx.warn("Manually confirm a NON-member is still reachable before "
                     "trusting this.")
            return

        if not self.inv.external:
            ctx.warn("No [vm_config].external_vms in yaml -- skipping scope "
                     "verification.")
            return

        iso_uuids = {uuid for _n, uuid, _ip in self.isolated}
        victim = next((vm for vm in self.inv.external
                       if vm.uuid not in iso_uuids), None)
        if victim is None:
            ctx.log("Every external VM is a group member -- no non-member to "
                    "verify against.")
            return

        lrp_ext_mac = ctx.cfg("setup", "lrp_ext_mac")
        host_ip = ctx.cfg("setup", "host_if_ip")

        ctx.log(f"  probing non-member {victim.name} ({victim.ip}) from the "
                "router port...")
        expr = (f'inport=="{self.ls_ext}-to-lr" && eth.src=={lrp_ext_mac} && '
                f'eth.dst=={victim.mac} && ip4.src=={host_ip} && '
                f'ip4.dst=={victim.ip} && ip.ttl==63')
        out = ovn.trace(ctx, self.ls_ext, expr)
        verdict = trace_verdict(out)

        if verdict == "UNKNOWN":
            ctx.warn("ovn-trace produced no usable verdict for the non-member "
                     "probe --")
            ctx.warn("scope has NOT been verified. Output was:")
            ctx.note_stderr(out or "(nothing)")
            ctx.warn("Verify by hand before trusting this isolation:")
            ctx.warn(f"  ovn-trace {self.ls_ext} '{expr}'")
            return

        if verdict == "DROP":
            ctx.err(f"SCOPE FAILURE: traffic to NON-member {victim.name} "
                    f"({victim.ip}) is being DROPPED.")
            ctx.err("The ACLs are applying to the whole switch instead of just "
                    "group members.")
            ctx.err("Offending trace:")
            ctx.note_stderr(out)
            ctx.err("Removing the port group to avoid leaving a switch-wide "
                    "outage in place.")
            ctx.run("ovn-nbctl", "pg-del", self.pg_name)
            Tracker(ctx).unmark(VM_ISOLATION)
            raise Abort("isolation aborted -- ACL scope was wrong, "
                        "port group removed.")

        ctx.log(f"  OK: non-member {victim.name} is NOT affected by the "
                "isolation ACLs.")

        # And confirm the members ARE blocked (isolation actually works).
        #
        # Every member, not just the first. Probing self.isolated[0] alone
        # meant the message always named the same VM, which read as "this
        # one VM is special" when it only ever meant "index zero" -- and it
        # said nothing at all about the other three.
        blocked: list[str] = []
        unblocked: list[str] = []
        exempted: list[str] = []
        unknown: list[str] = []
        last_expr = last_out = ""
        fail_expr = fail_out = ""
        for m_name, m_uuid, m_ip in self.isolated:
            member = self.inv.by_uuid(m_uuid)
            if member is None:
                continue
            target = m_ip or member.ip
            # Bare ip4, NOT icmp4. The isolation drop is protocol-agnostic,
            # so any protocol tests it -- but ICMP is now deliberately
            # exempted from it for troubleshooting ([acls] icmp-mgmt-in),
            # and probing with the one protocol that has a documented
            # exception makes this check report the exception as a
            # failure. It did exactly that, and only on a RE-RUN: on a
            # first deploy the acl stage has not run yet when this
            # executes, so the exception does not exist and the same code
            # passes. A check whose result depends on what a previous run
            # left behind is worse than no check.
            expr = (f'inport=="{self.ls_ext}-to-lr" && eth.src=={lrp_ext_mac} && '
                    f'eth.dst=={member.mac} && ip4.src=={host_ip} && '
                    f'ip4.dst=={target} && ip.ttl==63')
            out = ovn.trace(ctx, self.ls_ext, expr)
            verdict = trace_verdict(out)
            if verdict == "DROP":
                blocked.append(m_name)
            elif verdict == "UNKNOWN":
                unknown.append(f"{m_name} ({target})")
                last_expr, last_out = expr, out
            else:
                # Allowed -- but by WHAT? A rule above this one is an
                # intentional exception someone configured; nothing at all
                # is a broken deployment. Naming the priority is the
                # difference between "check your policy" and "check your
                # northd".
                decided = [p for p in trace_acl_priorities(out, "out")
                           if p > 0]
                mine = int(self.acl_priority)
                higher = [p for p in decided if acl_priority_of(p) > mine]
                if higher:
                    exempted.append(
                        f"{m_name} ({target}) via priority "
                        f"{acl_priority_of(max(higher))}")
                else:
                    unblocked.append(f"{m_name} ({target})")
                    if not fail_expr:
                        fail_expr, fail_out = expr, out

        if blocked:
            ctx.log(f"  OK: {len(blocked)} member(s) correctly blocked from "
                    f"internal: {', '.join(blocked)}")
        if exempted:
            ctx.log(f"  {len(exempted)} member(s) reachable via a "
                    f"higher-priority allow (configured exception):")
            for line in exempted:
                ctx.log(f"    {line}")

        # Separated deliberately. "the trace could not tell us" and "the
        # ACL is not working" are completely different problems, and
        # reporting the first as the second sends you to read acl-list for
        # a rule that is perfectly correct.
        if unknown:
            ctx.warn(f"{len(unknown)} member(s) could NOT be verified -- "
                     "ovn-trace gave no usable verdict:")
            for entry in unknown:
                ctx.warn(f"  {entry}")
            ctx.warn("This says nothing about whether isolation works. The "
                     "usual cause is")
            ctx.warn(f"ovn-trace timing out on a large Southbound db "
                     f"(limit is {ovn.TRACE_TIMEOUT}s).")
            ctx.warn("Last trace output was:")
            ctx.note_stderr(last_out or "(nothing)")
            ctx.warn("Reproduce with:")
            ctx.warn(f"  ovn-trace {self.ls_ext} '{last_expr}'")

        if not unblocked:
            return

        ctx.warn(f"{len(unblocked)} member(s) NOT blocked -- isolation may not "
                 "be effective:")
        for entry in unblocked:
            ctx.warn(f"  {entry}")
        self._explain_unblocked(fail_expr, fail_out)

    def _explain_unblocked(self, expr: str, out: str) -> None:
        """Show the evidence rather than just the conclusion.

        A bare "not blocked" sends you to read acl-list and compare match
        strings by eye. The three things needed to tell an ACL problem from
        a probe problem are the trace itself, what OVN actually has
        deployed, and whether northd has compiled it -- so print all three
        here instead of making them the next round-trip.
        """
        ctx = self.ctx
        if expr:
            ctx.warn("Trace for the first unblocked member "
                     "(ALLOW means the drop ACL was never reached):")
            tail = out.splitlines()[-25:]
            ctx.note_stderr("\n".join(tail) if tail else "(no output)")
            ctx.warn("Reproduce with:")
            ctx.warn(f"  ovn-trace {self.ls_ext} '{expr}'")

        acls = ctx.qout("ovn-nbctl", "acl-list", self.pg_name)
        ctx.warn(f"Deployed ACLs on {self.pg_name}:")
        ctx.note_stderr(acls or "(none -- the ACLs were not created)")

        members = ovn.pg_members(ctx, self.pg_name)
        ctx.warn(f"Port group members ({len(members)}): "
                 f"{', '.join(members) or '(none)'}")

        # If northd has not compiled the ACLs into logical flows, the trace
        # is describing a pipeline that does not contain them yet -- which
        # looks exactly like a missing ACL.
        if not ctx.have("ovn-sbctl"):
            ctx.warn("ovn-sbctl not available -- cannot tell whether northd "
                     "has compiled these ACLs.")
            return
        res = ctx.q("ovn-sbctl", "--bare", "--columns=_uuid", "find",
                    "Logical_Flow", f"match~=\"{self.pg_name}\"")
        if not res:
            # An empty result and a failed command look identical if you
            # only read stdout, and announcing "northd has not compiled
            # these ACLs" because the SB socket was unreadable sends
            # someone to restart a daemon that was never the problem.
            ctx.warn("Could not query the Southbound db, so whether northd "
                     "has compiled these ACLs is unknown.")
            return
        n_flows = len([f for f in res.stdout.splitlines() if f.strip()])
        if n_flows:
            ctx.warn(f"Southbound logical flows referencing {self.pg_name}: "
                     f"{n_flows} (northd has compiled them).")
        else:
            ctx.warn(f"NO Southbound logical flow references {self.pg_name}.")
            ctx.warn("northd has not compiled these ACLs, so nothing can "
                     "enforce them yet.")
            ctx.warn("Check: systemctl status ovn-northd")

    # ------------------------------------------------------------------
    def run_trace(self, src: str, dst: str) -> None:
        ctx = self.ctx
        ctx.require_cmd("ovn-trace")
        ctx.log(f"Tracing src={src} dst={dst} through {self.ls_ext}...")

        src_vm = self.inv.by_ip(src)
        dst_vm = self.inv.by_ip(dst)

        inport = src_vm.uuid if src_vm else ""
        src_mac = src_vm.mac if src_vm else ""

        # Fall back to the isolated list for the inport if the full
        # inventory does not carry this IP.
        if not inport:
            for _n, uuid, ip in self.isolated:
                if ip == src:
                    inport = uuid
                    break

        # Choose eth.dst the way a real guest would.
        #
        # This matters: without it the frame carries an all-zero destination
        # MAC, the FDB lookup misses, and the packet dies at
        # ls_in_l2_unknown -- which looks like a policy drop but is purely an
        # artifact of the trace. On-subnet destinations go straight to the
        # peer's MAC; anything else goes to the router port's MAC.
        lrp_ext_mac = ctx.cfg("setup", "lrp_ext_mac")
        lrp_ext_cidr = ctx.cfg("setup", "lrp_ext_cidr")
        on_subnet = netcalc.cidr_contains(lrp_ext_cidr, dst)

        if on_subnet and dst_vm is not None:
            eth_dst = dst_vm.mac
            ctx.log(f"  destination is on-subnet ({dst_vm.name}) -- "
                    "eth.dst = its own MAC")
        else:
            eth_dst = lrp_ext_mac
            if on_subnet:
                ctx.log("  destination is on-subnet but unknown to the inventory --")
                ctx.log("  using the gateway MAC; result may not reflect a real frame.")
            else:
                ctx.log(f"  destination is off-subnet -- eth.dst = gateway MAC "
                        f"({lrp_ext_mac})")

        if not src_mac:
            src_mac = "00:00:00:00:00:01"

        print("")
        if inport:
            expr = (f'inport=="{inport}" && eth.src=={src_mac} && '
                    f'eth.dst=={eth_dst} && ip4.src=={src} && ip4.dst=={dst} && '
                    f'ip.ttl==64 && icmp4')
        else:
            ctx.warn(f"{src} isn't a known VM on {self.ls_ext} -- tracing "
                     "without inport context.")
            ctx.warn("(ACLs scoped to the port group cannot match without an "
                     "inport, so")
            ctx.warn(" this will NOT show isolation behaviour.)")
            expr = (f'eth.src=={src_mac} && eth.dst=={eth_dst} && '
                    f'ip4.src=={src} && ip4.dst=={dst} && ip.ttl==64 && icmp4')
        print(ovn.trace(ctx, self.ls_ext, expr))

    # ------------------------------------------------------------------
    def teardown(self) -> None:
        ctx = self.ctx
        ctx.log("Removing isolation port group and its ACLs...")
        # pg-del removes the group; ACLs referenced only via this group's
        # acl column are garbage-collected once the group is gone.
        # (--if-exists isn't supported by pg-del on all OVN versions, so
        # check existence first.)
        if ovn.pg_exists(ctx, self.pg_name):
            if ctx.run("ovn-nbctl", "pg-del", self.pg_name):
                ctx.log(f"Removed port group {self.pg_name} (and its ACLs).")
        else:
            ctx.log(f"Port group {self.pg_name} does not exist, nothing to remove.")
        Tracker(ctx).unmark(VM_ISOLATION)
        ctx.log("Removed 'vm-isolation' from deployment tracker.")
        ctx.log("Done. The VMs are no longer isolated -- they'll behave like any")
        ctx.log(f"other port on {self.ls_ext} (still subject to the ASA reroute")
        ctx.log("policy for external traffic, but no longer blocked from internal).")

    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        ctx = self.ctx
        print("")
        print("=== Isolation summary ===")
        print(f"Port group:  {self.pg_name}")
        print("Members:")
        for name, uuid, ip in self.isolated:
            print(f"  {name}  ({ip})  port={uuid}")
        print("")
        print(f"Blocked (both directions): {' '.join(self.internal_ranges)}")
        print("  -- this list comes from [internal_ranges], NOT a blanket")
        print("     RFC1918 block (the external-to-us network via the ASA also")
        print("     uses RFC1918, so that would've cut off these VMs' only path).")
        print("  It includes the gateway itself and same-subnet neighbours, since")
        print("  both fall inside the listed ranges.")
        print("Not blocked: ARP (L2 resolution still works), and anything outside")
        print("  the list above -- that traffic reaches lr-core and follows the")
        print("  existing reroute policy out to the ASA.")
        print("Console access: unaffected -- VNC/KVM console is out-of-band from")
        print("  this network path entirely.")
        print("")
        print(f"Current ACLs on {self.pg_name}:")
        for line in ovn.acl_list(ctx, self.pg_name):
            print(f"  {line}")
        print("")
        print("Trace both cases before testing live:")
        first_ip = self.isolated[0][2] or "<member-ip>"
        print(f"  ovnctl vm-isolation --trace {first_ip} 192.168.1.50   "
              "# should show DROP")
        print(f"  ovnctl vm-isolation --trace {first_ip} 8.8.8.8        "
              "# should reach router, reroute to ASA")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-isolate")
    ctx.require_cfg("setup:host_if_ip", "setup:lrp_ext_cidr", "setup:lrp_ext_mac",
                    "topology:ls_ext", "vm_isolation:acl_priority",
                    "vm_isolation:pg_name")

    ctx.require_root()
    ctx.require_cmd("ovn-nbctl")

    cmd = VMIsolation(ctx)

    if args.remove:
        cmd.teardown()
        return 0

    if args.trace:
        cmd.run_trace(args.trace[0], args.trace[1])
        return 0

    runner = StepRunner(ctx, "vm-isolation")
    runner.add("check-ports", "verify every isolated port exists",
               cmd.check_ports_exist)
    runner.add("port-group", "create the port group with correct membership",
               cmd.create_port_group)
    runner.add("acls", "the allow tier and the two drop ACLs", cmd.add_acls)
    runner.add("verify-scope", "prove non-members are unaffected",
               cmd.verify_scope)

    if not runner.run(args):
        return 0

    record(ctx, VM_ISOLATION, runner)

    if ctx.verbose and not ctx.dry_run:
        cmd.print_summary()
    ctx.finish("isolation port group + scoped ACLs")
    return 0