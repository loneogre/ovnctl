"""
ovnctl vm-attach -- port of ovn-vm-attach.sh

Re-attaches running VMs' tap interfaces to br-int with the correct
iface-id, without restarting the guests.

Why this is needed: deleting br-int (as `ovnctl delete` does) detaches
every running VM's tap from OVS. libvirt only plugs a tap in when a domain
starts, so after a teardown + redeploy the guests keep running with a tap
attached to nothing -- their ports show "DOWN (no chassis)" forever.
Rebooting works only because it restarts the guests.

Taps are matched to logical ports by MAC using [vm_config], so a mismatch
is reported rather than silently wired to the wrong port.
"""

from __future__ import annotations

import argparse
import time

from .. import inventory, libvirtutil, ovn
from ..context import Abort, Ctx
from ..inventory import VM, Inventory
from ..steps import StepRunner, add_step_args

NAME = "vm-attach"
HELP = "re-attach running VM taps to br-int"

# How long to wait for ovn-controller to claim a freshly attached port.
#
# This used to be a flat 3-second sleep followed by an immediate status
# print, which is why `ovnctl deploy` could report every VM as
# "DOWN (no chassis)" on a deployment that was in fact fine thirty seconds
# later. Claiming is not instant, and it is slowest right after
# `delete --purge-db`, when ovn-controller is rebuilding its whole view.
DEFAULT_TIMEOUT = 60


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--status", action="store_true",
                   help="show what is attached vs not, and change nothing")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   metavar="SECONDS",
                   help=f"how long to wait for ports to bind "
                        f"(default: {DEFAULT_TIMEOUT})")
    p.add_argument("--watch-memory", action="store_true",
                   help="sample ovn-controller's resident memory each second "
                        "while waiting, and print the curve")
    p.add_argument("--no-nudge", dest="nudge", action="store_false",
                   default=True,
                   help="do not re-assert iface-id on a port that is still "
                        "unclaimed halfway through the wait (the nudge is on "
                        "by default and is skipped automatically when "
                        "ovn-controller's memory looks abnormal)")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class VMAttach:
    def __init__(self, ctx: Ctx, timeout: int = DEFAULT_TIMEOUT,
                 watch_memory: bool = False, nudge: bool = True):
        self.ctx = ctx
        # Sampling the curve is how you tell "allocates enormously on the
        # first claim" from "leaks steadily while running" -- two different
        # bugs that look identical once the number is already huge.
        self.watch_memory = watch_memory
        self.nudge = nudge
        self.br_int = ctx.cfg("topology", "br_int")
        self.timeout = timeout
        self.inv = Inventory(ctx.config)
        if not self.inv.all:
            raise Abort("No [vm_config] inventory in ovn-settings.yaml -- "
                        "cannot map taps to ports.")
        # user-vm slots are NOT in [vm_config] -- they are allocated at
        # runtime and recorded in state/user-vms.json. Without them here,
        # a user VM's tap has a MAC this command cannot match, so it is
        # reported as "not in the inventory" and never attached: the one
        # class of VM whose owner is least able to debug it.
        self.vms = list(self.inv.all) + inventory.user_vm_slots()
        extra = len(self.vms) - len(self.inv.all)
        ctx.log(f"Loaded {len(self.inv.all)} VMs from the inventory"
                + (f" and {extra} user-vm slot(s)." if extra else "."))
        self.attached = 0
        self.skipped = 0
        self.unknown = 0
        # Every VM that has a live tap this run, attached now or already
        # attached. These are the ones that SHOULD end up bound, and the
        # only ones worth waiting on -- a powered-off VM has no tap and
        # will never bind, which is not a fault.
        self.expect_bound: list[tuple[VM, str]] = []

    def _by_mac(self, mac: str):
        want = mac.lower()
        for vm in self.vms:
            if vm.mac.lower() == want:
                return vm
        return None

    # ------------------------------------------------------------------
    def check_bridge(self) -> None:
        if not ovn.br_exists(self.ctx, self.br_int):
            raise Abort(f"{self.br_int} does not exist. Run `ovnctl setup` first.")

    # ------------------------------------------------------------------
    def attach(self) -> None:
        ctx = self.ctx
        domains = libvirtutil.running_domains(ctx)
        if not domains:
            ctx.log("No running VMs.")
            return

        ctx.dr_head(f"Re-attach VM taps to {self.br_int}")
        bridge_ports = ovn.list_ports(ctx, self.br_int)

        for domain in domains:
            for iface in libvirtutil.domiflist(ctx, domain):
                vm = self._by_mac(iface.mac)
                if vm is None:
                    ctx.warn(f"{domain}: tap {iface.tap} has MAC {iface.mac}, "
                             "which is not in the inventory.")
                    ctx.warn("  Not attaching -- fix [vm_config] or the domain "
                             "XML first.")
                    self.unknown += 1
                    continue

                self.expect_bound.append((vm, iface.tap))

                if iface.tap in bridge_ports:
                    current = ovn.iface_id_of(ctx, iface.tap)
                    if current == vm.uuid:
                        ctx.log(f"  {domain}/{iface.tap} ({vm.name}) already "
                                "attached correctly.")
                        self.skipped += 1
                        continue
                    ctx.warn(f"{domain}/{iface.tap} is attached with iface-id "
                             f"'{current}', expected '{vm.uuid}'. Correcting.")

                ctx.run("ovs-vsctl", "--may-exist", "add-port", self.br_int,
                        iface.tap, "--", "set", "interface", iface.tap,
                        f"external-ids:iface-id={vm.uuid}")
                ctx.log(f"  attached {domain}/{iface.tap} -> {vm.name} ({vm.uuid})")
                self.attached += 1

        if ctx.dry_run:
            return

        print("")
        ctx.log(f"Attached {self.attached}, already correct {self.skipped}, "
                f"unmatched {self.unknown}.")

    # ------------------------------------------------------------------
    def wait_for_bindings(self) -> None:
        """Wait until every tap that should be claimed actually is.

        Polls the SB db rather than sleeping a fixed interval. The old
        3-second sleep was a guess, and it was wrong in the one situation
        this command exists for: straight after `delete --purge-db`,
        ovn-controller is rebuilding from an empty SB db and has several
        hundred thousand flows to compute, so a claim can take far longer
        than three seconds. Deploy then printed "DOWN (no chassis)" for a
        deployment that came good on its own a minute later, which is
        indistinguishable from a real failure.
        """
        ctx = self.ctx
        if ctx.dry_run or not self.expect_bound:
            return

        # vm-config wrote the logical ports to the NORTHBOUND db moments
        # ago; there is no Port_Binding to claim until northd has compiled
        # them. Waiting on the controller before that is waiting on the
        # wrong process.
        ovn.sync_sb(ctx)

        pending = list(self.expect_bound)
        ctx.log(f"Waiting up to {self.timeout}s for ovn-controller to claim "
                f"{len(pending)} port(s)...")
        nudged = False
        deadline = time.time() + self.timeout

        # Baseline, so the guard below measures GROWTH rather than an
        # absolute that might be normal on a bigger deployment.
        rss0 = ovn.controller_rss_mb(ctx)
        if rss0:
            ctx.log(f"  ovn-controller resident memory: {rss0} MB")

        while pending and time.time() < deadline:
            # Stop hammering a controller that is running away with the
            # host's memory. Claiming a port is what triggers it to build
            # that datapath's pipeline, so continuing to poll -- and worse,
            # re-asserting iface-id to force another claim -- drives the
            # box towards OOM while we wait for something that is not
            # going to happen.
            rss = ovn.controller_rss_mb(ctx)
            if rss > ovn.CONTROLLER_RSS_WARN_MB:
                ctx.warn(f"ovn-controller has reached {rss} MB resident "
                         f"(was {rss0} MB when this started).")
                ctx.warn("Abandoning the wait rather than provoking further "
                         "claims -- each one")
                ctx.warn("makes it worse, and the host is what pays for it.")
                for vm, tap in pending:
                    ctx.warn(f"  {vm.name} left unbound (tap {tap})")
                self.explain_unbound(*pending[0])
                return

            if self.watch_memory and rss:
                elapsed = int(time.time() - (deadline - self.timeout))
                ctx.log(f"    t+{elapsed:>3}s  {rss} MB")

            still: list[tuple[VM, str]] = []
            for vm, tap in pending:
                if ovn.port_binding_chassis(ctx, vm.uuid):
                    ctx.log(f"  {vm.name} bound.")
                else:
                    still.append((vm, tap))
            pending = still
            if not pending:
                break

            # ON by default, with a guard.
            #
            # Clearing and re-setting iface-id makes ovn-controller RELEASE
            # the port and then CLAIM it again -- the right cure for a
            # missed event, which is what happens when the SB Port_Binding
            # row had not propagated at the moment the key first appeared.
            #
            # It was briefly opt-in, on the theory that claiming was
            # expensive. It is not: that turned out to be a negated
            # destination in a router policy, now fixed. What remains is
            # the `rss` condition below, which skips the nudge if the
            # controller's memory looks abnormal -- if claiming is ever
            # expensive again, forcing a second one is the worst available
            # move, and that guard costs nothing when things are healthy.
            if (self.nudge and not nudged
                    and time.time() > deadline - self.timeout / 2
                    and rss <= ovn.CONTROLLER_RSS_WARN_MB):
                nudged = True
                ctx.log("  Still unclaimed -- re-asserting iface-id to "
                        "re-trigger the claim.")
                for vm, tap in pending:
                    ctx.run("ovs-vsctl", "remove", "interface", tap,
                            "external-ids", "iface-id")
                    ctx.run("ovs-vsctl", "set", "interface", tap,
                            f"external-ids:iface-id={vm.uuid}")
            time.sleep(2)

        if not pending:
            ctx.log("All expected ports are bound.")
            return

        ctx.warn(f"{len(pending)} port(s) still unbound after {self.timeout}s:")
        for vm, tap in pending:
            ctx.warn(f"  {vm.name} ({vm.uuid}) tap {tap}")
            self.explain_unbound(vm, tap)
        if not self.nudge:
            ctx.warn("The iface-id nudge was disabled (--no-nudge), so no "
                     "re-claim was attempted.")

    def explain_unbound(self, vm, tap: str) -> None:
        """Say WHICH of the three causes this is.

        "ovn-controller is not claiming it" was the old message and it is
        only one of the possibilities -- the other two are not
        ovn-controller's fault at all, and chasing its log for them wastes
        the time when the fix is somewhere else entirely:

          1. no SB Port_Binding row  -> northd has not compiled the
             logical port yet (or vm-config never created it). Nothing to
             claim. Not an ovn-controller problem.
          2. the tap is dead in OVS (ofport -1, or an error column) ->
             usually the tap device disappeared underneath OVS when br-int
             was recreated. ovn-controller cannot claim a port with no
             datapath number, and no amount of re-setting iface-id will
             change that. The VM has to be restarted, or its interface
             re-attached in libvirt.
          3. both fine -> genuinely a controller problem, and now the log
             is worth reading.
        """
        ctx = self.ctx

        # 1. Does the port exist in the Southbound db at all?
        rows = ctx.qout("ovn-sbctl", "--bare", "--columns=_uuid", "find",
                        "Port_Binding", f"logical_port={vm.uuid}")
        if not rows.strip():
            ctx.warn("    No Southbound Port_Binding row exists for this "
                     "port.")
            ctx.warn("    ovn-controller has nothing to claim -- this is "
                     "northd, not the controller.")
            ctx.warn(f"    Check: ovn-nbctl find Logical_Switch_Port "
                     f"name={vm.uuid}")
            ctx.warn("           systemctl status ovn-northd")
            ctx.warn("    An empty first result means vm-config never made "
                     "the port;")
            ctx.warn("    a populated one means northd has not compiled it.")
            return

        # 2. Is the tap usable by OVS?
        ofport = ctx.qout("ovs-vsctl", "--if-exists", "get", "interface", tap,
                          "ofport").strip()
        error = ctx.qout("ovs-vsctl", "--if-exists", "get", "interface", tap,
                         "error").strip()
        if ofport in ("-1", "[]", "") or (error and error != "[]"):
            ctx.warn(f"    The tap is not usable by OVS: ofport={ofport or '?'}"
                     f"{'  error=' + error if error and error != '[]' else ''}")
            ctx.warn("    A port with no OpenFlow number cannot be claimed, "
                     "and re-setting")
            ctx.warn("    iface-id will not change that. The usual cause is "
                     "the tap device")
            ctx.warn("    disappearing underneath OVS when br-int was "
                     "recreated -- libvirt")
            ctx.warn("    created it against the old bridge and nothing "
                     "recreated it.")
            ctx.warn(f"    Fix: virsh destroy/start the domain owning {tap}, "
                     "then re-run")
            ctx.warn("         ovnctl vm-attach")
            return

        # 3. Everything the controller needs is present, so interrogate the
        #    controller instead of telling the operator to go and do it.
        #    "Check the log" is not a diagnosis, and the state that answers
        #    this is four commands nobody should have to remember under
        #    time pressure.
        ctx.warn("    Port exists in SB and the tap is usable. Controller "
                 "state:")

        alive = ctx.q("pgrep", "-x", "ovn-controller").ok
        ctx.warn(f"      process running     : {'yes' if alive else 'NO'}")

        # Checked BEFORE the connection status, because it changes what an
        # unresponsive socket means. "Busy" is a state a controller comes
        # out of; a multi-gigabyte resident set is one it does not, and
        # from the outside the two are identical.
        rss = ovn.controller_rss_mb(ctx)
        if rss:
            flag = "  <-- ABNORMAL" if rss > ovn.CONTROLLER_RSS_WARN_MB else ""
            ctx.warn(f"      resident memory     : {rss} MB{flag}")
        if rss > ovn.CONTROLLER_RSS_WARN_MB:
            ctx.warn("      -> ovn-controller is using far more memory than "
                     "this topology")
            ctx.warn("         can account for. A few tens of MB is normal "
                     "for one chassis")
            ctx.warn("         and ~600 flows. At this size it stops "
                     "servicing its control")
            ctx.warn("         socket, claims ports slowly or not at all, "
                     "and cannot be")
            ctx.warn("         stopped cleanly -- every symptom in this "
                     "report follows from it.")
            ctx.warn("         This is the daemon, not the deployment.")
            sizes = ovn.sb_table_sizes(ctx)
            ctx.warn("         Southbound row counts: " + ", ".join(
                f"{k}={v}" for k, v in sizes.items()))
            if sizes.get("MAC_Binding", 0) > 1000:
                ctx.warn("         MAC_Binding is large -- it grows from "
                         "observed traffic, not")
                ctx.warn("         from configuration, and is the usual "
                         "cause of controller")
                ctx.warn("         memory that does not match the topology.")
            else:
                ctx.warn("         None of these explain the memory. That "
                         "points at the daemon")
                ctx.warn("         itself: check `ovn-controller --version` "
                         "against known leaks.")
            ctx.warn("         A restart reclaims the memory but does not "
                     "address the cause.")

        if not alive:
            ctx.warn("      -> ovn-controller is not running. Nothing will "
                     "bind until it is.")
            ctx.warn("         systemctl status ovn-controller")
            return

        res = ovn.appctl(ctx, "connection-status")
        conn = res.stdout.strip()
        ctx.warn(f"      control socket      : "
                 f"{ovn.controller_ctl(ctx) or 'NOT FOUND'}")
        ctx.warn(f"      SB connection       : {conn or 'no answer'}")
        if not conn and res.stderr:
            ctx.warn(f"      appctl said         : {res.stderr.splitlines()[0]}")
        if not conn:
            # An empty answer usually means the controller is too busy to
            # service its control socket -- which on this deployment means
            # it is rebuilding, and a rebuilding controller claims nothing.
            ctx.warn("      -> the control socket did not answer. That "
                     "normally means")
            ctx.warn("         ovn-controller is still rebuilding its "
                     "flow table. Wait, then")
            ctx.warn("         re-run `ovnctl vm-attach`; it is not stuck, "
                     "just busy.")

        local_id = ovn.external_id(ctx, "system-id").strip()
        registered = ovn.chassis_names(ctx)
        ctx.warn(f"      local system-id     : {local_id or '<unset>'}")
        ctx.warn(f"      registered chassis  : "
                 f"{', '.join(registered) or '(none)'}")
        if local_id and local_id not in registered:
            ctx.warn("      -> the controller has not registered under its "
                     "own system-id.")
            ctx.warn("         It cannot claim anything. "
                     "ovnctl reconcile --repair-identity")
            return

        # requested_chassis is the one field that makes a healthy
        # controller refuse a port it can otherwise see: if it names a
        # different chassis, this one is being told to keep its hands off.
        row = ctx.qout("ovn-sbctl", "list", "Port_Binding", vm.uuid)
        for line in row.splitlines():
            key = line.split(":", 1)[0].strip()
            if key in ("up", "requested_chassis", "additional_chassis",
                       "requested_additional_chassis", "options", "type"):
                ctx.warn(f"      {line.strip()}")

        # ovn-controller's OWN log, not systemd's view of the unit. The
        # journal only ever showed "stopping / starting", which is the one
        # thing we already knew; the daemon writes "Claiming lport ..." (or
        # its reason for not) to its log file.
        log = ovn.controller_log_tail(ctx, match=vm.uuid[:8])
        if log.strip():
            ctx.warn("    ovn-controller log (binding/errors):")
            for line in log.splitlines():
                ctx.warn(f"      {line}")
        else:
            ctx.warn("    ovn-controller's log file was not readable. Try:")
            for path in ovn.CONTROLLER_LOGS:
                ctx.warn(f"      tail -50 {path}")
            ctx.warn("    (journalctl -u ovn-controller shows only systemd's "
                     "view of the unit,")
            ctx.warn("     not what the daemon itself is saying.)")

    # ------------------------------------------------------------------
    def print_status(self) -> None:
        """The resulting table.

        A VM with no tap is powered off and was never going to bind, so it
        gets its own state rather than the same "DOWN (no chassis)" as a
        running VM whose port failed to be claimed. Printing ten identical
        alarming rows, nine of which are normal, trains people to ignore
        the one that matters.
        """
        ctx = self.ctx
        # A live-state report, not a command. Under --dry-run it would be
        # printed into `ovnctl runbook`'s output, which captures stdout to
        # build a shell script -- a table of port bindings in the middle of
        # one is at best confusing and at worst breaks it.
        if ctx.dry_run:
            ctx.log("(status table omitted in dry-run: it reports live state, "
                    "not commands)")
            return
        chassis_names = ovn.chassis_uuid_names(ctx)
        print("")
        print("=== Port binding status ===")
        print(f"{'VM':<10} {'PORT (iface-id)':<38} {'TAP':<10} CHASSIS")
        problems = 0
        for vm in self.vms:
            tap = ovn.iface_for_iface_id(ctx, vm.uuid)
            chassis = ovn.port_binding_chassis(ctx, vm.uuid)
            if chassis:
                state = f"bound @{chassis_names.get(chassis, chassis[:12])}"
            elif not tap:
                state = "no tap -- VM not running"
            else:
                state = "UNBOUND -- tap present, not claimed"
                problems += 1
            print(f"{vm.name:<10} {vm.uuid:<38} {tap or '-':<10} {state}")
        if problems:
            print("")
            print(f"{problems} running VM(s) are not bound. Re-run "
                  "`ovnctl vm-attach`, then `ovnctl diagnose`.")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-attach")
    ctx.require_cfg("topology:br_int")
    ctx.require_root()

    cmd = VMAttach(ctx, timeout=getattr(args, "timeout", DEFAULT_TIMEOUT),
                   watch_memory=getattr(args, "watch_memory", False),
                   nudge=getattr(args, "nudge", True))

    if args.status:
        cmd.print_status()
        return 0

    # No libvirt CLI on this host means there are no taps for us to re-plug
    # -- that is a no-op, not a deployment failure. Exiting non-zero here
    # would break the chain in `ovnctl deploy`.
    if not libvirtutil.available(ctx) and not ctx.listing:
        ctx.warn("virsh not found -- nothing to re-attach, skipping.")
        return 0
    ctx.require_cmd("ovs-vsctl")

    runner = StepRunner(ctx, "vm-attach")
    runner.add("check-bridge", "verify br-int exists", cmd.check_bridge)
    runner.add("attach", "re-attach every running VM's tap", cmd.attach)
    runner.add("wait", "wait for ovn-controller to claim the ports",
               cmd.wait_for_bindings)
    runner.add("status", "print the resulting port binding table",
               cmd.print_status)

    if not runner.run(args):
        return 0
    return 0