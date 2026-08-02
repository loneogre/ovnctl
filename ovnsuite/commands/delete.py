"""
ovnctl delete -- port of ovndelete.sh

Reverses the OVN/OVS config so you can start from scratch. Everything is
DISCOVERED dynamically rather than matched against hardcoded names, so this
works regardless of what names were used to create the
switches/routers/ports/bridges.

  - removes any host-facing internal interface on br-int (routes,
    addresses, link state) and its OVS port
  - removes ANY other OVS bridge along with whatever physical NIC is
    plugged into it, and re-manages that NIC in NetworkManager
  - removes ALL logical routers, switches, port groups, load balancers and
    meters in the NB db
  - stops ovn-controller and removes the Chassis / Chassis_Private rows
  - clears the OVS external-ids
  - removes br-int itself

--purge-db goes further: it also wipes the raw NB/SB database files. That
is belt-and-braces on top of the object-level wipe above, which already
removes everything logically.
"""

from __future__ import annotations

import argparse
import re
import time
from pathlib import Path

from .. import libvirtutil, ovn, paths
from ..context import Ctx
from ..state import Tracker
from ..steps import StepRunner, add_step_args

NAME = "delete"
HELP = "tear down everything this deployment created"

# br-int is OVN's own integration bridge and gets special handling -- it is
# not an uplink bridge to remove outright. Everything else is discovered.
DEFAULT_BR_INT = "br-int"


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, aliases=["teardown"],
                              description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--purge-db", action="store_true",
                   help="also wipe the raw NB/SB database files")
    p.add_argument("--keep-br-int", action="store_true",
                   help="leave br-int in place")
    p.add_argument("--forget-user-vms", action="store_true",
                   help="also discard the user-VM slot allocations "
                        "(state/user-vms.json). Without this they are kept, "
                        "and `ovnctl deploy` rebuilds those slots with the "
                        "same UUIDs and MACs")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class Teardown:
    def __init__(self, ctx: Ctx, purge_db: bool, keep_br_int: bool,
                 forget_user_vms: bool = False):
        self.ctx = ctx
        self.purge_db = purge_db
        self.keep_br_int = keep_br_int
        self.forget_user_vms = forget_user_vms
        self.br_int = ctx.config.cfg_opt("topology", "br_int", DEFAULT_BR_INT)

    # ------------------------------------------------------------------
    def report(self, label: str, detail: str) -> None:
        """One line per step, always shown.

        A teardown is destructive: the operator needs to see what was
        removed even on a quiet run. Per-item detail stays behind -v.
        """
        if not self.ctx.dry_run:
            print(f"[{self.ctx.prefix}] {label:<22} {detail}")

    def _internal_ports(self) -> list[str]:
        """Internal-type ports on br-int that are not br-int's own local port."""
        ctx = self.ctx
        out = []
        for port in ovn.list_ports(ctx, self.br_int):
            if port == self.br_int:
                continue
            if ovn.iface_type(ctx, port) == "internal":
                out.append(port)
        return out

    # -- 1 ---------------------------------------------------------------
    def host_networking(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Host networking")
        ctx.log(f"Discovering host-facing internal interfaces on {self.br_int}...")
        ifaces = self._internal_ports()
        if not ifaces:
            self.report("Host networking:", f"nothing attached to {self.br_int}")
            return

        flushed = 0
        for iface in ifaces:
            ctx.log(f"Cleaning up kernel networking for {iface}...")
            if ctx.q("ip", "link", "show", iface).ok:
                ctx.run("ip", "route", "flush", "dev", iface)
                ctx.run("ip", "addr", "flush", "dev", iface)
                ctx.run("ip", "link", "set", iface, "down")
                ctx.log(f"Flushed routes/addresses and set {iface} down.")
                flushed += 1
            else:
                ctx.log(f"{iface} has no kernel link, skipping ip cleanup.")
        self.report("Host networking:", f"{flushed} interface(s) flushed")

    # -- 2 ---------------------------------------------------------------
    def ovs_ports(self) -> None:
        ctx = self.ctx
        ctx.dr_head("OVS ports on br-int")
        ctx.log(f"Discovering and removing host-facing OVS ports on "
                f"{self.br_int}...")
        ifaces = self._internal_ports()
        if not ifaces:
            self.report("OVS ports:", "none to remove")
            return

        removed = 0
        for iface in ifaces:
            if ctx.run("ovs-vsctl", "--if-exists", "del-port", self.br_int, iface):
                ctx.log(f"Removed OVS port {iface}")
                removed += 1
            else:
                ctx.warn(f"Failed to remove OVS port {iface}")
        self.report("OVS ports:", f"{removed} removed")

    # -- 3 ---------------------------------------------------------------
    def uplink_bridges(self) -> None:
        """Remove any OVS bridge besides br-int.

        These are uplink bridges created to bridge OVN out to a physical
        NIC. Discovered dynamically, not hardcoded, so this catches any such
        bridge regardless of name.
        """
        ctx = self.ctx
        ctx.dr_head("Uplink bridges and their NICs")
        ctx.log(f"Discovering uplink bridges (any OVS bridge besides "
                f"{self.br_int})...")
        bridges = [b for b in ovn.list_br(ctx) if b != self.br_int]
        if not bridges:
            self.report("Uplink bridges:", "none found")
            return

        names: list[str] = []
        for bridge in bridges:
            ctx.log(f"Cleaning up bridge {bridge}...")
            for port in ovn.list_ports(ctx, bridge):
                if port == bridge:
                    continue
                ptype = ovn.iface_type(ctx, port)
                if ctx.run("ovs-vsctl", "--if-exists", "del-port", bridge, port):
                    ctx.log(f"  removed port {port} (type={ptype or 'system'}) "
                            f"from {bridge}")
                else:
                    ctx.warn(f"  failed to remove port {port} from {bridge}")
                # A "system" type port is a physical NIC -- hand it back to
                # NetworkManager so it is usable for normal host networking.
                if ptype != "internal" and ctx.have("nmcli"):
                    if ctx.run("nmcli", "device", "set", port, "managed", "yes"):
                        ctx.log(f"  returned {port} to NetworkManager management.")

            if ctx.run("ovs-vsctl", "--if-exists", "del-br", bridge):
                ctx.log(f"Removed bridge {bridge}.")
                names.append(bridge)
            else:
                ctx.warn(f"Failed to remove bridge {bridge}.")
        self.report("Uplink bridges:", f"removed: {' '.join(names)}")

    # -- 4 ---------------------------------------------------------------
    def logical_config(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Logical routers and switches")

        def names_from(listing: str) -> list[str]:
            # `lr-list` / `ls-list` print "<uuid> (<name>)".
            return [m.group(1) for m in re.finditer(r"\(([^)]+)\)", listing)]

        ctx.log("Discovering and removing all logical routers...")
        routers = names_from(ctx.qout("ovn-nbctl", "lr-list"))
        removed_r = 0
        for router in routers:
            if ctx.run("ovn-nbctl", "--if-exists", "lr-del", router):
                ctx.log(f"Removed router {router}")
                removed_r += 1
            else:
                ctx.warn(f"Failed to remove router {router}")

        ctx.log("Discovering and removing all logical switches...")
        switches = names_from(ctx.qout("ovn-nbctl", "ls-list"))
        removed_s = 0
        for switch in switches:
            if ctx.run("ovn-nbctl", "--if-exists", "ls-del", switch):
                ctx.log(f"Removed switch {switch}")
                removed_s += 1
            else:
                ctx.warn(f"Failed to remove switch {switch}")

        self.report("Logical routers:", f"{removed_r} removed")
        self.report("Logical switches:", f"{removed_s} removed")

    # -- 5 ---------------------------------------------------------------
    def port_groups(self) -> None:
        """pg-del also garbage-collects ACLs referenced only via that group."""
        ctx = self.ctx
        ctx.dr_head("Port groups")
        ctx.log("Discovering and removing all port groups...")
        groups = ctx.q("ovn-nbctl", "--bare", "--columns=name", "list",
                       "Port_Group").lines
        if not groups:
            self.report("Port groups:", "none found")
            return
        removed = 0
        for group in groups:
            if ctx.run("ovn-nbctl", "pg-del", group):
                ctx.log(f"Removed port group {group} (and its ACLs).")
                removed += 1
            else:
                ctx.warn(f"Failed to remove port group {group}.")
        self.report("Port groups:", f"{removed} removed (with their ACLs)")
        self._address_sets()

    def _address_sets(self) -> None:
        """Address sets outlive the policies that referenced them.

        Nothing else removes them, and a stale set with the old internal
        ranges in it would be silently reused by the next deployment --
        widening or narrowing the ASA bypass without anything in the
        settings file saying so.
        """
        ctx = self.ctx
        sets = ctx.q("ovn-nbctl", "--bare", "--columns=_uuid", "list",
                     "Address_Set").lines
        if not sets:
            self.report("Address sets:", "none found")
            return
        removed = 0
        for uuid in sets:
            if ctx.run("ovn-nbctl", "--if-exists", "destroy", "Address_Set",
                       uuid):
                removed += 1
        self.report("Address sets:", f"{removed} removed")

    # -- 6 ---------------------------------------------------------------
    def lb_and_meters(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Load balancers and meters")
        ctx.log("Discovering and removing load balancers...")
        lbs = ctx.q("ovn-nbctl", "--bare", "--columns=name", "list",
                    "Load_Balancer").lines
        n_lb = 0
        for lb in lbs:
            if ctx.run("ovn-nbctl", "--if-exists", "lb-del", lb):
                ctx.log(f"Removed load balancer {lb}.")
                n_lb += 1
            else:
                ctx.warn(f"Failed to remove load balancer {lb}.")

        ctx.log("Discovering and removing meters...")
        meters = ctx.q("ovn-nbctl", "--bare", "--columns=_uuid", "list",
                       "Meter").lines
        n_mt = 0
        for uuid in meters:
            if ctx.run("ovn-nbctl", "--if-exists", "destroy", "Meter", uuid):
                ctx.log(f"Removed meter {uuid}.")
                n_mt += 1
            else:
                ctx.warn(f"Failed to remove meter {uuid}.")
        self.report("Load balancers/meters:", f"{n_lb} / {n_mt} removed")

    # -- 6a --------------------------------------------------------------
    def stop_pcap(self) -> None:
        """Stop captures first: mirrors reference ports on br-int, and leaving
        tcpdump attached to a capture port that is about to be deleted leaves
        orphan processes."""
        ctx = self.ctx
        ctx.dr_head("Packet captures and mirrors")
        ctx.log("Stopping any running packet captures...")
        try:
            from . import pcap as pcap_cmd
            sub = Ctx(prefix="ovn-pcap", verbose=ctx.verbose,
                      dry_run=ctx.dry_run)
            sub._config = ctx.config
            capture = pcap_cmd.Pcap(sub)
            capture.build_virsh_map()
            capture.do_stop()
        except Exception as exc:  # a teardown must keep going regardless
            ctx.log(f"(pcap stop skipped: {exc})")

    # -- 6b --------------------------------------------------------------
    def stop_controller(self) -> None:
        self.ctx.dr_head("ovn-controller")
        self.ctx.log("Stopping ovn-controller before chassis removal...")
        self.stop_controller_hard()

    def stop_controller_hard(self) -> bool:
        """Stop ovn-controller by every available means, and confirm it.

        This matters twice over: a running controller re-registers its
        Chassis row as fast as it is deleted, AND it recreates br-int within
        milliseconds of removal -- which is why a teardown can appear to
        leave br-int behind.
        """
        ctx = self.ctx
        if ctx.dry_run:
            ctx.run("systemctl", "stop", "ovn-controller")
            return True
        if not ctx.q("pgrep", "-x", "ovn-controller").ok:
            ctx.log("ovn-controller is not running.")
            return True

        if ctx.have("systemctl"):
            for unit in ("ovn-controller", "ovn_controller"):
                if ctx.run("systemctl", "stop", unit):
                    break
        time.sleep(1)
        if not ctx.q("pgrep", "-x", "ovn-controller").ok:
            ctx.log("Stopped ovn-controller (systemd).")
            return True

        # Then the OVN helper, which is how it is started when there is no unit.
        if ctx.have("ovn-ctl"):
            ctx.run("ovn-ctl", "stop_controller")
            time.sleep(1)
            if not ctx.q("pgrep", "-x", "ovn-controller").ok:
                ctx.log("Stopped ovn-controller (ovn-ctl).")
                return True

        # Last resort. Without this the rest of the teardown silently fails.
        ctx.warn("ovn-controller did not stop via systemd or ovn-ctl -- "
                 "signalling it directly.")
        ctx.run("pkill", "-x", "ovn-controller")
        for _ in range(5):
            if not ctx.q("pgrep", "-x", "ovn-controller").ok:
                ctx.log("Stopped ovn-controller.")
                return True
            time.sleep(1)

        ctx.run("pkill", "-9", "-x", "ovn-controller")
        time.sleep(1)
        if ctx.q("pgrep", "-x", "ovn-controller").ok:
            pids = ctx.qout("pgrep", "-x", "ovn-controller").replace("\n", " ")
            ctx.warn(f"ovn-controller is STILL running (pid {pids}).")
            ctx.warn("It will recreate br-int and re-register its chassis. Stop it")
            ctx.warn("manually and re-run, or the teardown cannot complete.")
            return False
        ctx.log("Stopped ovn-controller (forced).")
        return True

    # -- 6c --------------------------------------------------------------
    def remove_chassis(self) -> None:
        """Remove the Chassis and Chassis_Private rows.

        Leaving these behind is what makes a redeploy look healthy while
        nothing binds: northd repopulates Port_Bindings, the stale chassis
        makes everything look registered, gateway pins resolve against a
        dead name, and no live controller ever claims a port. Symptom is
        'cr-lrp-* unbound' plus every VIF 'DOWN (no chassis)'.
        """
        ctx = self.ctx
        ctx.dr_head("Chassis / Chassis_Private")
        ctx.log("Removing Chassis / Chassis_Private rows from the Southbound db...")
        if not ctx.have("ovn-sbctl"):
            ctx.warn("ovn-sbctl not found -- cannot clean up chassis rows.")
            return

        names = ovn.chassis_names(ctx)
        if names:
            for name in names:
                if ctx.run("ovn-sbctl", "--if-exists", "chassis-del", name):
                    ctx.log(f"Removed chassis '{name}'.")
                else:
                    ctx.warn(f"chassis-del failed for '{name}', will try by UUID.")
        else:
            ctx.log("No chassis rows found.")

        # Fallback: names containing characters chassis-del won't take, or
        # rows that survived the delete for any other reason.
        for table in ("Chassis", "Chassis_Private"):
            uuids = ctx.q("ovn-sbctl", "--bare", "--columns=_uuid", "list",
                          table).lines
            for uuid in uuids:
                if ctx.run("ovn-sbctl", "destroy", table, uuid):
                    ctx.log(f"Destroyed leftover {table} {uuid}.")
                else:
                    ctx.warn(f"Could not destroy {table} {uuid}.")

        remaining = len(ovn.chassis_names(ctx))
        if remaining > 0:
            ctx.warn(f"{remaining} chassis row(s) STILL present after deletion.")
            ctx.warn("This means something re-registered them -- confirm "
                     "ovn-controller")
            ctx.warn("is stopped (pgrep -x ovn-controller) and re-run.")
        else:
            self.report("Chassis:", "removed, SB tables clean")

    # -- 7 ---------------------------------------------------------------
    def clear_external_ids(self) -> None:
        ctx = self.ctx
        ctx.dr_head("OVS external-ids")
        ctx.log("Clearing OVS external-ids (ovn-remote, ovn-encap-*, system-id, "
                "ovn-bridge-mappings)...")
        for key in ("ovn-remote", "ovn-encap-type", "ovn-encap-ip", "system-id",
                    "ovn-bridge-mappings"):
            ctx.run("ovs-vsctl", "remove", "open", ".", "external-ids", key)
        self.report("OVS external-ids:", "cleared")

    # -- 9 ---------------------------------------------------------------
    def purge_databases(self) -> None:
        """(--purge-db) Wipe the raw NB/SB database files.

        Runs BEFORE br-int is removed: it restarts services, and a restarted
        ovn-controller would recreate the bridge immediately after deletion.
        """
        ctx = self.ctx
        if not self.purge_db:
            return
        ctx.dr_head("NB/SB database files")
        ctx.log("PURGE requested: also wiping raw NB/SB database files...")
        ctx.log("(Note: the steps above already removed everything logically --")
        ctx.log("this is an extra, not a requirement for a clean state.)")

        services = ("ovn-controller", "ovn-northd", "ovn-ovsdb-server-nb",
                    "ovn-ovsdb-server-sb")
        if ctx.have("systemctl"):
            for svc in services:
                if ctx.unit_exists(svc):
                    ctx.run("systemctl", "stop", svc)

        # First, find the actual db file paths from the running ovsdb-server
        # process(es) -- far more reliable than guessing static paths that
        # vary by distro/version.
        found = False
        ps = ctx.qout("ps", "aux")
        proc_paths = set()
        for line in ps.splitlines():
            if "ovsdb-server" not in line:
                continue
            for m in re.finditer(r"(/\S*ovn[a-z]*_db\.db)", line):
                proc_paths.add(m.group(1))

        for p in sorted(proc_paths):
            if Path(p).is_file():
                found = True
                ctx.log(f"Removing {p} (found via running process)")
                ctx.run("rm", "-f", p)

        if not found:
            ctx.log("No db paths found via running processes, searching "
                    "filesystem...")
            search = ctx.q("find", "/etc", "/var/lib", "/usr/etc", "-xdev",
                           "-maxdepth", "6", "-iname", "ovn?b_db.db")
            for p in search.lines:
                found = True
                ctx.log(f"Removing {p} (found via filesystem search)")
                ctx.run("rm", "-f", p)

        if not found:
            ctx.warn("Could not find NB/SB db files anywhere. This is NOT fatal --")
            ctx.warn("the earlier steps already wiped everything at the object "
                     "level. If")
            ctx.warn("you specifically need the db files regenerated, locate them")
            ctx.warn("with: find / -xdev -iname 'ovn?b_db.db' 2>/dev/null")

        # Deliberately NOT restarting ovn-controller: it would recreate
        # br-int before the next step gets to remove it. `ovnctl setup`
        # starts it again on the next deployment.
        if ctx.have("systemctl"):
            for svc in ("ovn-ovsdb-server-nb", "ovn-ovsdb-server-sb",
                        "ovn-northd"):
                if ctx.unit_exists(svc):
                    ctx.log(f"Restarting {svc}...")
                    if not ctx.run("systemctl", "restart", svc):
                        ctx.warn(f"Failed to restart {svc}")
            ctx.log("ovn-controller left STOPPED on purpose (it owns br-int).")
        else:
            ctx.warn("systemctl not found; restart OVN services manually "
                     "(e.g. via ovn-ctl).")

        self.report("Databases:", "NB/SB files purged")

    # -- 8 ---------------------------------------------------------------
    def remove_br_int(self) -> None:
        ctx = self.ctx
        ctx.dr_head("br-int")

        # Deleting br-int detaches every running VM's tap. libvirt only plugs
        # a tap in at domain start, so those VMs stay disconnected until they
        # are restarted -- which is why a redeploy can need a reboot.
        if libvirtutil.available(ctx):
            running = len(libvirtutil.running_domains(ctx))
            taps = len([p for p in ovn.list_ports(ctx, self.br_int)
                        if p.startswith("vnet")])
            if running > 0 and taps > 0:
                ctx.warn(f"{running} VM(s) are running with {taps} tap(s) on "
                         f"{self.br_int}.")
                ctx.warn(f"Removing {self.br_int} detaches them and libvirt will "
                         "NOT re-plug")
                ctx.warn("them automatically -- those VMs stay off the network "
                         "until they")
                ctx.warn("are restarted (or the taps are re-added with "
                         "`ovnctl vm-attach`).")

        if self.keep_br_int:
            self.report(f"{self.br_int}:", "kept (--keep-br-int)")
            return

        # Anything that restarted the controller (including the db purge) can
        # have brought it back, so make sure it is down immediately before
        # the bridge is deleted.
        if not self.stop_controller_hard():
            ctx.warn(f"Proceeding, but {self.br_int} will likely reappear.")

        if ovn.br_exists(ctx, self.br_int):
            if ctx.run("ovs-vsctl", "--if-exists", "del-br", self.br_int):
                ctx.log(f"Removed bridge {self.br_int}.")
            else:
                ctx.warn(f"Failed to remove bridge {self.br_int}.")
        else:
            ctx.log(f"{self.br_int} does not exist, skipping.")

        # Verify it stayed removed. A bridge that reappears is the clearest
        # sign the controller is still alive. Meaningless in a dry-run.
        if ctx.dry_run:
            return
        time.sleep(1)
        if ovn.br_exists(ctx, self.br_int):
            ctx.warn(f"{self.br_int} came BACK after deletion.")
            if ctx.q("pgrep", "-x", "ovn-controller").ok:
                pids = ctx.qout("pgrep", "-x", "ovn-controller").replace("\n", " ")
                ctx.warn(f"ovn-controller is running (pid {pids}) and recreated it.")
                ctx.warn("Stop it and delete the bridge by hand:")
                ctx.warn("  systemctl stop ovn-controller ; pkill -x ovn-controller")
                ctx.warn(f"  ovs-vsctl --if-exists del-br {self.br_int}")
            else:
                ctx.warn("ovn-controller is NOT running, so something else "
                         "recreated it.")
                ctx.warn("Check: ovs-vsctl show ; systemctl status openvswitch")
        else:
            self.report(f"{self.br_int}:", "removed and verified gone")

        ctx.log(f"Note: {self.br_int} will be recreated automatically the next "
                "time ovn-controller starts")
        ctx.log("(e.g. when you rerun `ovnctl setup`). ovs-system is left alone -- "
                "it's a")
        ctx.log("kernel datapath interface owned by the openvswitch module.")

    # -- 8b --------------------------------------------------------------
    def verify_clean(self) -> None:
        """Confirm the Southbound db is actually empty.

        If a chassis or port binding survived, a redeploy will look healthy
        but bind nothing.
        """
        ctx = self.ctx
        ctx.log("Verifying Southbound db is clean...")
        if not ctx.have("ovn-sbctl"):
            return

        chassis = len(ovn.chassis_names(ctx))
        bindings = len(ovn.port_binding_ports(ctx))
        if chassis == 0 and bindings == 0:
            ctx.log("Southbound db is clean (0 chassis, 0 port bindings).")
            return

        ctx.warn(f"Southbound db is NOT clean: {chassis} chassis, "
                 f"{bindings} port binding(s).")
        ctx.warn("A redeploy on top of this will look correct in ovn-nbctl but "
                 "nothing")
        ctx.warn("will bind -- cr-lrp-* unbound, every VIF 'DOWN (no chassis)'.")
        ctx.warn("Fix before redeploying:")
        ctx.warn("  systemctl stop ovn-controller")
        ctx.warn("  ovn-sbctl --bare --columns=_uuid list Chassis "
                 "| xargs -r -n1 ovn-sbctl destroy Chassis")
        ctx.warn("  ovn-sbctl --bare --columns=_uuid list Chassis_Private "
                 "| xargs -r -n1 ovn-sbctl destroy Chassis_Private")
        ctx.warn("Or re-run with --purge-db to wipe the db files outright.")

    # ------------------------------------------------------------------
    def clear_tracker(self) -> None:
        Tracker(self.ctx).clear()
        self.report("Deployment tracker:", "erased")
        self._user_vm_allocations()

    def _user_vm_allocations(self) -> None:
        """Report -- and optionally discard -- the user-VM slot records.

        They are KEPT by default, and deliberately: an operator's libvirt
        domain references a slot's UUID and MAC by value, so discarding
        the record would orphan somebody else's VM. `deploy` rebuilds the
        slots from it with the same identities, which is the whole point
        of the file surviving a purge.

        But it is surprising if nobody says so -- a teardown that reports
        everything else as removed, followed by a deploy that recreates
        ten ports out of apparently nowhere, reads as a bug.
        """
        import json

        ctx = self.ctx
        path = paths.state_dir() / "user-vms.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.report("User-VM allocations:", "none recorded")
            return
        count = len(data.get("slots") or {})
        if not count:
            self.report("User-VM allocations:", "none recorded")
            return

        if not self.forget_user_vms:
            self.report("User-VM allocations:",
                        f"{count} slot(s) KEPT ({path.name})")
            ctx.log("  Their UUIDs and MACs are referenced by libvirt domains, "
                    "so they")
            ctx.log("  survive a teardown. `ovnctl deploy` rebuilds them "
                    "identically.")
            ctx.log("  Use --forget-user-vms to discard them instead.")
            return

        if ctx.dry_run:
            print(f"rm -f {path}")
        else:
            try:
                path.unlink()
            except OSError as exc:
                ctx.warn(f"Could not remove {path}: {exc}")
                return
            ctx.changes += 1
        self.report("User-VM allocations:", f"{count} slot(s) DISCARDED")
        ctx.warn("Any libvirt domain still pointing at those interface UUIDs "
                 "now references a port that will never exist. Re-create the "
                 "slots and update the domain XML.")

    def final_show(self) -> None:
        ctx = self.ctx
        if ctx.verbose and not ctx.dry_run:
            print("")
            print("--- ovs-vsctl show ---")
            print(ctx.qout("ovs-vsctl", "show"))
            print("--- ovn-nbctl show ---")
            print(ctx.qout("ovn-nbctl", "show"))


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-teardown")
    ctx.require_root()

    t = Teardown(ctx, args.purge_db, args.keep_br_int,
                 getattr(args, "forget_user_vms", False))
    runner = StepRunner(ctx, "delete")
    runner.add("host-networking", "flush addresses/routes on br-int internal ports",
               t.host_networking)
    runner.add("ovs-ports", "remove those OVS ports", t.ovs_ports)
    runner.add("uplink-bridges", "remove every other OVS bridge and free its NIC",
               t.uplink_bridges)
    runner.add("logical-config", "remove all logical routers and switches",
               t.logical_config)
    runner.add("port-groups", "remove all port groups and their ACLs",
               t.port_groups)
    runner.add("lb-meters", "remove load balancers and meters", t.lb_and_meters)
    runner.add("stop-pcap", "stop captures and remove mirrors", t.stop_pcap)
    runner.add("stop-controller", "stop ovn-controller", t.stop_controller)
    runner.add("chassis", "remove Chassis / Chassis_Private rows", t.remove_chassis)
    runner.add("external-ids", "clear the OVS external-ids", t.clear_external_ids)
    # The db purge restarts services, so it has to happen BEFORE br-int is
    # removed -- otherwise a restarted ovn-controller recreates the bridge
    # immediately after we delete it.
    runner.add("purge-db", "(--purge-db only) wipe the raw NB/SB db files",
               t.purge_databases)
    runner.add("br-int", "remove br-int and verify it stays gone", t.remove_br_int)
    runner.add("verify-clean", "confirm the SB db is empty", t.verify_clean)
    runner.add("tracker", "erase the deployment tracker", t.clear_tracker)
    runner.add("show", "(-v) dump ovs-vsctl / ovn-nbctl show", t.final_show)

    if not runner.run(args):
        return 0

    if args.purge_db:
        ctx.finish("teardown complete (databases purged)")
    else:
        ctx.finish("teardown complete")
    return 0