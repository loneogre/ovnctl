"""
ovnctl setup -- port of ovn-setup.sh

Sets up a single-node OVN environment:
  - configures OVS external-ids (if not already set)
  - starts ovn-controller and waits for br-int
  - creates the logical switches (ls-int-vm, ls-ext-vm, ls-host)
  - creates the logical router (lr-core) with a port on each segment
  - attaches the switches to the router
  - creates a host-facing OVN interface for the host itself
"""

from __future__ import annotations

import argparse
import time

from .. import identity, ovn
from ..context import Abort, Ctx
from ..state import SETUP, record
from ..steps import StepRunner, add_step_args

NAME = "setup"
HELP = "base topology, host segment, logical router"

REQUIRED_CFG = (
    "setup:host_if_ip", "setup:host_if_mac", "setup:host_if_prefix",
    "setup:lrp_ext", "setup:lrp_ext_cidr", "setup:lrp_ext_mac",
    "setup:lrp_host", "setup:lrp_host_cidr", "setup:lrp_host_mac",
    "setup:lrp_int", "setup:lrp_int_cidr", "setup:lrp_int_mac",
    "setup:ovn_encap_ip", "setup:ovn_encap_type", "setup:ovn_remote",
    "setup:system_id",
    "topology:br_int", "topology:host_if", "topology:lr_core",
    "topology:ls_ext", "topology:ls_host", "topology:ls_int",
)


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class Setup:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        # Set by external_ids() when it had to rewrite system-id, so later
        # steps (and `ovnctl reconcile`) know the chassis has just been
        # re-registered under a different name.
        self.identity_changed = False

        self.ovn_remote = c.cfg("setup", "ovn_remote")
        self.encap_type = c.cfg("setup", "ovn_encap_type")
        self.encap_ip = c.cfg("setup", "ovn_encap_ip")

        # REQUIRED, and deliberately so. There used to be a fallback to
        # socket.gethostname() here; a hostname that changes between boots
        # (localhost vs localhost.localdomain, a DHCP-supplied name, a
        # rename) renames the chassis, and every Port_Binding and gateway
        # pin then references an identity nothing is running under.
        # identity.configured() aborts with instructions if it is unset.
        self.system_id = identity.configured(ctx)

        self.ls_int = c.cfg("topology", "ls_int")
        self.ls_ext = c.cfg("topology", "ls_ext")
        self.ls_host = c.cfg("topology", "ls_host")
        self.lr_core = c.cfg("topology", "lr_core")
        self.br_int = c.cfg("topology", "br_int")

        self.lrp_int = c.cfg("setup", "lrp_int")
        self.lrp_int_mac = c.cfg("setup", "lrp_int_mac")
        self.lrp_int_cidr = c.cfg("setup", "lrp_int_cidr")

        self.lrp_ext = c.cfg("setup", "lrp_ext")
        self.lrp_ext_mac = c.cfg("setup", "lrp_ext_mac")
        self.lrp_ext_cidr = c.cfg("setup", "lrp_ext_cidr")

        self.lrp_host = c.cfg("setup", "lrp_host")
        self.lrp_host_mac = c.cfg("setup", "lrp_host_mac")
        self.lrp_host_cidr = c.cfg("setup", "lrp_host_cidr")
        self.host_gw = self.lrp_host_cidr.split("/")[0]

        # host-if sits on its own /30, not on the VM subnet, so the
        # workstation LAN can be routed to it without putting laptops on a
        # VM segment.
        self.host_if = c.cfg("topology", "host_if")
        self.host_if_mac = c.cfg("setup", "host_if_mac")
        self.host_if_ip = c.cfg("setup", "host_if_ip")
        self.host_if_cidr = f"{self.host_if_ip}/{c.cfg('setup', 'host_if_prefix')}"

        # Everything the host needs to reach through the router. The legacy
        # single-route fields are still honoured if host_routes is absent.
        routes = c.cfg_array("setup", "host_routes")
        self.host_routes = routes if routes else [c.cfg("setup", "remote_subnet")]

        # Only consulted when writing the NetworkManager profile; the
        # `ip route` path leaves the metric to the kernel, as it always has.
        self.host_route_metric = c.cfg_opt("setup", "host_route_metric")

    # -- 1 ---------------------------------------------------------------
    def external_ids(self) -> None:
        """Reconcile external-ids -- every key, every run.

        This step used to return early if ovn-remote was already present.
        conf.db is persistent, so from the second deploy onwards that gate
        was always true and system-id was never re-asserted again, while
        `ovs-ctl start --system-id=random` rewrote it at every boot. The
        deployment then looked healthy and bound nothing.
        """
        ctx = self.ctx
        ctx.dr_head("OVS external-ids")
        ctx.log("Reconciling OVS external-ids...")

        # Captured BEFORE the write, because "was it unset" and "was it a
        # different value" call for opposite responses below.
        previous_id = identity.local(ctx)

        id_changed = identity.assert_external_ids(
            ctx, self.system_id, self.ovn_remote, self.encap_type,
            self.encap_ip)

        if not id_changed:
            return

        self.identity_changed = True

        # DO NOT restart first. ovn-controller usually notices a system-id
        # change on its own and re-registers within a few seconds, and a
        # restart here is expensive in a way that is easy to miss: it lands
        # in the middle of a deploy, `ovn-ctl stop` regularly fails to exit
        # cleanly and gets SIGKILLed, and the replacement process then has
        # to rebuild its entire view -- several hundred thousand flows on
        # this deployment. During that rebuild it claims nothing, so
        # vm-attach a few stages later finds running VMs unbound and blames
        # the controller.
        #
        # This path is hit on every deploy after `delete --purge-db`,
        # because teardown clears external-ids and so system-id always
        # "changes". Restarting unconditionally there turned a working
        # deploy into one that needed a second vm-attach run.
        # How long to give it before resorting to a restart depends on
        # what it was doing beforehand:
        #
        #   previously SET to something else -- the controller is running
        #     and registered under the old name. It usually notices the
        #     change and re-registers on its own, so wait properly.
        #
        #   previously UNSET -- which is the state `delete --purge-db`
        #     leaves behind, since teardown clears external-ids. A
        #     controller with no system-id has no identity to register
        #     under and is doing nothing at all. Waiting 20s for it is 20s
        #     of guaranteed delay on every post-teardown deploy, and then
        #     restarting anyway.
        patience = 20 if previous_id else 3
        if identity.wait_for_chassis(ctx, self.system_id, timeout=patience):
            ctx.log(f"ovn-controller registered as '{self.system_id}' without "
                    "a restart.")
            return

        if not (ctx.q("pgrep", "-x", "ovn-controller").ok or ctx.dry_run):
            ctx.log("ovn-controller is not running -- nothing to restart.")
            return

        if previous_id:
            ctx.warn(f"ovn-controller did not register as '{self.system_id}' "
                     f"within {patience}s of the change -- restarting it.")
        else:
            ctx.log("external-ids had no system-id (the state a teardown "
                    "leaves), so the")
            ctx.log("controller had no identity to register under. "
                    "Restarting it.")
        identity.restart_controller(ctx, "system-id changed")
        if not identity.wait_for_chassis(ctx, self.system_id, timeout=60):
            ctx.warn(f"ovn-controller has not registered as "
                     f"'{self.system_id}' yet -- later steps that need a "
                     "chassis may fail; re-run if so.")

        leftovers = identity.stale(ctx, self.system_id)
        if leftovers:
            ctx.warn(f"Chassis row(s) under the previous identity remain: "
                     f"{', '.join(leftovers)}")
            ctx.warn("Port bindings and gateway pins referencing them will "
                     "never bind.")
            ctx.warn("Clear them with: ovnctl reconcile --repair-identity")

    # -- 1b --------------------------------------------------------------
    def ovn_controller(self) -> None:
        """Make sure ovn-controller is running and br-int has been created.

        br-int is auto-created by ovn-controller once it connects to the SB
        db using the external-ids set above -- if it is missing,
        ovn-controller is either not running or not connected.
        """
        ctx = self.ctx
        ctx.dr_head("ovn-controller / br-int")
        ctx.log("Checking for br-int / ovn-controller...")

        if ovn.br_exists(ctx, self.br_int):
            ctx.log("br-int already exists.")
            return

        ctx.log("br-int not found -- starting the OVN control plane.")

        # openvswitch must be up first; ovn-controller cannot create br-int
        # without it.
        if ctx.have("systemctl"):
            for unit in ("openvswitch", "ovs-vswitchd"):
                if ctx.unit_exists(unit):
                    if not ctx.unit_active(unit):
                        ctx.log(f"Starting {unit}...")
                        if not ctx.run("systemctl", "start", unit):
                            ctx.warn(f"Failed to start {unit}.")
                    break

        # The Southbound db must be reachable, or ovn-controller starts and
        # then sits retrying forever.
        sb_sock = self.ovn_remote[len("unix:"):] if self.ovn_remote.startswith("unix:") else ""
        if sb_sock:
            from pathlib import Path
            import stat as _stat
            sock = Path(sb_sock)
            exists = sock.exists() and _stat.S_ISSOCK(sock.stat().st_mode)
            if not exists:
                ctx.warn(f"SB socket {sb_sock} does not exist -- the OVN central services")
                ctx.warn("are not running. Starting ovn-northd...")
                if ctx.have("systemctl"):
                    for unit in ("ovn-northd", "ovn-ovsdb-server-nb",
                                 "ovn-ovsdb-server-sb"):
                        if ctx.unit_exists(unit):
                            ctx.run("systemctl", "start", unit)
                elif ctx.have("ovn-ctl"):
                    ctx.run("ovn-ctl", "start_northd")
                if not ctx.dry_run:
                    time.sleep(2)

        started = False
        if ctx.have("systemctl") and ctx.unit_exists("ovn-controller"):
            if ctx.unit_active("ovn-controller"):
                ctx.log("ovn-controller service is already active.")
                started = True
            else:
                # reset-failed first, so a unit left 'failed' by a previous
                # teardown can start again.
                ctx.run("systemctl", "reset-failed", "ovn-controller")
                ctx.log("Starting ovn-controller service...")
                if ctx.run("systemctl", "enable", "--now", "ovn-controller"):
                    started = True
                elif ctx.run("systemctl", "start", "ovn-controller"):
                    started = True
                else:
                    ctx.warn("systemctl could not start ovn-controller.")

        if not started and ctx.have("ovn-ctl"):
            ctx.log("Falling back to ovn-ctl start_controller...")
            if ctx.run("ovn-ctl", "start_controller"):
                started = True

        if not started:
            ctx.warn("Could not start ovn-controller by any method.")

        if ctx.dry_run:
            return

        ctx.log("Waiting for br-int (up to 30s)...")
        for _ in range(30):
            if ovn.br_exists(ctx, self.br_int):
                ctx.log("br-int is up.")
                return
            time.sleep(1)

        self._br_int_diagnosis(sb_sock)

    def _br_int_diagnosis(self, sb_sock: str) -> None:
        ctx = self.ctx
        running = ctx.q("pgrep", "-x", "ovn-controller").ok
        lines = [
            "",
            "State right now:",
            f"  ovn-controller process : {'running' if running else 'NOT running'}",
        ]
        if ctx.have("systemctl"):
            unit_state = ctx.qout("systemctl", "is-active", "ovn-controller") or "unknown"
            lines.append(f"  systemd unit           : {unit_state}")
        lines.append(f"  ovn-remote             : {self.ovn_remote}")
        if sb_sock:
            from pathlib import Path
            lines.append(f"  SB socket exists       : {'yes' if Path(sb_sock).exists() else 'NO'}")
        lines += [
            "",
            "Most likely causes:",
            "  - The OVN central services are not running (ovn-northd / ovsdb-server)",
            "  - ovn-controller cannot reach the SB db at the ovn-remote above",
            "  - A previous teardown left the unit in a failed state",
            "    (systemctl reset-failed ovn-controller ; systemctl start ovn-controller)",
            "",
            "Check: journalctl -u ovn-controller -e --no-pager | tail -30",
            "",
        ]
        raise Abort("br-int still does not exist after waiting.\n" + "\n".join(lines))

    # -- 2 ---------------------------------------------------------------
    def logical_switches(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Logical switches")
        ctx.log("Creating logical switches...")
        for switch in (self.ls_int, self.ls_ext, self.ls_host):
            ctx.run("ovn-nbctl", "--may-exist", "ls-add", switch)

    # -- 3 ---------------------------------------------------------------
    def logical_router(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Logical router + gateway ports")
        ctx.log("Creating logical router...")
        ctx.run("ovn-nbctl", "--may-exist", "lr-add", self.lr_core)

        existing = ovn.lrp_list(ctx, self.lr_core)
        for port, mac, cidr in (
            (self.lrp_int, self.lrp_int_mac, self.lrp_int_cidr),
            (self.lrp_ext, self.lrp_ext_mac, self.lrp_ext_cidr),
            (self.lrp_host, self.lrp_host_mac, self.lrp_host_cidr),
        ):
            if port not in existing:
                ctx.run("ovn-nbctl", "lrp-add", self.lr_core, port, mac, cidr)

    # -- 4 ---------------------------------------------------------------
    def attach_switches(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Attach switches to router")
        for switch, lrp in ((self.ls_int, self.lrp_int),
                            (self.ls_ext, self.lrp_ext),
                            (self.ls_host, self.lrp_host)):
            ctx.log(f"Attaching {switch} to router...")
            peer = f"{switch}-to-lr"
            ctx.run("ovn-nbctl", "--may-exist", "lsp-add", switch, peer)
            ctx.run("ovn-nbctl", "lsp-set-type", peer, "router")
            ctx.run("ovn-nbctl", "lsp-set-addresses", peer, "router")
            ctx.run("ovn-nbctl", "lsp-set-options", peer, f"router-port={lrp}")

    # -- 5 ---------------------------------------------------------------
    def host_interface(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Host-facing port")
        ctx.log(f"Creating host OVN interface ({self.host_if}) on "
                f"{self.ls_host} ({self.host_if_cidr})...")

        if ctx.have("ovn-sbctl"):
            if "Chassis" not in ctx.qout("ovn-sbctl", "show"):
                ctx.log("WARNING: no Chassis registered in the Southbound db yet.")
                ctx.log("ovn-controller may still be connecting; ports may stay "
                        "'down' until it does.")

        # Migration: host-if used to live on the VM switch. If it is still
        # there (or on any switch other than ls_host), remove it first --
        # lsp-add would otherwise fail with a duplicate-name error.
        if ovn.lsp_exists(ctx, self.host_if):
            if self.host_if not in ovn.lsp_list(ctx, self.ls_host):
                ctx.log(f"Migrating {self.host_if} to {self.ls_host} "
                        "(it was on another switch)...")
                ctx.run("ovn-nbctl", "--if-exists", "lsp-del", self.host_if)

        self._ensure_ovs_port()

        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.ls_host, self.host_if)
        ctx.run("ovn-nbctl", "lsp-set-addresses", self.host_if,
                f"{self.host_if_mac} {self.host_if_ip}")
        ctx.run("ovs-vsctl", "set", "interface", self.host_if,
                f"external-ids:iface-id={self.host_if}")
        ctx.run("ip", "link", "set", self.host_if, "up")

        self._fix_kernel_mac()
        self._fix_addresses()
        self._add_routes()

        if ctx.dry_run:
            return

        self._verify_and_report()

    # Kernel device kinds that are safe to delete in order to free the
    # host_if name. They are placeholders: nothing can be reached through
    # one, so a device of this kind wearing the name can only ever be
    # something left behind. Anything else -- a bridge, a bond, a VLAN, a
    # physical NIC -- might be carrying real traffic, so we refuse rather
    # than guess.
    PLACEHOLDER_KINDS = ("dummy", "veth")

    def _link_kind(self) -> str:
        """The kernel's device kind for host_if ('' if it does not exist).

        `ip -d link show` names the kind on the third line: 'openvswitch'
        for a real OVS internal port, 'dummy' for a placeholder, and so
        on. The distinction matters because the name is a single global
        namespace -- whoever creates a device called host-if first owns
        it, and ovs-vswitchd cannot then create its internal port.
        """
        res = self.ctx.q("ip", "-d", "link", "show", "dev", self.host_if)
        if not res.ok:
            return ""
        known = ("openvswitch", "dummy", "veth", "bridge", "bond", "vlan",
                 "tun", "vxlan", "macvlan", "team", "geneve")
        for line in res.stdout.splitlines()[1:]:
            for token in line.split():
                if token in known:
                    return token
        return "unknown"

    def _reclaim_name(self) -> None:
        """Free the host_if name if a non-OVS device is holding it.

        This is the failure this whole step used to walk straight past. A
        device called host-if that ovs-vswitchd did not create makes
        `add-port ... type=internal` fail with

            could not add network device host-if to ofproto (File exists)

        and vswitchd leaves the row in place with ofport -1, admin_state
        unset and error set. Everything downstream then looks healthy --
        the port is on br-int, the iface-id is right, the address and the
        routes apply to the kernel device that IS there -- while
        ovn-controller has no ofport to bind and the host can reach
        nothing. A NetworkManager profile that creates a device (dummy,
        bridge, bond) is the usual way to end up here, and it recreates
        the device at every boot, so this has to be handled rather than
        reported once.
        """
        ctx = self.ctx
        kind = self._link_kind()
        if kind in ("", "openvswitch"):
            return

        if kind not in self.PLACEHOLDER_KINDS:
            raise Abort(
                f"a {kind} device named '{self.host_if}' already exists, so "
                f"ovs-vswitchd cannot create its internal port of that name.\n"
                f"It is not a placeholder, so it will not be removed "
                f"automatically. Inspect it (ip -d link show {self.host_if}), "
                f"remove or rename it, then re-run.")

        ctx.warn(f"A {kind} device named '{self.host_if}' is holding the name; "
                 "ovs-vswitchd cannot create its internal port while it exists.")
        ctx.warn("Removing it. If something recreates it at boot -- typically a "
                 "NetworkManager profile of that type -- delete that profile "
                 f"too: nmcli -f NAME,TYPE,DEVICE connection show | grep {self.host_if}")
        ctx.run("ip", "link", "del", self.host_if)

    def _ensure_ovs_port(self) -> None:
        """Create the internal port, and rebuild it if it is not working.

        The old shape of this was `if port-to-br fails: add-port, else:
        skip`. Presence of the port row is not the same thing as a working
        interface, so once a broken row existed nothing here would ever
        rebuild it -- setup and reconcile both re-asserted the iface-id on
        a dead row for as long as anyone cared to re-run them.
        """
        ctx = self.ctx
        exists = ctx.q("ovs-vsctl", "port-to-br", self.host_if).ok

        if exists:
            ofport, error = ovn.iface_health(ctx, self.host_if)
            if ofport > 0:
                ctx.log(f"OVS port {self.host_if} exists and is healthy "
                        f"(ofport {ofport}), skipping add-port.")
                return
            ctx.warn(f"OVS port {self.host_if} exists but has no datapath "
                     f"(ofport {ofport}). Rebuilding it.")
            if error:
                ctx.warn(f"ovs-vswitchd reports: {error}")
            ctx.run("ovs-vsctl", "--if-exists", "del-port", self.br_int,
                    self.host_if)

        # Only now, with the OVS row gone, is a leftover device of that
        # name unambiguously not ours to keep.
        self._reclaim_name()

        ctx.run("ovs-vsctl", "add-port", self.br_int, self.host_if,
                "--", "set", "interface", self.host_if, "type=internal",
                f'mac="{self.host_if_mac}"')

        if ctx.dry_run:
            return

        ofport, error = ovn.iface_health(ctx, self.host_if)
        if ofport > 0:
            return
        ctx.warn(f"{self.host_if} still has no datapath after being recreated "
                 f"(ofport {ofport}).")
        if error:
            ctx.warn(f"ovs-vswitchd reports: {error}")
        ctx.warn("ovn-controller cannot bind a port with no ofport, so the "
                 "host will not reach anything through it.")
        ctx.warn(f"-> ip -d link show {self.host_if}   (what else owns the name?)")

    def _kernel_mac(self) -> str:
        out = self.ctx.qout("ip", "-o", "link", "show", "dev", self.host_if)
        parts = out.split()
        # "N: name: <FLAGS> mtu ... link/ether <mac> brd ..."
        for i, tok in enumerate(parts):
            if tok.startswith("link/") and i + 1 < len(parts):
                return parts[i + 1]
        return ""

    def _fix_kernel_mac(self) -> None:
        ctx = self.ctx
        kernel_mac = self._kernel_mac()
        if kernel_mac and kernel_mac.lower() != self.host_if_mac.lower():
            ctx.log(f"Kernel MAC ({kernel_mac}) does not match desired MAC "
                    f"({self.host_if_mac}), fixing...")
            ctx.run("ip", "link", "set", "dev", self.host_if, "down")
            ctx.run("ip", "link", "set", "dev", self.host_if, "address",
                    self.host_if_mac)
            ctx.run("ip", "link", "set", "dev", self.host_if, "up")

    def _fix_addresses(self) -> None:
        """Drop any address that is not the one we want.

        Removing the old address also removes its connected route and
        anything that used it, which is what makes the move off the VM
        subnet clean.
        """
        ctx = self.ctx
        out = ctx.qout("ip", "-4", "-o", "addr", "show", "dev", self.host_if)
        existing = [ln.split()[3] for ln in out.splitlines() if len(ln.split()) > 3]
        for addr in existing:
            if addr != self.host_if_cidr:
                ctx.log(f"Removing stale address {addr} from {self.host_if}...")
                ctx.run("ip", "addr", "del", addr, "dev", self.host_if)

        if self.host_if_cidr not in existing:
            ctx.run("ip", "addr", "add", self.host_if_cidr, "dev", self.host_if)
        else:
            ctx.log(f"Address {self.host_if_cidr} already assigned to "
                    f"{self.host_if}, skipping.")

    def _route_metrics(self, net: str) -> list[str]:
        """Every metric at which `net` currently exists on host_if.

        A route with no metric is metric 0; report it as such so the
        caller can compare it against a configured value.
        """
        found: list[str] = []
        out = self.ctx.qout("ip", "route", "show", net, "dev", self.host_if)
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if "metric" in parts:
                idx = parts.index("metric")
                if idx + 1 < len(parts):
                    found.append(parts[idx + 1])
                    continue
            found.append("0")
        return found

    def _add_routes(self) -> None:
        """host-if is no longer on the VM segment, so every internal
        destination is now a routed hop via the router port.

        `ip route replace` matches on (destination, metric), so a copy of
        a prefix installed at any OTHER metric is invisible to it and
        survives beside the one written here -- which is exactly what a
        NetworkManager profile (550 by default on an OVS internal port)
        and this function (metric 0) did to each other, one extra pair of
        routes per prefix per reconcile. Delete the strays first, then
        write the canonical route at the configured metric so that the
        two paths address the same route and `replace` really replaces.
        """
        ctx = self.ctx
        metric = str(self.host_route_metric).strip() if self.host_route_metric else ""
        want = metric or "0"

        for net in self.host_routes:
            if not net.strip():
                continue

            for existing in self._route_metrics(net):
                if existing != want:
                    ctx.log(f"Removing duplicate route {net} dev {self.host_if} "
                            f"at metric {existing}.")
                    ctx.run("ip", "route", "del", net, "dev", self.host_if,
                            "metric", existing)

            cmd = ["ip", "route", "replace", net, "via", self.host_gw,
                   "dev", self.host_if]
            if metric:
                cmd += ["metric", metric]
            ctx.run(*cmd)
            suffix = f" metric {metric}" if metric else ""
            ctx.log(f"Route {net} via {self.host_gw} dev {self.host_if}{suffix}")

    def _verify_and_report(self) -> None:
        ctx = self.ctx
        kernel_mac = self._kernel_mac()
        if kernel_mac.lower() == self.host_if_mac.lower():
            ctx.log(f"Verified: {self.host_if} kernel MAC matches OVN logical "
                    f"port MAC ({self.host_if_mac}).")
        else:
            ctx.warn(f"{self.host_if} kernel MAC is {kernel_mac}, "
                     f"expected {self.host_if_mac}.")
            ctx.warn("Traffic sourced from this host may not match what OVN expects.")

        if not ctx.verbose:
            return
        net = self.host_if_cidr.split("/")[0]
        print("")
        print("=== Host segment ===")
        print(f"  host-if      {self.host_if_cidr}   "
              f"(was on {self.ls_int}, now on {self.ls_host})")
        print(f"  gateway      {self.host_gw}   ({self.lrp_host} on {self.lr_core})")
        print(f"  routes via   {self.host_gw}:  {' '.join(self.host_routes)}")
        print("")
        print(f"For workstation laptops to reach {self.host_if_ip}, "
              "BOTH upstream firewalls need:")
        print(f"  a route for {net}/30 pointing back toward 172.31.1.6")
        print("  and a rule permitting that traffic in both directions.")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-setup")
    # Fail before changing anything if the settings file is incomplete.
    ctx.require_cfg(*REQUIRED_CFG)

    ctx.require_root()
    ctx.require_cmd("ovs-vsctl", "ovn-nbctl", "ip")

    setup = Setup(ctx)
    runner = StepRunner(ctx, "setup")
    runner.add("external-ids", "configure OVS external-ids", setup.external_ids)
    runner.add("ovn-controller", "start the control plane, wait for br-int",
               setup.ovn_controller)
    runner.add("switches", "create the logical switches", setup.logical_switches)
    runner.add("logical-router", "create lr-core and its gateway ports",
               setup.logical_router)
    runner.add("attach-switches", "attach each switch to the router",
               setup.attach_switches)
    runner.add("host-interface", "create host-if, address it, add routes",
               setup.host_interface)

    if not runner.run(args):
        return 0

    record(ctx, SETUP, runner)
    ctx.finish("base topology, host segment, router")
    return 0