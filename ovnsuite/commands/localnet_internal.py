"""
ovnctl localnet-internal -- port of ovn-localnet-internal.sh

Gives the VMs behind lr-core a path to the rest of the internal
infrastructure via a localnet port bridging OVN out to a physical NIC.
This is NOT an internet gateway -- no NAT is configured, traffic leaves and
returns with real 172.31.x.x addresses.

Run this AFTER `ovnctl setup` (lr-core must already exist).
"""

from __future__ import annotations

import argparse

from .. import identity, ovn
from ..context import Abort, Ctx
from ..state import LOCALNET_INTERNAL, Tracker, record
from ..steps import StepRunner, add_step_args

NAME = "localnet-internal"
HELP = "br-internal uplink to the workstation LAN + default route"

REQUIRED_CFG = (
    "localnet_internal:br_internal",
    "localnet_internal:gateway_chassis_priority",
    "localnet_internal:lan_gateway", "localnet_internal:ln_uplink",
    "localnet_internal:lrp_uplink", "localnet_internal:lrp_uplink_mac",
    "localnet_internal:ls_uplink", "localnet_internal:phys_nic",
    "localnet_internal:physnet_label", "localnet_internal:transit_ip",
    "localnet_internal:transit_subnet",
    "localnet_internal:workstation_subnet", "topology:lr_core",
)


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--remove", action="store_true",
                   help="tear down just this gateway")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class LocalnetInternal:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        # The SPARE physical NIC cabled into the workstation LAN segment.
        # Do NOT point this at a NIC being used for SSH/management --
        # confirm from console/IPMI first.
        self.phys_nic = c.cfg("localnet_internal", "phys_nic")
        self.br_internal = c.cfg("localnet_internal", "br_internal")
        self.physnet_label = c.cfg("localnet_internal", "physnet_label")

        self.lr_core = c.cfg("topology", "lr_core")
        self.ls_uplink = c.cfg("localnet_internal", "ls_uplink")
        self.ln_uplink = c.cfg("localnet_internal", "ln_uplink")
        self.lrp_uplink = c.cfg("localnet_internal", "lrp_uplink")
        self.lrp_uplink_mac = c.cfg("localnet_internal", "lrp_uplink_mac")

        # This NIC terminates on a point-to-point link to the first upstream
        # firewall, NOT directly on the workstation LAN.
        self.transit_subnet = c.cfg("localnet_internal", "transit_subnet")
        self.lan_gateway = c.cfg("localnet_internal", "lan_gateway")
        self.transit_ip = c.cfg("localnet_internal", "transit_ip")
        # Documentation only -- routing beyond lan_gateway is entirely up to
        # the firewalls in between.
        self.workstation_subnet = c.cfg("localnet_internal", "workstation_subnet")
        self.gw_priority = c.cfg("localnet_internal", "gateway_chassis_priority")

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

    # -- 1 ---------------------------------------------------------------
    def bridge_nic(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Uplink bridge + NIC")
        ctx.log(f"Setting up {self.br_internal} with uplink {self.phys_nic}...")

        if not ctx.q("ip", "link", "show", self.phys_nic).ok:
            if ctx.dry_run:
                ctx.warn(f"Interface {self.phys_nic} does not exist "
                         "(dry-run: continuing).")
            else:
                raise Abort(
                    f"Interface {self.phys_nic} does not exist on this host.\n"
                    "Fix localnet_internal.phys_nic in the settings and re-run."
                )

        if ctx.have("nmcli"):
            if ctx.run("nmcli", "device", "set", self.phys_nic, "managed", "no"):
                ctx.log(f"Set {self.phys_nic} unmanaged in NetworkManager.")
            else:
                ctx.warn(f"Could not set {self.phys_nic} unmanaged "
                         "(NetworkManager may not know about it, that's fine).")
        else:
            ctx.log("nmcli not present, skipping NetworkManager unmanage step.")

        if not ovn.br_exists(ctx, self.br_internal):
            ctx.run("ovs-vsctl", "add-br", self.br_internal)
            ctx.log(f"Created bridge {self.br_internal}.")
        else:
            ctx.log(f"Bridge {self.br_internal} already exists.")

        if self.phys_nic not in ovn.list_ports(ctx, self.br_internal):
            ctx.run("ovs-vsctl", "add-port", self.br_internal, self.phys_nic)
            ctx.log(f"Added {self.phys_nic} to {self.br_internal}.")
        else:
            ctx.log(f"{self.phys_nic} already a port on {self.br_internal}.")

        ctx.run("ip", "link", "set", self.br_internal, "up")

        # Deliberately no IP on the bridge or the physical NIC -- OVN owns
        # this path.
        if "inet " in ctx.qout("ip", "addr", "show", "dev", self.phys_nic):
            ctx.warn(f"{self.phys_nic} still has an IP address assigned. "
                     "Remove it manually --")
            ctx.warn("OVN, not the kernel, should own addressing on this path.")

    # -- 2 ---------------------------------------------------------------
    def bridge_mapping(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Bridge mapping")
        mapping = f"{self.physnet_label}:{self.br_internal}"
        ctx.log(f"Setting ovn-bridge-mappings={mapping}...")
        existing = ovn.external_id(ctx, "ovn-bridge-mappings")

        if not existing:
            ctx.run("ovs-vsctl", "set", "open", ".",
                    f"external-ids:ovn-bridge-mappings={mapping}")
        elif mapping in existing:
            ctx.log(f"Mapping already present in: {existing}")
        else:
            ctx.log(f"Appending to existing bridge-mappings ({existing})...")
            ctx.run("ovs-vsctl", "set", "open", ".",
                    f"external-ids:ovn-bridge-mappings={existing},{mapping}")

    # -- 3 ---------------------------------------------------------------
    def transit_switch(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Transit switch + localnet port")
        ctx.log(f"Creating transit switch {self.ls_uplink} with localnet port "
                f"{self.ln_uplink}...")
        ctx.run("ovn-nbctl", "--may-exist", "ls-add", self.ls_uplink)
        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.ls_uplink,
                self.ln_uplink)
        ctx.run("ovn-nbctl", "lsp-set-type", self.ln_uplink, "localnet")
        ctx.run("ovn-nbctl", "lsp-set-addresses", self.ln_uplink, "unknown")
        ctx.run("ovn-nbctl", "lsp-set-options", self.ln_uplink,
                f"network_name={self.physnet_label}")

    # -- 4 ---------------------------------------------------------------
    def attach_router(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Router port + gateway chassis")
        ctx.log(f"Attaching {self.lr_core} to {self.ls_uplink} via "
                f"{self.lrp_uplink} ({self.transit_ip})...")

        if not ovn.lrp_present(ctx, self.lr_core, self.lrp_uplink):
            ctx.run("ovn-nbctl", "lrp-add", self.lr_core, self.lrp_uplink,
                    self.lrp_uplink_mac, self.transit_ip)
        else:
            ctx.log(f"{self.lrp_uplink} already exists on {self.lr_core}.")

        peer = f"{self.ls_uplink}-to-lr"
        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.ls_uplink, peer)
        ctx.run("ovn-nbctl", "lsp-set-type", peer, "router")
        ctx.run("ovn-nbctl", "lsp-set-addresses", peer, "router")
        ctx.run("ovn-nbctl", "lsp-set-options", peer,
                f"router-port={self.lrp_uplink}")

        ctx.log(f"Pinning {self.lrp_uplink} to a gateway chassis "
                "(required even with a single chassis)...")

        # NOT ovn.first_chassis(). On a host whose identity has drifted the
        # SB db can hold a stale row, and "the first chassis" is whichever
        # one the db returns first -- pinning to that is precisely how a
        # pin ends up naming a chassis nothing runs under. pin_target()
        # returns the configured identity and refuses if it is not actually
        # registered.
        chassis = identity.pin_target(ctx)
        ctx.log(f"Using chassis: {chassis}")
        identity.repin_gateway(ctx, self.lrp_uplink, chassis, self.gw_priority)

    # -- 5 ---------------------------------------------------------------
    def routes(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Default route")
        ctx.log(f"Adding catch-all route 0.0.0.0/0 via {self.lan_gateway}...")
        ctx.log("(More specific routes to directly-connected subnets still win "
                "over this.)")
        ctx.run("ovn-nbctl", "--may-exist", "lr-route-add", self.lr_core,
                "0.0.0.0/0", self.lan_gateway)

    # -- 6 ---------------------------------------------------------------
    def confirm_no_nat(self) -> None:
        ctx = self.ctx
        ctx.log(f"Confirming no NAT rules exist on {self.lr_core}...")
        nat = ctx.qout("ovn-nbctl", "lr-nat-list", self.lr_core)
        if not nat:
            ctx.log("No NAT configured -- correct for internal routing.")
            return
        ctx.warn(f"NAT rules ARE present on {self.lr_core}:")
        ctx.note_stderr(nat)
        ctx.warn("Traffic will be source-NATed, which defeats "
                 "'route everywhere with real IPs'.")
        ctx.warn(f"Remove with: ovn-nbctl lr-nat-del {self.lr_core} ...")

    # ------------------------------------------------------------------
    def teardown(self) -> None:
        ctx = self.ctx
        ctx.log("Removing localnet gateway config...")

        if ctx.run("ovn-nbctl", "--if-exists", "lr-route-del", self.lr_core,
                   "0.0.0.0/0"):
            ctx.log("Removed default route.")

        if ovn.lrp_present(ctx, self.lr_core, self.lrp_uplink):
            if ctx.run("ovn-nbctl", "--if-exists", "lrp-del", self.lrp_uplink):
                ctx.log(f"Removed router port {self.lrp_uplink}.")

        if ctx.run("ovn-nbctl", "--if-exists", "ls-del", self.ls_uplink):
            ctx.log(f"Removed transit switch {self.ls_uplink}.")

        if ctx.run("ovs-vsctl", "remove", "open", ".", "external-ids",
                   "ovn-bridge-mappings"):
            ctx.log("Cleared ovn-bridge-mappings.")

        if self.phys_nic in ovn.list_ports(ctx, self.br_internal):
            if ctx.run("ovs-vsctl", "del-port", self.br_internal, self.phys_nic):
                ctx.log(f"Removed {self.phys_nic} from {self.br_internal}.")

        if ovn.br_exists(ctx, self.br_internal):
            if ctx.run("ovs-vsctl", "del-br", self.br_internal):
                ctx.log(f"Removed bridge {self.br_internal}.")

        if ctx.have("nmcli"):
            if ctx.run("nmcli", "device", "set", self.phys_nic, "managed", "yes"):
                ctx.log(f"Returned {self.phys_nic} to NetworkManager management.")

        Tracker(ctx).unmark(LOCALNET_INTERNAL)
        ctx.log("Removed 'localnet-internal' from deployment tracker.")
        ctx.log(f"Done. Note: this does NOT restore an IP on {self.phys_nic} -- "
                "reconfigure")
        ctx.log("it manually (e.g. via nmcli) if you need it back for normal "
                "host networking.")

    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        transit_bare = self.transit_ip.split("/")[0]
        print("")
        print("=== Localnet gateway summary ===")
        print(f"Bridge:         {self.br_internal} (uplink: {self.phys_nic})")
        print(f"Physnet label:  {self.physnet_label}")
        print(f"Transit port:   {self.lrp_uplink} ({self.transit_ip}) "
              f"on {self.ls_uplink}")
        print(f"Transit link:   {self.transit_subnet} (P2P to first-hop firewall)")
        print(f"First-hop fw:   {self.lan_gateway}  (default route next-hop)")
        print(f"Destination:    {self.workstation_subnet} "
              "(workstation LAN, 2 firewall hops away)")
        print("")
        print("IMPORTANT -- manual steps still required upstream (2 firewall hops):")
        print(f"  Traffic will reach the first firewall ({self.lan_gateway}) fine, "
              "but won't")
        print("  get further -- and won't route back -- unless BOTH firewalls have:")
        print(f"    a) A route/rule for 172.31.1.0/24 pointing back toward "
              f"{transit_bare}")
        print("       -- this MUST include 172.31.1.8/30, the host-if segment, or")
        print("          workstation laptops will not be able to reach the host at")
        print("          172.31.1.9")
        print(f"       (via {self.lan_gateway} from the second firewall's perspective)")
        print("    b) Any filtering rules updated to permit this traffic in both")
        print("       directions -- P2P links to firewalls are almost always deny-by-")
        print("       default")
        print("  This script cannot configure either firewall -- confirm with whoever")
        print("  manages them.")
        print("")
        print("Test from a VM behind lr-core:")
        print(f"  ping {self.lan_gateway}            "
              "# first-hop firewall, tests the P2P link")
        print("  ping <workstation-host>        # tests the full path")
        print("Test from a workstation host (once both firewalls have return routes):")
        print("  ping 172.31.1.20   # e.g. int-vm3")
        print("")
        print("If the first ping works but the second doesn't, the P2P link and OVN")
        print("side are fine -- the problem is firewall routing/rules further "
              "upstream,")
        print("not this script.")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-localnet")
    ctx.require_cfg(*REQUIRED_CFG)

    ctx.require_root()
    ctx.require_cmd("ovs-vsctl", "ovn-nbctl", "ovn-sbctl", "ip")

    cmd = LocalnetInternal(ctx)

    if args.remove:
        cmd.teardown()
        return 0

    runner = StepRunner(ctx, "localnet-internal")
    runner.add("check-router", "verify lr-core exists", cmd.check_lr_core)
    runner.add("bridge-nic", "create br-internal and enslave the NIC",
               cmd.bridge_nic)
    runner.add("bridge-mapping", "extend ovn-bridge-mappings", cmd.bridge_mapping)
    runner.add("transit-switch", "transit switch + localnet port",
               cmd.transit_switch)
    runner.add("attach-router", "router port + gateway chassis pin",
               cmd.attach_router)
    runner.add("routes", "the 0.0.0.0/0 route to the first-hop firewall",
               cmd.routes)
    runner.add("confirm-no-nat", "warn if NAT is configured on lr-core",
               cmd.confirm_no_nat)

    if not runner.run(args):
        return 0

    record(ctx, LOCALNET_INTERNAL, runner)

    if ctx.verbose and not ctx.dry_run:
        cmd.print_summary()
    ctx.finish("br-internal uplink + default route")
    return 0