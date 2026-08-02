"""
ovnctl vm-config -- port of ovn-vm-config.sh

Creates the OVN logical switch ports for the VMs in this deployment.

UUIDs and MACs come from [vm_config] in ovn-settings.yaml and are pinned to
the libvirt domain XMLs -- keep the two in sync, and don't regenerate one
side without the other. The logical switch port is NAMED after the VM's
UUID, which is also what belongs in
<virtualport><parameters interfaceid='...'/> in the domain XML, so
libvirt, OVS and OVN all agree on one port identity.

Run this AFTER `ovnctl setup`.
"""

from __future__ import annotations

import argparse

from .. import ovn
from ..context import Abort, Ctx
from ..inventory import VM, Inventory
from ..state import VM_CONFIG, Tracker, record
from ..steps import StepRunner, add_step_args

NAME = "vm-config"
HELP = "VM logical switch ports"


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--remove", action="store_true",
                   help="remove these VM ports only")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class VMConfig:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.ls_int = ctx.cfg("topology", "ls_int")
        self.ls_ext = ctx.cfg("topology", "ls_ext")
        self.inv = Inventory(ctx.config, self.ls_int, self.ls_ext)

        if not self.inv.all:
            raise Abort("No VMs in [vm_config] -- nothing to configure.")

    # ------------------------------------------------------------------
    def check_switches(self) -> None:
        for switch in (self.ls_int, self.ls_ext):
            if ovn.ls_exists(self.ctx, switch):
                continue
            if self.ctx.dry_run:
                self.ctx.warn(f"logical switch '{switch}' does not exist "
                              "(dry-run: continuing).")
                continue
            raise Abort(f"logical switch '{switch}' does not exist.\n"
                        "Run `ovnctl setup` first to create the base topology.")

    # ------------------------------------------------------------------
    def _configure(self, vms: list[VM], switch: str) -> None:
        ctx = self.ctx
        for vm in vms:
            ctx.log(f"  {vm.name}: port={vm.uuid} mac={vm.mac} ip={vm.ip}")
            ctx.run("ovn-nbctl", "--may-exist", "lsp-add", switch, vm.uuid)
            ctx.run("ovn-nbctl", "lsp-set-addresses", vm.uuid,
                    f"{vm.mac} {vm.ip}")
            # Port security binds the port to this MAC+IP: the guest cannot
            # spoof either. That is load-bearing, not cosmetic -- the router
            # policy and several ACLs match on ip4.src, so a VM able to
            # forge a source address could route around them.
            #
            # The command is lsp-set-port-security. It was once written as
            # "lsp-port-security" with errors suppressed, so it failed
            # silently on every run and port security was never applied.
            ctx.run("ovn-nbctl", "lsp-set-port-security", vm.uuid,
                    f"{vm.mac} {vm.ip}")
            # external-id for readability in `ovn-nbctl list Logical_Switch_Port`
            ctx.run("ovn-nbctl", "set", "Logical_Switch_Port", vm.uuid,
                    f"external-ids:vm-name={vm.name}")

    def internal_ports(self) -> None:
        self.ctx.dr_head("VM logical switch ports (internal)")
        self.ctx.log(f"Configuring internal VMs on {self.ls_int}...")
        self._configure(self.inv.internal, self.ls_int)

    def external_ports(self) -> None:
        self.ctx.dr_head("VM logical switch ports (external)")
        self.ctx.log(f"Configuring external VMs on {self.ls_ext}...")
        self._configure(self.inv.external, self.ls_ext)

    # ------------------------------------------------------------------
    def remove(self) -> None:
        ctx = self.ctx
        ctx.log("Removing VM logical switch ports...")
        for vm in self.inv.all:
            ctx.log(f"  removing {vm.name} ({vm.uuid}) from {vm.switch}")
            if not ctx.run("ovn-nbctl", "--if-exists", "lsp-del", vm.uuid):
                ctx.warn(f"Failed to remove port {vm.uuid} for {vm.name}")
        Tracker(ctx).unmark(VM_CONFIG)
        ctx.log("Removed 'vm-config' from deployment tracker.")
        ctx.log("Done.")

    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        ctx = self.ctx
        lrp_int = ctx.cfg_opt("setup", "lrp_int_cidr", "")
        lrp_ext = ctx.cfg_opt("setup", "lrp_ext_cidr", "")
        print("")
        print("=== VM inventory (for libvirt domain XML uuid/network fields) ===")
        print(f"{'NAME':<10} {'UUID':<38} {'MAC':<19} {'IP':<15}")
        for vm in self.inv.all:
            print(f"{vm.name:<10} {vm.uuid:<38} {vm.mac:<19} {vm.ip:<15}")
        print("")
        if lrp_int:
            print(f"Internal gateway: {lrp_int.split('/')[0]}  (subnet {lrp_int})")
        if lrp_ext:
            print(f"External gateway: {lrp_ext.split('/')[0]}  (subnet {lrp_ext})")
        print("")
        print("For each VM's libvirt XML, the interface should look like:")
        print("  <interface type='bridge'>")
        print("    <mac address='<MAC FROM TABLE ABOVE>'/>")
        print("    <source bridge='br-int'/>")
        print("    <virtualport type='openvswitch'>")
        print("      <parameters interfaceid='<UUID FROM TABLE ABOVE>'/>")
        print("    </virtualport>")
        print("  </interface>")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-vm-config")
    ctx.require_cfg("topology:ls_ext", "topology:ls_int")

    ctx.require_root()
    ctx.require_cmd("ovn-nbctl")

    cmd = VMConfig(ctx)

    if args.remove:
        cmd.remove()
        return 0

    runner = StepRunner(ctx, "vm-config")
    runner.add("check-switches", "verify the logical switches exist",
               cmd.check_switches)
    runner.add("internal-ports", "create the internal VM ports",
               cmd.internal_ports)
    runner.add("external-ports", "create the external VM ports",
               cmd.external_ports)

    if not runner.run(args):
        return 0

    record(ctx, VM_CONFIG, runner)

    if ctx.verbose and not ctx.dry_run:
        cmd.print_summary()
    ctx.finish("VM logical ports")
    return 0
