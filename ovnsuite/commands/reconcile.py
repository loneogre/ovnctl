"""
ovnctl reconcile -- make the running system match the intent again.

`deploy` builds a deployment. `delete` removes one. Neither answers the
question a reboot asks: the OVN databases are persistent, but the half of
the deployment that lives in kernel and process state is not, and nothing
put it back.

What survives a reboot:
  - conf.db: bridges, ports, external-ids, iface-ids
  - the NB db: switches, routers, ACLs, gateway pins
  - the SB db: Port_Binding rows, INCLUDING their chassis column, which is
    why a stale binding reads as "up" long after it stopped meaning
    anything

What does not:
  - external-ids:system-id, which `ovs-ctl start --system-id=random`
    rewrites from /etc/openvswitch/system-id.conf at every boot
  - the kernel side of host-if: link state, its address, its routes
  - any claim ovn-controller had on a VIF whose tap is recreated after it

So this command re-asserts identity, repairs pins that identity drift
broke, brings host-if back up, and nudges ovn-controller if a tap exists
that it never claimed. Everything it does is idempotent; running it when
nothing is wrong changes nothing.

    ovnctl reconcile                    reassert, report anything unsafe
    ovnctl -n reconcile                 preview it
    ovnctl reconcile --repair-identity  also delete stale chassis rows
    ovnctl reconcile --install-unit     run it automatically at every boot
    ovnctl reconcile --install-nm-profile   let NetworkManager own host-if's
                                            address and routes across reboots
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

from .. import identity, ovn, paths
from ..context import Ctx
from ..state import SETUP, Tracker, current_boot_id
from ..steps import StepRunner, add_step_args
from .setup import Setup

NAME = "reconcile"
HELP = "reapply the runtime state a reboot dropped (identity, host-if, pins)"

UNIT_PATH = Path("/etc/systemd/system/ovn-reconcile.service")

UNIT_TEMPLATE = """\
[Unit]
Description=Reapply OVN runtime state after boot (ovnctl reconcile)
Documentation=man:ovn-controller(8)
# ovn-controller must be up first: reconcile compares the registered
# chassis against the configured identity, and there is nothing to
# compare against until the controller has connected to the SB db.
After=ovn-controller.service openvswitch.service
Wants=ovn-controller.service
Requires=openvswitch.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={exe} reconcile
# A failed reconcile must be visible in `systemctl status`, but must not
# block the rest of the boot.
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
"""

NM_PROFILE_DIR = Path("/etc/NetworkManager/system-connections")


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repair-identity", action="store_true",
                   help="delete Chassis rows left behind by a previous "
                        "identity (stops and restarts ovn-controller)")
    p.add_argument("--install-unit", action="store_true",
                   help=f"write {UNIT_PATH} and enable it, then exit")
    p.add_argument("--install-nm-profile", action="store_true",
                   help="write a NetworkManager keyfile so host-if's address "
                        "and routes are reapplied at every boot, then exit")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


def _executable() -> str:
    """An absolute path to this ovnctl, for the unit file."""
    candidate = paths.suite_root() / "ovnctl"
    if candidate.is_file():
        return str(candidate)
    argv0 = Path(sys.argv[0]).resolve()
    return str(argv0) if argv0.is_file() else "ovnctl"


class Reconcile:
    def __init__(self, ctx: Ctx, repair_identity: bool):
        self.ctx = ctx
        self.repair_identity = repair_identity
        # Setup owns the external-ids and host-if logic; reconcile is a
        # different entry point into the same steps, not a second copy of
        # them that can drift out of agreement.
        self.setup = Setup(ctx)
        self.canonical = self.setup.system_id
        self.identity_ok = False

    # -- 1 ---------------------------------------------------------------
    def external_ids(self) -> None:
        """Re-assert system-id / ovn-remote / encap and system-id.conf."""
        self.setup.external_ids()

    # -- 2 ---------------------------------------------------------------
    def check_identity(self) -> None:
        ctx = self.ctx
        ctx.dr_head("Chassis identity")

        local = identity.local(ctx)
        if local != self.canonical:
            ctx.warn(f"external-ids:system-id is '{local}', expected "
                     f"'{self.canonical}' -- step 1 should have fixed this.")

        leftovers = identity.stale(ctx, self.canonical)
        registered = identity.is_registered(ctx, self.canonical)

        if registered and not leftovers:
            ctx.log(f"Chassis identity is clean: '{self.canonical}' is "
                    "registered and nothing else is.")
            self.identity_ok = True
            return

        if not registered:
            ctx.warn(f"Chassis '{self.canonical}' is NOT registered in the SB db.")
            ctx.warn("ovn-controller has not (re-)registered under it yet.")

        if not leftovers:
            return

        ctx.warn(f"Stale chassis row(s) from a previous identity: "
                 f"{', '.join(leftovers)}")
        if not self.repair_identity:
            ctx.warn("Every Port_Binding and gateway pin naming these will "
                     "never bind.")
            ctx.warn("Re-run with --repair-identity to remove them.")
            return

        # A running controller re-creates its Chassis row as fast as it is
        # deleted, so it has to be stopped for the purge and started again
        # afterwards -- which is also what makes it register under the
        # canonical name.
        ctx.log("Stopping ovn-controller for the purge...")
        if ctx.have("systemctl") and ctx.unit_exists("ovn-controller"):
            ctx.run("systemctl", "stop", "ovn-controller")
        elif ctx.have("ovn-ctl"):
            ctx.run("ovn-ctl", "stop_controller")

        removed = identity.purge_stale_chassis(ctx, self.canonical)
        ctx.log(f"Removed {removed} stale chassis row(s).")

        identity.restart_controller(ctx, "re-register under the canonical id")
        if identity.wait_for_chassis(ctx, self.canonical):
            ctx.log(f"Chassis '{self.canonical}' is registered.")
            self.identity_ok = True
        else:
            ctx.warn(f"ovn-controller did not register '{self.canonical}' "
                     "within 30s.")
            ctx.warn("Check: journalctl -u ovn-controller -e --no-pager | tail -30")

    # -- 3 ---------------------------------------------------------------
    def gateway_pins(self) -> None:
        """Re-point pins that name a chassis nobody is running under."""
        ctx = self.ctx
        ctx.dr_head("Gateway-chassis pins")

        stale_pins = identity.stale_pins(ctx, self.canonical)
        if not stale_pins:
            ctx.log(f"All gateway pins already name '{self.canonical}'.")
            return

        if not identity.is_registered(ctx, self.canonical) and not ctx.dry_run:
            ctx.warn(f"{len(stale_pins)} stale pin(s), but '{self.canonical}' "
                     "is not registered -- not re-pinning.")
            ctx.warn("Fix the identity first (--repair-identity), then re-run.")
            return

        priority = ctx.config.cfg_opt("localnet_internal",
                                      "gateway_chassis_priority", "10")
        for pin_name, pin_chassis in stale_pins:
            lrp = _lrp_of_pin(pin_name, pin_chassis)
            if not lrp:
                ctx.warn(f"Cannot tell which router port pin '{pin_name}' "
                         "belongs to, leaving it alone.")
                continue
            if not ovn.nb_exists(ctx, "Logical_Router_Port", lrp):
                ctx.warn(f"Pin '{pin_name}' names router port '{lrp}', which "
                         "no longer exists.")
                ctx.run("ovn-nbctl", "--if-exists", "lrp-del-gateway-chassis",
                        lrp, pin_chassis)
                continue
            ctx.log(f"Re-pinning {lrp}: {pin_chassis} -> {self.canonical}")
            identity.repin_gateway(ctx, lrp, self.canonical, priority)

    # -- 4 ---------------------------------------------------------------
    def host_interface(self) -> None:
        """Link up, address, routes -- none of which survive a reboot."""
        self.setup.host_interface()

    # -- 5 ---------------------------------------------------------------
    def claim_check(self) -> None:
        """Find taps that exist locally but that no chassis has claimed.

        This is the reboot race: libvirt recreates a tap and sets its
        iface-id, but ovn-controller was not in a position to claim it.
        The cure is a controller restart -- but ONLY once identity is
        consistent. Restarting while system-id disagrees with the
        registered chassis is what turns one stale chassis into two and
        takes the uplink down with it.
        """
        ctx = self.ctx
        ctx.dr_head("Unclaimed local taps")

        unbound = _unclaimed_vifs(ctx)
        if not unbound:
            ctx.log("Every locally plugged port has a chassis bound.")
            return

        ctx.warn(f"{len(unbound)} port(s) plugged into local OVS with no "
                 "chassis bound:")
        for lp, tap in unbound:
            ctx.warn(f"  {lp} (interface {tap})")

        if not self.identity_ok and not ctx.dry_run:
            ctx.warn("NOT restarting ovn-controller: the chassis identity is "
                     "not consistent yet.")
            ctx.warn("A restart in this state registers a second chassis and "
                     "unbinds the gateway.")
            ctx.warn("Fix identity first: ovnctl reconcile --repair-identity")
            return

        identity.restart_controller(ctx, "claim locally plugged ports")

    # -- 6 ---------------------------------------------------------------
    def acl_logging(self) -> None:
        """Re-apply the acl_log vlog level.

        ovn-controller's vlog levels are runtime state: they are set by
        ovn-appctl and forgotten at the next restart. Every ACL still says
        log=true afterwards, so nothing looks wrong -- the records simply
        stop arriving. Since this command already runs at boot and after
        any controller restart, it is the right place to re-assert it.
        """
        ctx = self.ctx
        ctx.dr_head("ACL logging")
        if not ctx.have("ovn-appctl"):
            return
        # Only if something actually logs. Raising the level otherwise
        # costs nothing but says something misleading in the output.
        if not any(row.get("log") for row in ovn.acl_index(ctx).values()):
            ctx.log("No ACL has logging enabled -- nothing to re-assert.")
            return
        severity = ctx.config.cfg_opt("acl_log", "severity", "info")
        if ovn.appctl(ctx, "vlog/set", f"acl_log:syslog:{severity}"):
            ctx.log(f"acl_log vlog level re-applied ({severity}).")
        else:
            ctx.warn("Could not re-apply the acl_log vlog level; ACL records "
                     "may not reach syslog until `ovnctl acl --only "
                     "log-sink` is run.")

    # -- 7 ---------------------------------------------------------------
    def refresh_tracker(self) -> None:
        """Stamp the tracker with the current boot id.

        Only for components that were already recorded: reconcile does not
        deploy anything, it re-realises what was already intended. The
        point is that the next diagnose can tell "reconciled during this
        boot" from "recorded three boots ago and never touched since".
        """
        ctx = self.ctx
        tracker = Tracker(ctx)
        if not tracker.exists():
            ctx.log("No tracker file -- nothing to refresh.")
            return
        stale_keys = tracker.any_from_earlier_boot()
        if not stale_keys:
            ctx.log("Tracker already reflects the current boot.")
            return
        for key in stale_keys:
            tracker.mark(key)
        ctx.log(f"Refreshed tracker boot id for: {', '.join(stale_keys)}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _lrp_of_pin(pin_name: str, pin_chassis: str) -> str:
    """Gateway_Chassis rows are named "<lrp>-<chassis>"."""
    suffix = f"-{pin_chassis}"
    if pin_chassis and pin_name.endswith(suffix):
        return pin_name[: -len(suffix)]
    return ""


def _unclaimed_vifs(ctx: Ctx) -> list[tuple[str, str]]:
    """(logical port, local interface) for every plugged-but-unbound port."""
    rows = ovn.sb_json(ctx, "logical_port,type,chassis", "Port_Binding")
    if not rows:
        return []
    non_vif = {"patch", "router", "localnet", "localport", "l2gateway",
               "chassisredirect"}
    taps: dict[str, str] | None = None
    out: list[tuple[str, str]] = []
    for row in rows:
        if len(row) < 3:
            continue
        lp, ptype = str(row[0]), str(row[1] or "")
        if ptype in non_vif or ovn.ref_is_set(row[2]):
            continue
        if taps is None:
            taps = ovn.iface_id_map(ctx)
        tap = taps.get(lp, "")
        if tap:
            out.append((lp, tap))
    return out


def _install_unit(ctx: Ctx) -> int:
    exe = _executable()
    content = UNIT_TEMPLATE.format(exe=exe)

    ctx.dr_head("systemd unit")
    if ctx.dry_run:
        print(f"cat > {UNIT_PATH} <<'EOF'")
        print(content, end="")
        print("EOF")
        print("systemctl daemon-reload")
        print("systemctl enable ovn-reconcile.service")
        return 0

    try:
        UNIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        UNIT_PATH.write_text(content, encoding="utf-8")
        os.chmod(UNIT_PATH, 0o644)
    except OSError as exc:
        ctx.err(f"Could not write {UNIT_PATH}: {exc}")
        return 1

    ctx.say(f"Wrote {UNIT_PATH} (ExecStart={exe} reconcile)")
    ctx.run("systemctl", "daemon-reload")
    if ctx.run("systemctl", "enable", "ovn-reconcile.service"):
        ctx.say("Enabled ovn-reconcile.service -- it will run at every boot.")
    else:
        ctx.warn("Could not enable the unit; enable it manually.")
    return 0


def _nm_profile(setup: Setup) -> str:
    """A NetworkManager keyfile describing host-if's kernel-side state.

    The systemd unit reapplies this state once, after boot. A keyfile
    instead makes it a property of the interface: NetworkManager reapplies
    it whenever the device appears, including after an ovs-vswitchd
    restart that recreates the internal port mid-boot.

    Deliberately no `gateway=`: that key installs a default route through
    lr-core, which then competes with the host's real uplink on metric.
    Only the configured host_routes go through the OVN router.
    """
    # Derived from the interface name so rewriting the file updates the
    # existing profile rather than leaving a second one beside it.
    profile_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"ovnctl.{setup.host_if}")

    lines = [
        "[connection]",
        f"id={setup.host_if}",
        f"uuid={profile_uuid}",
        "type=ethernet",
        f"interface-name={setup.host_if}",
        "autoconnect=true",
        "",
        "[ethernet]",
        f"cloned-mac-address={setup.host_if_mac}",
        "",
        "[ipv4]",
        "method=manual",
        f"address1={setup.host_if_cidr}",
    ]
    metric = str(setup.host_route_metric).strip() if setup.host_route_metric else ""
    routes = [net for net in setup.host_routes if net.strip()]
    for n, net in enumerate(routes, start=1):
        # keyfile route syntax is dest,next-hop[,metric]. Naming the
        # metric here rather than leaning on route-metric alone keeps the
        # number visible in the file next to the route it applies to.
        suffix = f",{metric}" if metric else ""
        lines.append(f"route{n}={net},{setup.host_gw}{suffix}")
    if metric:
        # Also covers the routes NM derives rather than reads: without
        # this the connected route for host_if_cidr keeps NM's default of
        # 550 while everything beside it is at the configured metric.
        #
        # The number matters because `ip route replace` matches on
        # (destination, metric). setup and reconcile install the same
        # prefixes through `ip route`, and unless both owners use the same
        # metric neither can see -- or replace -- the other's copy, so
        # every prefix ends up installed twice.
        lines.append(f"route-metric={metric}")
    lines += [
        "never-default=true",
        "",
        "[ipv6]",
        "method=disabled",
        "",
    ]
    return "\n".join(lines)


# NetworkManager connection types that CREATE a kernel device rather than
# just configuring one that already exists. A profile of one of these
# types pointed at host-if takes the name before ovs-vswitchd can, at
# every boot, and the OVS internal port then fails to come up with
# "could not add network device ... (File exists)".
NM_DEVICE_CREATING_TYPES = ("dummy", "bridge", "bond", "team", "vlan",
                            "tun", "vxlan", "macvlan", "ip-tunnel",
                            "ovs-interface", "ovs-port", "ovs-bridge")


def _nm_conflicting_profiles(ctx: Ctx, iface: str, own_uuid: str) -> list[str]:
    """NM profiles that would create a device called `iface`.

    An ethernet profile only configures a device that already exists,
    which is why this one is safe on an OVS internal port. A profile of a
    device-creating type is not: it wins the race for the name at boot and
    leaves the OVS port with no datapath.
    """
    out = ctx.qout("nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show")
    found: list[str] = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 3:
            continue
        name, prof_uuid, prof_type = parts[0], parts[1], parts[2]
        if prof_uuid == own_uuid or prof_type not in NM_DEVICE_CREATING_TYPES:
            continue
        bound = ctx.qout("nmcli", "-g", "connection.interface-name",
                         "connection", "show", prof_uuid).strip()
        if bound == iface:
            found.append(f"{name} ({prof_type}, {prof_uuid})")
    return found


def _install_nm_profile(ctx: Ctx) -> int:
    if not ctx.have("nmcli"):
        ctx.err("nmcli not found -- NetworkManager does not appear to be "
                "installed on this host.")
        ctx.err("Use `ovnctl reconcile --install-unit` instead.")
        return 1

    setup = Setup(ctx)
    path = NM_PROFILE_DIR / f"{setup.host_if}.nmconnection"
    content = _nm_profile(setup)

    # A profile that creates the device defeats the whole arrangement, and
    # does so silently: everything downstream still looks configured while
    # ovn-controller has no ofport to bind.
    conflicts = _nm_conflicting_profiles(
        ctx, setup.host_if, str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                           f"ovnctl.{setup.host_if}")))
    if conflicts:
        ctx.err(f"Another NetworkManager profile creates a device named "
                f"'{setup.host_if}':")
        for c in conflicts:
            ctx.err(f"  {c}")
        ctx.err("It will take the name at every boot and ovs-vswitchd will not "
                "be able to create its internal port.")
        ctx.err("Delete it first: nmcli connection delete <uuid>")
        return 1

    kind = setup._link_kind()
    if kind and kind != "openvswitch":
        ctx.err(f"'{setup.host_if}' is currently a {kind} device, not an OVS "
                "internal port.")
        ctx.err("Rebuild it before installing the profile: "
                "ovnctl setup --only host-interface")
        return 1

    if not setup.host_route_metric:
        # Two owners install these prefixes: this profile and the
        # `ip route replace` in setup/reconcile. `replace` matches on
        # (destination, metric), so if they disagree -- NM's 550 for an
        # OVS internal port against the kernel's 0 -- neither can replace
        # the other and every prefix accumulates a second copy.
        ctx.warn("[setup].host_route_metric is not set, so NetworkManager "
                 "and `ip route` will install these routes at different "
                 "metrics and each prefix will end up duplicated.")
        ctx.warn("Set it (100 is a reasonable value) and re-run this.")

    ctx.dr_head("NetworkManager profile")
    if ctx.dry_run:
        print(f"cat > {path} <<'EOF'")
        print(content, end="")
        print("EOF")
        print(f"chmod 600 {path}")
        print("nmcli connection reload")
        print(f"nmcli device set {setup.host_if} managed yes")
        print(f"nmcli connection up {setup.host_if}")
        return 0

    try:
        NM_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        # NetworkManager silently ignores a keyfile that is readable by
        # anyone but root.
        os.chmod(path, 0o600)
    except OSError as exc:
        ctx.err(f"Could not write {path}: {exc}")
        return 1

    ctx.say(f"Wrote {path}")
    ctx.say(f"  address  {setup.host_if_cidr}")
    for net in setup.host_routes:
        if net.strip():
            ctx.say(f"  route    {net} via {setup.host_gw}")

    if not ctx.run("nmcli", "connection", "reload"):
        ctx.warn("nmcli connection reload failed; the profile is on disk but "
                 "NetworkManager has not picked it up yet.")
        return 1

    if not ctx.q("ip", "link", "show", "dev", setup.host_if).ok:
        ctx.say(f"{setup.host_if} does not exist yet -- run `ovnctl setup "
                "--only host-interface` to create it. NetworkManager will "
                "apply this profile as soon as it appears.")
        return 0

    dev_type = ctx.qout("nmcli", "-g", "GENERAL.TYPE", "device", "show",
                        setup.host_if).strip()
    if dev_type == "ovs-interface":
        ctx.warn(f"NetworkManager classifies {setup.host_if} as an "
                 "ovs-interface, so it will not accept this ethernet profile.")
        ctx.warn("That happens when NetworkManager's OVS plugin is loaded and "
                 "reading ovsdb.")
        ctx.warn("Use `ovnctl reconcile --install-unit` on this host instead.")
        return 1

    ctx.run("nmcli", "device", "set", setup.host_if, "managed", "yes")
    if ctx.run("nmcli", "connection", "up", setup.host_if):
        ctx.say(f"Activated {setup.host_if}; it will come up with this address "
                "and these routes at every boot.")
        # Rewriting the keyfile drops any hand-added key, but routes an
        # earlier version of it already installed in the kernel at another
        # metric are not NM's to remove. reconcile's host-interface step
        # deletes them.
        ctx.say("Run `ovnctl reconcile` now to clear any copy of these "
                "routes left in the kernel at a different metric.")
    else:
        ctx.warn(f"Could not activate {setup.host_if} now. Check: "
                 f"nmcli connection up {setup.host_if}")
        return 1
    return 0


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-reconcile")
    ctx.require_root()

    if args.install_unit:
        return _install_unit(ctx)

    if args.install_nm_profile:
        return _install_nm_profile(ctx)

    ctx.require_cmd("ovs-vsctl", "ovn-nbctl", "ip")

    cmd = Reconcile(ctx, args.repair_identity)

    if not ctx.dry_run:
        tracker = Tracker(ctx)
        if tracker.exists() and tracker.has(SETUP) \
                and tracker.from_earlier_boot(SETUP):
            ctx.log(f"Tracker was written during an earlier boot "
                    f"(now {current_boot_id()[:8]}...) -- reapplying.")

    runner = StepRunner(ctx, "reconcile")
    runner.add("external-ids", "re-assert system-id / ovn-remote / encap",
               cmd.external_ids)
    runner.add("identity", "compare the registered chassis to the configured id",
               cmd.check_identity)
    runner.add("gateway-pins", "re-point pins left on a dead chassis",
               cmd.gateway_pins)
    runner.add("host-interface", "bring host-if up, re-add its address and routes",
               cmd.host_interface)
    runner.add("claim-check", "restart ovn-controller if a tap went unclaimed",
               cmd.claim_check)
    runner.add("acl-logging", "re-assert the acl_log vlog level",
               cmd.acl_logging)
    runner.add("tracker", "stamp the tracker with this boot id",
               cmd.refresh_tracker)

    if not runner.run(args):
        return 0

    ctx.finish("runtime state reconciled")
    return 0