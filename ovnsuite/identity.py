"""
Chassis identity -- the one piece of state that must not drift.

An OVN chassis is identified by ``external-ids:system-id`` in the local
OVS db. Everything downstream is keyed off that name: the Chassis row in
the Southbound db, every Port_Binding.chassis reference, and every
Gateway_Chassis pin in the Northbound db. Change the name and all of it
silently stops matching -- the bindings and pins still exist, they just
point at a chassis that no longer runs anything.

Two things make the name drift across a reboot, and this suite used to
walk into both:

  1. ``ovs-ctl start --system-id=random`` (how openvswitch.service is
     normally invoked) reads /etc/openvswitch/system-id.conf, generating a
     random UUID if the file is absent, and writes it into
     external-ids:system-id at EVERY boot. Whatever setup put there is
     overwritten.
  2. Falling back to ``hostname`` when no id is configured. hostname vs
     FQDN vs a DHCP-supplied name is exactly the kind of thing that
     changes underneath a machine.

So the canonical name comes from the settings file, is written to BOTH
external-ids and system-id.conf, and is re-asserted on every run rather
than only when the deployment is first built.

Everything here is safe to call repeatedly. The only destructive
operation, ``purge_stale_chassis``, is opt-in and never touches the row
belonging to the canonical name.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import ovn
from .context import Abort, Ctx, shquote

# Where ovs-ctl persists the id it will re-assert at the next boot. Writing
# external-ids without writing this file fixes the running system and
# nothing else.
SYSTEM_ID_CONF = Path("/etc/openvswitch/system-id.conf")

_UNSET_HELP = """\
[setup].system_id is empty in the settings file.

The chassis identity has to be a fixed string that survives reboots,
hostname changes and NIC replacement. There is no safe default: falling
back to the hostname is what produced the 'gateway pinned to a chassis
that no longer exists' failure this key was added to prevent.

Set something stable and re-run, e.g.:

  setup:
    system_id: ovn-host
"""


# ---------------------------------------------------------------------------
# what the name should be, and what it currently is
# ---------------------------------------------------------------------------
def configured_opt(ctx: Ctx) -> str:
    """The canonical name from the settings file ('' if unset)."""
    return (ctx.config.cfg_opt("setup", "system_id", "") or "").strip()


def configured(ctx: Ctx) -> str:
    """The canonical name, or abort with an explanation."""
    value = configured_opt(ctx)
    if not value:
        raise Abort(_UNSET_HELP)
    return value


def local(ctx: Ctx) -> str:
    """external-ids:system-id as it stands right now ('' if unset)."""
    return ovn.external_id(ctx, "system-id").strip()


def conf_file_value() -> str:
    """The id ovs-ctl will re-assert at the next boot ('' if no file)."""
    try:
        return SYSTEM_ID_CONF.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def registered(ctx: Ctx) -> list[str]:
    """Chassis names present in the Southbound db."""
    return [n for n in ovn.chassis_names(ctx) if n]


def stale(ctx: Ctx, canonical: str = "") -> list[str]:
    """Registered chassis that are NOT the canonical one.

    On a single-node deployment every such row is by definition a leftover
    identity: there is only ever one chassis, and it is this host.
    """
    canonical = canonical or configured_opt(ctx)
    if not canonical:
        return []
    return [n for n in registered(ctx) if n != canonical]


def is_registered(ctx: Ctx, name: str) -> bool:
    return bool(name) and name in registered(ctx)


# ---------------------------------------------------------------------------
# making it so
# ---------------------------------------------------------------------------
def write_system_id_conf(ctx: Ctx, value: str) -> bool:
    """Persist the id where ovs-ctl looks for it at boot.

    Returns True if the file was changed (or would be, in a dry run).
    """
    if conf_file_value() == value:
        ctx.log(f"{SYSTEM_ID_CONF} already reads '{value}'.")
        return False

    if ctx.dry_run:
        print(f"printf '%s\\n' {shquote(value)} > {SYSTEM_ID_CONF}")
        return True

    try:
        SYSTEM_ID_CONF.parent.mkdir(parents=True, exist_ok=True)
        SYSTEM_ID_CONF.write_text(f"{value}\n", encoding="utf-8")
    except OSError as exc:
        ctx.warn(f"Could not write {SYSTEM_ID_CONF}: {exc}")
        ctx.warn("ovs-ctl will overwrite external-ids:system-id at the next "
                 "boot and the identity will drift again.")
        return False
    ctx.log(f"Wrote {SYSTEM_ID_CONF} = {value}")
    ctx.changes += 1
    return True


def assert_external_ids(ctx: Ctx, canonical: str, ovn_remote: str,
                        encap_type: str, encap_ip: str) -> bool:
    """Reconcile every external-ids key this deployment depends on.

    Deliberately NOT gated on 'is ovn-remote already set'. conf.db is
    persistent, so after the first deploy that gate is always true and the
    other three keys -- system-id above all -- are never looked at again.
    Each key is compared and set individually so a re-run is quiet when
    nothing has moved and loud when something has.

    Returns True if the system-id changed, because that is the one key
    ovn-controller only reads at startup.
    """
    desired = {
        "ovn-remote": ovn_remote,
        "ovn-encap-type": encap_type,
        "ovn-encap-ip": encap_ip,
        "system-id": canonical,
    }

    changed: list[str] = []
    for key, want in desired.items():
        have = ovn.external_id(ctx, key).strip()
        if have == want:
            ctx.log(f"external-ids:{key} already '{want}'.")
            continue
        if have:
            ctx.log(f"external-ids:{key} is '{have}', setting to '{want}'.")
        else:
            ctx.log(f"external-ids:{key} unset, setting to '{want}'.")
        ctx.run("ovs-vsctl", "set", "open", ".",
                f"external-ids:{key}={want}")
        changed.append(key)

    write_system_id_conf(ctx, canonical)

    if changed:
        ctx.log(f"external-ids reconciled ({', '.join(changed)}).")
    return "system-id" in changed


def restart_controller(ctx: Ctx, reason: str = "") -> bool:
    """Restart ovn-controller so it re-reads its identity.

    ovn-controller reads external-ids:system-id once, at startup. Changing
    the key under a running controller leaves the process registered as
    the old name -- which looks fine in every check that only asks whether
    a chassis exists.
    """
    if reason:
        ctx.log(f"Restarting ovn-controller: {reason}")
    if ctx.have("systemctl") and ctx.unit_exists("ovn-controller"):
        # ovn-ctl's stop regularly fails to exit cleanly and gets
        # SIGKILLed after its own alarm; systemctl then waits on the unit.
        # Bounded so a stuck restart cannot hold a deploy open forever.
        if ctx.run("systemctl", "restart", "ovn-controller", timeout=120):
            return True
        ctx.warn("systemctl could not restart ovn-controller.")
        return False
    if ctx.have("ovn-ctl"):
        ctx.run("ovn-ctl", "stop_controller")
        return bool(ctx.run("ovn-ctl", "start_controller"))
    ctx.warn("No way to restart ovn-controller (no systemd unit, no ovn-ctl).")
    return False


def wait_for_chassis(ctx: Ctx, name: str, timeout: int = 30) -> bool:
    """Block until <name> appears in the SB db, or give up.

    Used for two different questions, both of which need patience rather
    than action: "has the controller finished starting?" and "has it
    noticed the system-id I just changed?". A restart is the last resort
    for the second one, not the first response -- see setup.external_ids
    for why an unnecessary restart is expensive.
    """
    if ctx.dry_run:
        return True
    for _ in range(timeout):
        if is_registered(ctx, name):
            return True
        time.sleep(1)
    return False


def purge_stale_chassis(ctx: Ctx, canonical: str) -> int:
    """Destroy Chassis/Chassis_Private rows that are not the canonical name.

    DESTRUCTIVE and opt-in. The controller must be stopped first or it
    re-registers the row as fast as it is deleted; callers are expected to
    stop it, call this, then start it again.

    Returns the number of rows removed.
    """
    victims = stale(ctx, canonical)
    if not victims:
        ctx.log("No stale chassis rows.")
        return 0

    removed = 0
    for name in victims:
        if ctx.run("ovn-sbctl", "--if-exists", "chassis-del", name):
            ctx.log(f"Removed stale chassis '{name}'.")
            removed += 1
        else:
            ctx.warn(f"chassis-del failed for '{name}'.")

    # chassis-del leaves Chassis_Private behind on some versions, and a
    # name containing characters the CLI won't take never matched at all.
    for table in ("Chassis", "Chassis_Private"):
        for row in ovn.sb_json(ctx, "_uuid,name", table):
            if len(row) < 2:
                continue
            name = str(row[1] or "")
            if name == canonical:
                continue
            uuids = ovn.uuid_list(row[0])
            if not uuids:
                continue
            if ctx.run("ovn-sbctl", "destroy", table, uuids[0]):
                ctx.log(f"Destroyed leftover {table} row for '{name}'.")
                removed += 1
    return removed


# ---------------------------------------------------------------------------
# gateway pins
# ---------------------------------------------------------------------------
def pin_target(ctx: Ctx) -> str:
    """The chassis a gateway port should be pinned to.

    The configured name, not 'whichever chassis happens to be registered'.
    Aborts if that name is not actually registered, because a pin to an
    unregistered chassis is a silent black hole: northd accepts it, the
    cr- port never binds, and nothing reaches the physical network.
    """
    canonical = configured(ctx)
    if is_registered(ctx, canonical):
        return canonical

    if ctx.dry_run:
        ctx.warn(f"Chassis '{canonical}' is not registered "
                 "(dry-run: continuing).")
        return canonical

    names = registered(ctx)
    detail = ("Registered right now: " + ", ".join(names)) if names \
        else "No chassis is registered at all."
    raise Abort(
        f"Chassis '{canonical}' is not registered in the Southbound db.\n"
        f"{detail}\n"
        "Pinning a gateway port to an unregistered chassis creates a pin "
        "that never binds.\n"
        "Run `ovnctl reconcile --repair-identity` first, then re-run this "
        "command."
    )


def repin_gateway(ctx: Ctx, lrp: str, chassis: str, priority) -> None:
    """Pin a router port to <chassis>, removing any pin to another one.

    lrp-set-gateway-chassis ADDS a pin; it does not replace the existing
    ones. A host that has drifted therefore ends up with both the stale
    and the correct pin, and the stale one keeps showing up in every
    audit. Old pins for this port are deleted explicitly.
    """
    for pin_name, pin_chassis in gateway_pins(ctx):
        # Pin rows are named "<lrp>-<chassis>".
        if not pin_name.startswith(f"{lrp}-"):
            continue
        if pin_chassis == chassis:
            continue
        ctx.log(f"Removing stale gateway pin {pin_name} -> {pin_chassis}.")
        ctx.run("ovn-nbctl", "--if-exists", "lrp-del-gateway-chassis", lrp,
                pin_chassis)

    ctx.run("ovn-nbctl", "lrp-set-gateway-chassis", lrp, chassis, priority)


def gateway_pins(ctx: Ctx) -> list[tuple[str, str]]:
    """Every Gateway_Chassis row as (pin name, chassis name)."""
    rows = ovn.nb_json(ctx, "name,chassis_name", "Gateway_Chassis")
    return [(str(r[0] or ""), str(r[1] or "")) for r in rows if len(r) >= 2]


def stale_pins(ctx: Ctx, canonical: str = "") -> list[tuple[str, str]]:
    """Pins that do not name the chassis this host should be running as.

    Two cases, and both matter. A pin naming an UNREGISTERED chassis is
    the obvious one: nothing binds. A pin naming a registered-but-stale
    chassis is the quieter one -- it survives right up until the stale row
    is finally cleaned up, at which point the uplink drops with no
    apparent cause. On a single-node deployment there is exactly one
    correct answer, so anything else is stale regardless of whether a row
    for it currently happens to exist.
    """
    canonical = canonical or configured_opt(ctx)
    if canonical:
        return [(n, c) for n, c in gateway_pins(ctx) if c != canonical]
    known = set(registered(ctx))
    return [(n, c) for n, c in gateway_pins(ctx) if c not in known]