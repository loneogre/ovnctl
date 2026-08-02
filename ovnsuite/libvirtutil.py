"""
virsh helpers.

libvirt is OPTIONAL throughout the suite. Taps are resolved from OVS by
iface-id wherever possible, because ovn-controller binds a port by matching
external-ids:iface-id on a local interface -- OVS holds the definitive
mapping, and it works on a host with no libvirt CLI at all. virsh is used
to put a human-readable domain name on things, and as a fallback for a tap
that has no iface-id set.
"""

from __future__ import annotations

from dataclasses import dataclass

from .context import Ctx


@dataclass(frozen=True)
class DomIface:
    domain: str
    tap: str
    mac: str


def available(ctx: Ctx) -> bool:
    return ctx.have("virsh")


def running_domains(ctx: Ctx) -> list[str]:
    if not available(ctx):
        return []
    return [d.strip() for d in
            ctx.q("virsh", "list", "--name", "--state-running").lines
            if d.strip()]


def domiflist(ctx: Ctx, domain: str) -> list[DomIface]:
    """Parse `virsh domiflist <domain>`.

    Output is a header line, a rule line, then rows:
        Interface  Type    Source   Model    MAC
        vnet3      bridge  br-int   virtio   52:54:00:df:c2:34
    """
    out = ctx.qout("virsh", "domiflist", domain)
    ifaces: list[DomIface] = []
    for line in out.splitlines()[2:]:
        parts = line.split()
        if not parts:
            continue
        tap = parts[0]
        if tap in ("Interface", "-", ""):
            continue
        mac = parts[-1]
        if ":" not in mac:
            continue
        ifaces.append(DomIface(domain=domain, tap=tap, mac=mac.lower()))
    return ifaces


def interfaces(ctx: Ctx) -> list[DomIface]:
    """Every interface of every running domain, in one pass."""
    out: list[DomIface] = []
    for domain in running_domains(ctx):
        out.extend(domiflist(ctx, domain))
    return out


def mac_maps(ctx: Ctx) -> tuple[dict[str, str], dict[str, str]]:
    """(mac -> tap, mac -> domain) for every running domain."""
    mac_tap: dict[str, str] = {}
    mac_domain: dict[str, str] = {}
    for iface in interfaces(ctx):
        mac_tap[iface.mac] = iface.tap
        mac_domain[iface.mac] = iface.domain
    return mac_tap, mac_domain
