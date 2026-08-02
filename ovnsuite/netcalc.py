"""
IPv4 CIDR arithmetic (port of ovn-netcalc.sh).

Exists for one reason: the deployment declares BOTH "our internal ranges"
and "external-via-ASA ranges", and both may use RFC1918. If those two
lists intersect, a destination-based routing policy becomes ambiguous --
one prefix cannot have two next-hops. Silently absorbing that ambiguity is
the worst outcome (it presents as "that host is mysteriously
unreachable"), so every command that builds policies or ACLs calls in here
first and says so out loud.

The shell version did the arithmetic by hand; here it is stdlib
``ipaddress``, which is the same maths with the parsing edge cases already
solved. A bare IP with no prefix is still treated as /32, and a host bits
set in a prefix is still masked off rather than rejected.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Sequence


def _net(cidr: str) -> ipaddress.IPv4Network | None:
    """Parse a CIDR (or bare IP, treated as /32). None if unparseable."""
    text = str(cidr).strip()
    if not text:
        return None
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def cidr_bounds(cidr: str) -> tuple[int, int] | None:
    """(first, last) as integers, or None if the CIDR is unparseable."""
    net = _net(cidr)
    if net is None:
        return None
    return int(net.network_address), int(net.broadcast_address)


def cidr_valid(cidr: str) -> bool:
    return _net(cidr) is not None


def cidr_overlap(a: str, b: str) -> bool:
    """True if the two ranges intersect."""
    na, nb = _net(a), _net(b)
    if na is None or nb is None:
        return False
    return na.overlaps(nb)


def cidr_contains(outer: str, inner: str) -> bool:
    """True if `inner` is fully contained by `outer`."""
    no, ni = _net(outer), _net(inner)
    if no is None or ni is None:
        return False
    return int(ni.network_address) >= int(no.network_address) and \
        int(ni.broadcast_address) <= int(no.broadcast_address)


def cidr_describe_overlap(a: str, b: str) -> str:
    """The intersecting range, as 'first - last'. Empty if disjoint."""
    ba, bb = cidr_bounds(a), cidr_bounds(b)
    if ba is None or bb is None:
        return ""
    lo = max(ba[0], bb[0])
    hi = min(ba[1], bb[1])
    if lo > hi:
        return ""
    return f"{ipaddress.IPv4Address(lo)} - {ipaddress.IPv4Address(hi)}"


def find_overlaps(list_a: Sequence[str],
                  list_b: Sequence[str]) -> list[tuple[str, str, str]]:
    """Every colliding pair as (a, b, intersecting-range).

    Empty list means the two range lists are disjoint.
    """
    found: list[tuple[str, str, str]] = []
    for x in list_a:
        if not str(x).strip():
            continue
        for y in list_b:
            if not str(y).strip():
                continue
            if cidr_overlap(x, y):
                found.append((x, y, cidr_describe_overlap(x, y)))
    return found


def validate_ranges(ranges: Iterable[str], label: str) -> list[str]:
    """Return the entries that are NOT valid IPv4 CIDRs."""
    bad: list[str] = []
    for r in ranges:
        if not str(r).strip():
            continue
        if not cidr_valid(r):
            bad.append(r)
    del label  # caller formats the message; kept for signature parity
    return bad


def ip_in_ranges(ip: str, ranges: Iterable[str]) -> bool:
    """True if the IP falls inside any entry."""
    return any(cidr_contains(r, ip) for r in ranges if str(r).strip())


def set_literal(items: Sequence[str]) -> str:
    """Build an OVN address-set literal '{a, b, c}' from a list."""
    return "{" + ",".join(str(i) for i in items) + "}"
