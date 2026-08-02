"""
ovnctl show -- port of the ovn-show tool

Cisco-style read-only views of the OVN northbound/southbound state:

    ovnctl show                 everything
    ovnctl show chassis         SB registration, gateway pins, cr- bindings
    ovnctl show routers         logical routers and their ports
    ovnctl show switches        logical switches and their ports
    ovnctl show ip-int-br       router ports and addresses
    ovnctl show interfaces      switch ports and attached VIFs
    ovnctl show route           the logical routing table
    ovnctl show policies        logical router policies (reroute rules)
    ovnctl show acls            switch-level AND port-group ACLs

Nothing here mutates anything, so it does not honour --dry-run.

The original shipped as a standalone script with shell=True string
commands; this runs everything as argv lists instead. Same output.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

from ..config import Config, ConfigError
from ..context import Abort, Colour, Ctx
from ..inventory import Inventory, user_vm_slots

NAME = "show"
HELP = "read-only views of the OVN configuration"

VIEWS = ("topology", "chassis", "routers", "switches", "ip-int-br",
         "interfaces", "route", "policies", "acls")

_ALIASES = {
    "topology": "topology", "topo": "topology", "map": "topology",
    "diagram": "topology", "show-topology": "topology",
    "chassis": "chassis", "show-chassis": "chassis",
    "routers": "routers", "router": "routers", "show-routers": "routers",
    "switches": "switches", "switch": "switches", "show-switches": "switches",
    "ip-int-br": "ip-int-br", "ip": "ip-int-br", "show-ip-int-br": "ip-int-br",
    "interfaces": "interfaces", "int": "interfaces",
    "show-interfaces": "interfaces",
    "route": "route", "routes": "route", "show-route": "route",
    "policy": "policies", "policies": "policies", "show-policies": "policies",
    "acl": "acls", "acls": "acls", "show-acls": "acls",
}


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("view", nargs="?", default="",
                   help=f"one of: {', '.join(VIEWS)} (default: all)")
    p.set_defaults(func=main)
    return p


# ---------------------------------------------------------------------------
# process + OVSDB JSON helpers
# ---------------------------------------------------------------------------
def run_cmd(argv: list[str]) -> str:
    try:
        res = subprocess.run(argv, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def nb(columns: str, table: str, *extra: str) -> str:
    return run_cmd(["ovn-nbctl", "--format=json", f"--columns={columns}",
                    "list", table, *extra])


def sb(columns: str, table: str) -> str:
    return run_cmd(["ovn-sbctl", "--format=json", f"--columns={columns}",
                    "list", table])


def rows(payload: str) -> list:
    if not payload:
        return []
    try:
        return json.loads(payload).get("data", [])
    except (ValueError, AttributeError):
        return []


def extract_ovsdb_ports(val) -> list[str]:
    """Parse OVSDB port reference sets.

    Extracts UUID hashes or named strings while filtering out the OVSDB
    metadata tuples.
    """
    if not val:
        return []
    if isinstance(val, list) and len(val) == 2 and val[0] == "set":
        items = val[1]
    elif isinstance(val, list):
        items = val
    else:
        items = [val]

    ports: list[str] = []
    for item in items:
        # OVSDB UUID tuple: ["uuid", "12345678-abcd-..."]
        if isinstance(item, list) and len(item) == 2 and item[0] == "uuid":
            ports.append(item[1])
        elif isinstance(item, str) and item != "uuid":
            ports.append(item)
    return list(dict.fromkeys(ports))


def parse_ovsdb_map(val) -> dict:
    res: dict = {}
    if isinstance(val, list) and len(val) == 2 and val[0] == "map":
        for pair in val[1]:
            if isinstance(pair, list) and len(pair) == 2:
                res[pair[0]] = pair[1]
    return res


def parse_ovsdb_bool(val, default: bool = True):
    if isinstance(val, bool):
        return val
    if isinstance(val, list):
        if len(val) == 2 and val[0] == "set":
            return val[1][0] if val[1] else default
        if not val:
            return default
    return default


def extract_ovsdb_set(val) -> list[str]:
    """Extract simple scalar arrays or sets (strings, IPs, etc.)."""
    if isinstance(val, str):
        return [val] if val != "uuid" else []
    if isinstance(val, list):
        if len(val) == 2 and val[0] in ("set", "map") and isinstance(val[1], list):
            res: list[str] = []
            for item in val[1]:
                res.extend(extract_ovsdb_set(item))
            return res
        res = []
        for item in val:
            res.extend(extract_ovsdb_set(item))
        return res
    return []


def extract_ovsdb_scalar(val, default: str = "") -> str:
    """A single scalar from either a bare value or a set-wrapped optional
    column (e.g. ACL 'name', which is a 0-or-1 set)."""
    if val is None:
        return default
    if isinstance(val, str):
        return val if val != "uuid" else default
    if isinstance(val, list):
        vals = extract_ovsdb_set(val)
        return vals[0] if vals else default
    return default


def _uuid_of(cell) -> str:
    return cell[1] if isinstance(cell, list) and len(cell) > 1 else ""


# ---------------------------------------------------------------------------
# lookup maps
# ---------------------------------------------------------------------------
def build_virsh_vm_map() -> dict[str, str]:
    """MAC addresses and tap names -> libvirt domain name."""
    vm_map: dict[str, str] = {}
    out = run_cmd(["virsh", "list", "--name", "--state-running"])
    if not out:
        return vm_map
    for vm in [v.strip() for v in out.splitlines() if v.strip()]:
        for line in run_cmd(["virsh", "domiflist", vm]).splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] != "Interface":
                vm_map[parts[4].lower()] = vm
                vm_map[parts[0]] = vm
    return vm_map


def get_lrp_details_map() -> dict:
    details: dict = {}
    for row in rows(nb("_uuid,name,networks,mac", "Logical_Router_Port")):
        nets = extract_ovsdb_set(row[2])
        info = {"name": row[1], "ip": nets[0] if nets else "unassigned",
                "mac": row[3] if row[3] else "auto"}
        details[row[1]] = info
        uuid = _uuid_of(row[0])
        if uuid:
            details[uuid] = info
    return details


def get_lsp_details_map() -> dict:
    details: dict = {}
    for row in rows(nb("_uuid,name,type,addresses,options",
                       "Logical_Switch_Port")):
        addrs = extract_ovsdb_set(row[3])
        info = {
            "name": row[1],
            "type": row[2] if row[2] else "vif",
            "addrs": " ".join(addrs) if addrs else "dynamic / unset",
            "options": parse_ovsdb_map(row[4]),
        }
        details[row[1]] = info
        uuid = _uuid_of(row[0])
        if uuid:
            details[uuid] = info
    return details


def get_port_parent_map(parent_table: str) -> dict[str, str]:
    """Port UUIDs/names -> their parent Logical Switch or Logical Router."""
    mapping: dict[str, str] = {}
    for row in rows(nb("name,ports", parent_table)):
        parent = row[0] if row[0] else "<unnamed>"
        for p in extract_ovsdb_ports(row[1]):
            mapping[p] = parent
    return mapping


def get_lrp_ip_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for row in rows(nb("name,networks", "Logical_Router_Port")):
        nets = extract_ovsdb_set(row[1])
        if nets:
            mapping[row[0]] = nets[0]
    return mapping


def get_switch_acl_map() -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for row in rows(nb("name,acls", "Logical_Switch")):
        mapping[row[0] if row[0] else "<unnamed>"] = extract_ovsdb_ports(row[1])
    return mapping


def get_acl_details_map() -> dict:
    """ACL UUID -> action/direction/match/priority/etc.

    The 'name' column is a newer addition (not present on all OVN versions)
    -- try including it first, and fall back to a query without it so this
    still works on older deployments instead of returning nothing at all.
    """
    base = "_uuid,action,direction,match,priority,log,severity"
    details: dict = {}
    for cols in (f"{base},name", base):
        data = rows(nb(cols, "ACL"))
        if not data:
            continue
        has_name = cols.endswith(",name")
        for row in data:
            details[_uuid_of(row[0])] = {
                "action": row[1] if row[1] else "unknown",
                "direction": row[2] if row[2] else "unknown",
                "match": row[3] if row[3] else "",
                "priority": row[4] if row[4] is not None else "",
                "log": parse_ovsdb_bool(row[5], default=False),
                "severity": extract_ovsdb_scalar(row[6], default=""),
                "name": (extract_ovsdb_scalar(row[7], default="")
                         if has_name and len(row) > 7 else ""),
            }
        break
    return details


def get_lsp_vm_name_map() -> dict[str, str]:
    """LSP name -> external-ids:vm-name.

    `ovnctl vm-config` tags every VM port with this for exactly this
    purpose -- a stable, always-present identifier that doesn't depend on
    virsh being available or the domain being defined yet.
    """
    mapping: dict[str, str] = {}
    for row in rows(nb("name,external_ids", "Logical_Switch_Port")):
        vm_name = parse_ovsdb_map(row[1]).get("vm-name")
        if vm_name:
            mapping[row[0]] = vm_name
    return mapping


def get_chassis_info() -> tuple[dict[str, str], list[dict]]:
    """(uuid_to_name, chassis_list) from the SB db.

    Both empty if the SB db is unreachable (not root, central down, etc.).
    """
    encap_map: dict[str, tuple[str, str]] = {}
    for row in rows(sb("_uuid,type,ip", "Encap")):
        uuid = _uuid_of(row[0])
        if uuid:
            encap_map[uuid] = (row[1] or "?", row[2] or "?")

    uuid_to_name: dict[str, str] = {}
    chassis_list: list[dict] = []
    for row in rows(sb("_uuid,name,hostname,encaps", "Chassis")):
        uuid = _uuid_of(row[0])
        name = row[1] or "<unnamed>"
        encaps = [encap_map.get(r, ("?", "?"))
                  for r in extract_ovsdb_ports(row[3])]
        if uuid:
            uuid_to_name[uuid] = name
        chassis_list.append({"name": name, "hostname": row[2] or "",
                             "encaps": encaps})
    return uuid_to_name, chassis_list


def get_port_binding_map() -> dict | None:
    """logical_port -> {"chassis": name or "", "type": t}.

    Returns None (not {}) if the SB db could not be queried at all, so
    callers can distinguish "SB unreachable" from "port genuinely unbound"
    -- conflating those two would turn every port into a false DOWN when
    the tool is run without root.
    """
    uuid_to_name, _ = get_chassis_info()
    payload = sb("logical_port,chassis,type", "Port_Binding")
    if not payload:
        return None
    mapping: dict = {}
    for row in rows(payload):
        refs = extract_ovsdb_ports(row[1])
        ch_name = uuid_to_name.get(refs[0], refs[0][:12]) if refs else ""
        mapping[row[0]] = {"chassis": ch_name,
                           "type": row[2] if row[2] else "vif"}
    return mapping


def get_gateway_chassis_pins() -> list[dict]:
    return [{"name": row[0] or "", "chassis_name": row[1] or "",
             "priority": row[2] if row[2] is not None else ""}
            for row in rows(nb("name,chassis_name,priority", "Gateway_Chassis"))]


def get_router_policies_map() -> dict[str, list[dict]]:
    """Logical Router name -> its policies (priority, match, action, nexthops)."""
    policy_to_router: dict[str, str] = {}
    router_order: list[str] = []
    for row in rows(nb("name,policies", "Logical_Router")):
        r_name = row[0] if row[0] else "<unnamed>"
        router_order.append(r_name)
        for p_uuid in extract_ovsdb_ports(row[1]):
            policy_to_router[p_uuid] = r_name

    mapping: dict[str, list[dict]] = {name: [] for name in router_order}
    for row in rows(nb("_uuid,priority,match,action,nexthop,nexthops",
                       "Logical_Router_Policy")):
        nexthop = extract_ovsdb_scalar(row[4], default="")
        nexthops = extract_ovsdb_set(row[5]) if len(row) > 5 else []
        all_nexthops = ([nexthop] if nexthop else []) + nexthops
        r_name = policy_to_router.get(_uuid_of(row[0]), "<unknown router>")
        mapping.setdefault(r_name, []).append({
            "priority": row[1] if row[1] is not None else "",
            "match": row[2] if row[2] else "",
            "action": row[3] if row[3] else "unknown",
            "nexthops": all_nexthops,
        })
    return mapping


def get_port_group_acl_map() -> dict:
    """Port_Group name -> its ACL UUIDs and member port refs.

    Port-group ACLs are a separate application mechanism from per-switch
    ACLs -- they attach to Port_Group.acls, not Logical_Switch.acls, so
    they need their own query or they are silently invisible.

    Uses --bare per column rather than one combined --format=json query:
    'ports' and 'acls' are structurally identical (both sets of UUID
    references), but the combined query was unreliable for one of them.
    """
    names_out = run_cmd(["ovn-nbctl", "--bare", "--columns=name", "list",
                         "Port_Group"])
    mapping: dict = {}
    if not names_out:
        return mapping
    for name in [n.strip() for n in names_out.splitlines() if n.strip()]:
        acls = run_cmd(["ovn-nbctl", "--bare", "--columns=acls", "list",
                        "Port_Group", name])
        ports = run_cmd(["ovn-nbctl", "--bare", "--columns=ports", "list",
                         "Port_Group", name])
        mapping[name] = {"acls": acls.split() if acls else [],
                         "ports": ports.split() if ports else []}
    return mapping


def _binding_str(port_name: str, port_type: str, pb_map: dict | None) -> str:
    """Human-readable chassis binding state for a logical switch port."""
    if pb_map is None:
        return "sb n/a"
    info = pb_map.get(port_name)
    if info is None:
        return "no binding row"
    if port_type in ("router", "localnet", "localport", "patch"):
        return "-"
    if info["chassis"]:
        return f"up @{info['chassis']}"
    return "DOWN (no chassis)"


def _acl_priority_key(r: dict) -> int:
    try:
        return int(r["priority"])
    except (TypeError, ValueError):
        return -1


_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _vm_domain(p_type: str, name: str, addr_str: str,
               virsh_vms: dict, vm_name_map: dict) -> str:
    """Correlate a port to a VM domain.

    virsh first (the actual running VM), then the vm-name tag `ovnctl
    vm-config` sets -- that still resolves even if the libvirt domain
    doesn't exist or isn't running yet.
    """
    if p_type != "vif":
        return "Host / Router"
    m = _MAC_RE.search(addr_str)
    if m:
        return virsh_vms.get(m.group(0).lower(),
                             vm_name_map.get(name, "Unknown VM"))
    return virsh_vms.get(name, vm_name_map.get(name, "Unknown VIF"))


# ---------------------------------------------------------------------------
# topology picture
# ---------------------------------------------------------------------------
# The art is written once, in box-drawing characters, and folded down to
# ASCII when the terminal cannot encode them. Every replacement is a
# single-width character, so the column arithmetic below holds either way
# -- which is the whole reason for doing it as a translation rather than
# as two separate templates that would drift apart on the first edit.
_ASCII_ART = str.maketrans({
    "─": "-", "│": "|", "┌": "+", "┐": "+", "└": "+", "┘": "+",
    "├": "+", "┤": "+", "┬": "+", "┴": "+", "┼": "+",
    "►": ">", "◄": "<", "·": "-", "▪": "*", "–": "-", "—": "-",
})

# Geometry. Every box is _CELL wide with its connector tick at _TICK,
# which is what lets the segment columns, the centre stack and the router
# bar line up without a single hand-typed run of padding. The number of
# columns is not fixed any more -- it is however many logical switches
# the db actually has -- so the widths derive from that at draw time.
_MARGIN = 4
_CELL = 24
_INNER = _CELL - 2
_GAP = 4
_TICK = 11                  # tick offset within a cell
_N_MIN = 4                  # keep the canvas this wide even when emptier


def _art_ascii_only() -> bool:
    """Can this stream actually encode the box-drawing characters?

    `ovnctl show > topology.txt` under LC_ALL=C gives a latin-1 or ascii
    stdout, and printing U+250C at it raises UnicodeEncodeError -- which
    would turn a read-only view into a traceback. Ask the stream rather
    than guessing from the locale.
    """
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "┌─┐►".encode(enc)
    except (UnicodeError, LookupError):
        return True
    return False


class _Art:
    """Fixed-width cell composer.

    Padding happens on the bare text and the colour codes are wrapped
    around the result, so the escape sequences never enter the width
    arithmetic. Doing it the other way round -- colouring first, padding
    after -- is what makes coloured ASCII art shear by nine characters the
    moment a value changes length.
    """

    def __init__(self, colour):
        self.c = colour
        self.ascii_only = _art_ascii_only()
        self.lines: list[str] = []

    def cell(self, text: str, colour: str = "", width: int = 0,
             how: str = "center") -> str:
        if width:
            text = text[:width]
            if how == "center":
                text = text.center(width)
            elif how == "left":
                text = text.ljust(width)
            else:
                text = text.rjust(width)
        if not colour:
            return text
        return colour + text + self.c.rst

    def add(self, *parts: str) -> None:
        self.lines.append("".join(parts))

    def emit(self) -> None:
        # rstrip because the connector rows are a tick plus the rest of
        # the cell's width, and a file full of trailing whitespace is a
        # file that fails everyone's linter and diffs badly.
        for line in self.lines:
            out = line.translate(_ASCII_ART) if self.ascii_only else line
            print(out.rstrip())


def _ovs_bridges() -> set[str] | None:
    """Bridge names on this host, or None if ovs-vsctl could not be run.

    None and set() are different answers: an empty result means "no
    bridges", an unreadable one means "no idea". Drawing br-internal as
    absent because ovs-vsctl is missing would be a confident lie.
    """
    payload = run_cmd(["ovs-vsctl", "--format=json", "--columns=name",
                       "list", "Bridge"])
    if not payload:
        return None
    return {r[0] for r in rows(payload) if r and isinstance(r[0], str)}


def _network_of(cidr: str) -> str:
    """The SUBNET a router port sits on, not the port's own address.

    An lrp's `networks` value is 172.31.1.17/28 -- the gateway. Printing
    that as the segment's network is the mistake everyone makes reading
    this topology, so do the masking here rather than inviting it.
    """
    try:
        import ipaddress
        return str(ipaddress.ip_interface(cidr).network)
    except (ValueError, TypeError):
        return ""


def show_topology() -> None:
    """A picture of what is actually deployed, drawn from the NB db.

    Everything here is read from OVN, not from the settings file: a box
    appears because the object exists, and disappears when it is deleted.
    That is the whole point of the view -- after `ovnctl delete` this
    should be as empty as every other section, and a half-built topology
    should look half-built rather than looking like the yaml.

    The settings file is still consulted, but only to name things that
    are expected and MISSING, which the db by definition cannot tell you.
    Those go in a footnote, never in a box.
    """
    col = Colour()
    art = _Art(col)
    OUT, LOG, TRU, ISO = col.gry, col.mag, col.cyan, col.ylw
    DIM, RST = col.dim, col.rst

    try:
        cfg = Config().load()
    except (ConfigError, OSError):
        cfg = None

    def g(section: str, key: str, default: str = "") -> str:
        return cfg.cfg_opt(section, key, default) if cfg else default

    # -- probe the db --------------------------------------------------
    ls_payload = nb("name,ports", "Logical_Switch")
    lr_payload = nb("name", "Logical_Router")
    if not ls_payload and not lr_payload:
        print("\n" + "=" * 78)
        print(" SHOW TOPOLOGY (live view, from the NB db)")
        print("=" * 78)
        print(f"{DIM}NB db unreachable -- run as root, or check "
              f"ovn-nbctl.{RST}")
        return

    sw_ports = {r[0]: extract_ovsdb_ports(r[1])
                for r in rows(ls_payload) if r and r[0]}
    routers = [r[0] for r in rows(lr_payload) if r and r[0]]
    lsp = get_lsp_details_map()
    lrp_ip = get_lrp_ip_map()
    pg_count = {r[0]: len(extract_ovsdb_ports(r[1]))
                for r in rows(nb("name,ports", "Port_Group")) if r and r[0]}
    bridges = _ovs_bridges()
    nat_rules = rows(nb("type", "NAT"))
    static = [(r[0], r[1]) for r in
              rows(nb("ip_prefix,nexthop", "Logical_Router_Static_Route"))
              if r]
    default_via = next((nh for pfx, nh in static if pfx == "0.0.0.0/0"), "")

    # vm_attach names logical ports after the libvirt domain UUID, so a
    # port's own name is unreadable in a 22-column box. The vm-name
    # external-id is the intended answer and costs one query; virsh is
    # consulted only if some port predates that tagging, and only once.
    vm_label = get_lsp_vm_name_map()
    virsh: dict[str, str] = {}
    unresolved: set[str] = set()

    def label_of(port: dict) -> str:
        name = port["name"]
        if name in vm_label:
            return vm_label[name]
        nonlocal virsh
        if not virsh:
            virsh = build_virsh_vm_map() or {"": ""}
        for token in port.get("addrs", "").split():
            hit = virsh.get(token.lower())
            if hit:
                return hit
        # Plain ASCII rather than an ellipsis: the box-drawing fallback
        # swaps characters one for one, and a 1-to-3 substitution there
        # would shear every column to the right of it.
        fallback = name if len(name) <= 16 else name[:11] + "..."
        unresolved.add(fallback)
        return fallback

    def natural(text: str) -> list:
        """Sort user-vm10 after user-vm9, not after user-vm1."""
        return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", text)]

    def ports_of(sw: str) -> list[dict]:
        return [lsp[u] for u in sw_ports.get(sw, []) if u in lsp]

    def typed(sw: str, kind: str) -> list[dict]:
        return [p for p in ports_of(sw) if p["type"] == kind]

    def gw_of(sw: str) -> tuple[str, str]:
        """(router-port name, its address) for a switch, live from the db.

        A switch with no router port is not a broken read -- it is an
        orphaned segment, which is worth seeing, so return empty strings
        and let the caller say so in the box.
        """
        rp = typed(sw, "router")
        lrp = rp[0]["options"].get("router-port", "") if rp else ""
        return lrp, lrp_ip.get(lrp, "")

    # The uplink is whichever switch owns a localnet port. Detected, not
    # assumed from the name: a rename in the yaml must not silently move
    # this box somewhere else in the picture.
    uplink = next((sw for sw in sw_ports if typed(sw, "localnet")), "")
    lr_core = routers[0] if routers else ""

    # -- decide which columns exist ------------------------------------
    # Config order first so the picture is stable between runs, then
    # anything else the db has, so an unexpected switch still shows up.
    wanted = [g("topology", "ls_host", "ls-host"),
              g("topology", "ls_int", "ls-int-vm"),
              g("topology", "ls_ext", "ls-ext-vm"),
              g("user_vms", "switch", "ls-user-vm")]
    ordered = [s for s in wanted if s and s in sw_ports and s != uplink]
    ordered += sorted(s for s in sw_ports
                      if s != uplink and s not in ordered)
    unexpected = [s for s in ordered if s not in wanted]

    # -- geometry, derived from the column count -----------------------
    n = len(ordered)
    span_cols = max(_N_MIN, n)
    bar = span_cols * _CELL + (span_cols - 1) * _GAP
    width = _MARGIN * 2 + bar
    cx = _MARGIN + (bar - _CELL) // 2
    wgap = cx - (_MARGIN + _CELL)
    group = n * _CELL + (n - 1) * _GAP if n else 0
    col_x = [_MARGIN + (bar - group) // 2 + i * (_CELL + _GAP)
             for i in range(n)]

    print("\n" + "=" * width)
    print(" SHOW TOPOLOGY (live view, from the NB db)")
    print("=" * width)

    # -- cell primitives ----------------------------------------------
    def rule(left: str, right: str, ticks, tick_ch: str,
             w: int = _CELL) -> str:
        chars = ["─"] * w
        chars[0], chars[-1] = left, right
        for t in ticks:
            chars[t] = tick_ch
        return "".join(chars)

    def c_top(colour: str, tick: bool = True) -> str:
        return art.cell(rule("┌", "┐", (_TICK,) if tick else (), "┴"), colour)

    def c_bot(colour: str, tick: bool = False) -> str:
        return art.cell(rule("└", "┘", (_TICK,) if tick else (), "┬"), colour)

    def c_txt(text: str, colour: str, tcol: str = "") -> str:
        return (art.cell("│", colour) + art.cell(text, tcol or colour, _INNER)
                + art.cell("│", colour))

    def c_stem(colour: str) -> str:
        return " " * _TICK + art.cell("│", colour) + " " * (_CELL - _TICK - 1)

    def mid(cell: str) -> None:
        art.add(" " * cx + cell)

    def col_row(cells: list[str]) -> None:
        out, at = "", 0
        for x, cell in zip(col_x, cells):
            out += " " * (x - at) + cell
            at = x + _CELL
        art.add(out)

    # -- the upper stack, only the tiers that exist --------------------
    # Assembled as a list first so each box knows whether anything sits
    # above or below it, and therefore whether to grow a connector tick.
    # Boxes that are not in the db never get added, which is what makes
    # the picture collapse after a delete instead of lying.
    br_name = g("localnet_internal", "br_internal", "br-internal")
    br_here = bridges is not None and br_name in bridges

    localnet = typed(uplink, "localnet")[0] if uplink else None
    physnet = (localnet["options"].get("network_name", "") if localnet
               else g("localnet_internal", "physnet_label", ""))
    nic = ""
    if br_here:
        nic = " ".join(p for p in run_cmd(
            ["ovs-vsctl", "list-ports", br_name]).split()
            if not p.startswith("patch-"))

    stack: list[tuple] = []
    if uplink or br_here:
        stack.append(("world", OUT, []))
    if br_here:
        stack.append(("box", OUT,
                      [br_name, " · ".join(x for x in (nic, physnet) if x)]))
    if uplink:
        up_lrp, up_ip = gw_of(uplink)
        stack.append(("box", LOG, [
            uplink,
            f"{localnet['name']} (localnet)" if localnet else "no localnet port",
            _network_of(up_ip) or "no router port"]))
    if lr_core:
        up_lrp, up_ip = gw_of(uplink) if uplink else ("", "")
        bits = [f"{up_lrp} {up_ip}" if up_lrp else "no uplink port",
                f"default 0.0.0.0/0 via {default_via}" if default_via
                else "no default route",
                "no NAT" if not nat_rules else f"{len(nat_rules)} NAT rules"]
        stack.append(("bar", LOG, [lr_core, " · ".join(bits)]))

    ws_label = g("localnet_internal", "workstation_subnet", "")
    asa = default_via or g("localnet_internal", "lan_gateway", "")

    for i, (kind, colour, lines) in enumerate(stack):
        above = i > 0
        below = i < len(stack) - 1 or (kind == "bar" and n)

        if kind == "world":
            left, right = _MARGIN, _MARGIN + bar - _CELL
            pad = " " * wgap
            art.add(" " * left, c_top(OUT, False), pad, c_top(OUT, False),
                    pad, c_top(OUT, False))
            art.add(" " * left, c_txt("workstation LAN", OUT),
                    art.cell("◄" + "─" * (wgap - 1), OUT),
                    c_txt("ASA firewall", OUT),
                    art.cell("─" * (wgap - 1) + "►", OUT),
                    c_txt("client targets", OUT))
            art.add(" " * left, c_txt(ws_label or "outside OVN", OUT),
                    pad, c_txt(asa or "?", OUT),
                    pad, c_txt("via default route", OUT))
            art.add(" " * left, c_bot(OUT, False), pad,
                    c_bot(OUT, tick=bool(below)), pad, c_bot(OUT, False))
        elif kind == "box":
            mid(c_top(colour, tick=above))
            mid(c_txt(lines[0], colour))
            for extra in lines[1:]:
                mid(c_txt(extra, colour, DIM))
            mid(c_bot(colour, tick=bool(below)))
        else:                                   # the router bar
            inner = bar - 4
            art.add(" " * _MARGIN,
                    art.cell(rule("┌", "┐", (cx + _TICK - _MARGIN,) if above
                                  else (), "┴", bar), colour))
            art.add(" " * _MARGIN, art.cell("│ ", colour),
                    col.bold + art.cell(lines[0], "", inner) + RST,
                    art.cell(" │", colour))
            art.add(" " * _MARGIN, art.cell("│ ", colour),
                    art.cell(lines[1], colour, inner), art.cell(" │", colour))
            ticks = tuple(x - _MARGIN + _TICK for x in col_x)
            art.add(" " * _MARGIN,
                    art.cell(rule("└", "┘", ticks, "┬", bar), colour))

        if below and kind != "bar":
            mid(c_stem(stack[i + 1][1]))

    # -- the segment columns -------------------------------------------
    def span(names: list[str]) -> str:
        """A range if it fits, otherwise a head count.

        Truncating "user-vm1 – user-vm10" mid-word to fit the box reads
        as a corrupted name rather than as an elided list, which is worse
        than not showing the range at all.
        """
        if not names:
            return "no ports"
        if len(names) == 1:
            return names[0]
        ranged = f"{names[0]} – {names[-1]}"
        if len(ranged) <= _INNER:
            return ranged
        return f"{names[0]} + {len(names) - 1} more"

    ls_host_n = g("topology", "ls_host", "ls-host")
    ls_ext_n = g("topology", "ls_ext", "ls-ext-vm")
    ls_user_n = g("user_vms", "switch", "ls-user-vm")
    pg_iso = g("vm_isolation", "pg_name", "pg_isolated")
    pg_user = g("user_vms", "pg_name", "pg_user_vms")
    slots = g("user_vms", "slots", "")

    cols: list[tuple] = []
    for sw in ordered:
        lrp, gw = gw_of(sw)
        vif_ports = {label_of(p): p for p in typed(sw, "vif")}
        # Ports whose name could not be resolved sort last, so one
        # untagged VIF cannot push the readable names out of the span.
        vifs = sorted(vif_ports, key=lambda x: (x in unresolved, natural(x)))
        tier = TRU if sw in (ls_host_n, g("topology", "ls_int", "ls-int-vm")) \
            else ISO
        if sw == ls_host_n and vifs:
            addrs = vif_ports[vifs[0]].get("addrs", "").split()
            members = [vifs[0], addrs[-1] if addrs else "no address",
                       "OVS internal port"]
        elif sw == ls_user_n:
            members = [span(vifs),
                       f"{len(vifs)}{'/' + slots if slots else ''} slots "
                       f"(dynamic)", pg_user if pg_user in pg_count else ""]
        elif sw == ls_ext_n:
            members = [span(vifs), f"{len(vifs)} VM ports",
                       f"{pg_count.get(pg_iso, 0)} in {pg_iso}"
                       if pg_iso in pg_count else ""]
        else:
            members = [span(vifs), f"{len(vifs)} VM ports", _network_of(gw)]
        cols.append((sw, lrp, gw, members, tier))

    if cols:
        tiers = [c[4] for c in cols]
        if lr_core:
            col_row([c_stem(LOG) for _ in cols])
        col_row([c_top(LOG, tick=bool(lr_core)) for _ in cols])
        # An orphaned switch -- one with no router port -- is drawn, not
        # hidden. It exists, so it belongs in the picture; the missing
        # gateway is flagged in amber inside the box where you will
        # actually look for it.
        left = [[sw, lrp or "no router port", f"gw {gw}" if gw else "—"]
                for sw, lrp, gw, _, _ in cols]
        for r in range(3):
            col_row([c_txt(lines[r], LOG,
                           LOG if r == 0 else (DIM if cols[i][1] else ISO))
                     for i, lines in enumerate(left)])
        col_row([c_bot(LOG, tick=True) for _ in cols])
        col_row([c_stem(t) for t in tiers])
        col_row([c_top(t) for t in tiers])
        for r in range(3):
            col_row([c_txt(m[r], t, t if r == 0 else DIM)
                     for _, _, _, m, t in cols])
        col_row([c_bot(t) for t in tiers])

    if not stack and not cols:
        art.add(f"  {DIM}Nothing deployed -- the NB db has no logical "
                f"switches or routers.{RST}")

    # -- legend and footnotes ------------------------------------------
    art.add("")
    art.add(f"  {OUT}▪{RST} outside OVN   {LOG}▪{RST} OVN logical   "
            f"{TRU}▪{RST} trusted   {ISO}▪{RST} isolated by port group")
    art.add(f"  {DIM}br-int is omitted: every VIF and host-if binds to it "
            f"locally, on every path shown.{RST}")

    expected = [g("topology", "lr_core", ""),
                g("localnet_internal", "ls_uplink", "")] + wanted
    have = set(sw_ports) | set(routers)
    absent = [x for x in expected if x and x not in have]
    if absent:
        src = "ovn-settings.yaml" if cfg else "the built-in defaults"
        art.add(f"  {col.ylw}!{RST} in {src} but NOT deployed: "
                f"{', '.join(absent)}")
        art.add(f"    {DIM}-> ovnctl deploy, or ovnctl diagnose to see "
                f"why.{RST}")
    if unexpected:
        art.add(f"  {col.ylw}!{RST} deployed but not in the settings file: "
                f"{', '.join(unexpected)}")
    if ls_user_n in sw_ports:
        tracked = len(user_vm_slots())
        live = len([p for p in typed(ls_user_n, "vif")])
        if tracked != live:
            art.add(f"  {col.ylw}!{RST} user-VM tracker and db disagree: "
                    f"{tracked} in state, {live} in OVN.")
    art.emit()


# ---------------------------------------------------------------------------
# views
# ---------------------------------------------------------------------------
def show_chassis() -> None:
    print("\n" + "=" * 110)
    print(" SHOW CHASSIS (SB registration, gateway pins, chassisredirect bindings)")
    print("=" * 110)

    _uuid_to_name, chassis_list = get_chassis_info()
    local_id = run_cmd(["ovs-vsctl", "get", "open", ".",
                        "external-ids:system-id"]).strip('"')

    if not chassis_list:
        print("No chassis registered (or SB db unreachable -- run as root?).")
        print(f"Local external-ids:system-id: {local_id or '<unset>'}")
        return

    print(f"{'CHASSIS NAME':<28} {'HOSTNAME':<24} {'ENCAP(S)':<30} "
          f"{'LOCAL MATCH':<14}")
    print("-" * 110)
    for ch in chassis_list:
        encap_str = ", ".join(f"{t}:{ip}" for t, ip in ch["encaps"]) or "-"
        match = "<-- this host" if local_id and ch["name"] == local_id else ""
        print(f"{ch['name']:<28} {ch['hostname']:<24} {encap_str:<30} "
              f"{match:<14}")

    if len(chassis_list) > 1:
        print("\n[WARN] Multiple chassis on what should be a single-node "
              "deployment --")
        print("       likely system-id drift (hostname vs FQDN across reboots).")
        print("       Gateway ports pinned to the stale name will never bind.")
    if local_id and all(ch["name"] != local_id for ch in chassis_list):
        print(f"\n[WARN] Local system-id '{local_id}' matches NO registered "
              "chassis.")

    pins = get_gateway_chassis_pins()
    registered = {ch["name"] for ch in chassis_list}
    print(f"\nGateway-chassis pins (NB): {len(pins)}")
    if pins:
        print(f"  {'PIN NAME':<34} {'PINNED CHASSIS':<28} {'PRIO':<6} "
              f"{'STATUS':<24}")
        print("  " + "-" * 96)
        for p in pins:
            status = ("registered" if p["chassis_name"] in registered
                      else "STALE -- not registered!")
            print(f"  {p['name']:<34} {p['chassis_name']:<28} "
                  f"{str(p['priority']):<6} {status:<24}")

    pb_map = get_port_binding_map()
    print("\nChassisredirect (gateway) port bindings (SB):")
    if pb_map is None:
        print("  (SB db unreachable)")
        return
    cr = {lp: i for lp, i in pb_map.items() if i["type"] == "chassisredirect"}
    if not cr:
        print("  (none exist -- fine if no localnet gateway is configured)")
        return
    for lp, info in sorted(cr.items()):
        state = (f"BOUND @{info['chassis']}" if info["chassis"]
                 else "UNBOUND -- gateway path DOWN")
        print(f"  {lp:<40} {state}")


def show_routers() -> None:
    print("\n" + "=" * 95)
    print(" SHOW ROUTERS (OVN Logical Routers & Consumed Ports)")
    print("=" * 95)
    data = rows(nb("name,ports", "Logical_Router"))
    if not data:
        print("No logical routers found.")
        return

    lrp_map = get_lrp_details_map()
    for row in data:
        r_name = row[0] if row[0] else "<unnamed>"
        port_refs = extract_ovsdb_ports(row[1])
        print(f"\nROUTER: {r_name:<25} Total Ports: {len(port_refs):<5} "
              "Status: UP/ACTIVE")
        print("  " + "-" * 91)
        print(f"  {'PORT NAME':<25} {'TYPE':<12} {'IP ADDRESS/NET':<22} "
              f"{'MAC ADDRESS':<20}")
        print("  " + "-" * 91)
        if not port_refs:
            print("  (No ports assigned)")
            continue
        for p_ref in port_refs:
            info = lrp_map.get(p_ref, {"name": p_ref, "ip": "unknown",
                                       "mac": "unknown"})
            print(f"  {info['name']:<25} {'router-port':<12} "
                  f"{info['ip']:<22} {info['mac']:<20}")


def show_switches() -> None:
    print("\n" + "=" * 105)
    print(" SHOW SWITCHES (OVN Logical Switches & Consumed Ports)")
    print("=" * 105)
    data = rows(nb("name,ports", "Logical_Switch"))
    if not data:
        print("No logical switches found.")
        return

    lsp_map = get_lsp_details_map()
    virsh_vms = build_virsh_vm_map()
    vm_name_map = get_lsp_vm_name_map()
    lrp_ips = get_lrp_ip_map()
    pb_map = get_port_binding_map()

    for row in data:
        s_name = row[0] if row[0] else "<unnamed>"
        port_refs = extract_ovsdb_ports(row[1])
        print(f"\nSWITCH: {s_name:<25} Total Ports: {len(port_refs):<5} "
              "Status: UP/ACTIVE")
        print("  " + "-" * 121)
        print(f"  {'PORT NAME':<38} {'TYPE':<10} {'VM DOMAIN':<18} "
              f"{'CHASSIS BINDING':<20} {'ADDRESSES / BINDINGS':<32}")
        print("  " + "-" * 121)
        if not port_refs:
            print("  (No logical ports assigned)")
            continue

        for p_ref in port_refs:
            info = lsp_map.get(p_ref, {"name": p_ref, "type": "vif",
                                       "addrs": "unknown", "options": {}})
            p_name, p_type = info["name"], info["type"]
            addr_str = info["addrs"]
            vm_domain = _vm_domain(p_type, p_name, addr_str, virsh_vms,
                                   vm_name_map)

            if p_type == "router":
                target = info["options"].get("router-port")
                if target and target in lrp_ips:
                    addr_str = f"{addr_str} {lrp_ips[target]} [Gateway: {target}]"
                elif target:
                    addr_str = f"{addr_str} [Gateway: {target}]"

            bind = _binding_str(p_name, p_type, pb_map)
            print(f"  {p_name:<38} {p_type:<10} {vm_domain:<18} "
                  f"{bind:<20} {addr_str:<32}")


def show_ip_int_brief() -> None:
    print("\n" + "=" * 96)
    print(" SHOW IP INT BRIEF (OVN Router Ports & Addresses)")
    print("=" * 96)

    lrp_to_router = get_port_parent_map("Logical_Router")
    pb_map = get_port_binding_map()
    data = rows(nb("_uuid,name,networks,mac,enabled", "Logical_Router_Port"))
    if not data:
        print("No router ports found.")
        return

    print(f"{'INTERFACE (LRP)':<20} {'ATTACHED TO':<20} {'IP ADDRESS':<18} "
          f"{'MAC ADDRESS':<18} {'STATUS':<22} {'GW BINDING':<26}")
    print("-" * 126)
    for row in data:
        uuid = _uuid_of(row[0])
        name = row[1]
        router = lrp_to_router.get(name, lrp_to_router.get(uuid, "unknown"))
        nets = extract_ovsdb_set(row[2])
        ip = nets[0] if nets else "unassigned"
        mac = row[3] if row[3] else "auto"
        status = ("up/up" if parse_ovsdb_bool(row[4], default=True)
                  else "administratively down")

        # Distributed LRPs have no chassisredirect port and show "-";
        # gateway-pinned LRPs get a cr-<name> Port_Binding whose chassis
        # column tells you whether the uplink path is actually alive.
        if pb_map is None:
            gw = "sb n/a"
        else:
            crb = pb_map.get(f"cr-{name}")
            if crb is None:
                gw = "-"
            elif crb["chassis"]:
                gw = f"gw bound @{crb['chassis']}"
            else:
                gw = "gw UNBOUND (path down)"

        print(f"{name:<20} {router:<20} {ip:<18} {mac:<18} {status:<22} {gw:<26}")


def show_interfaces() -> None:
    print("\n" + "=" * 115)
    print(" SHOW INTERFACES (Switch Ports & Attached Virtual Interfaces)")
    print("=" * 115)

    lsp_to_switch = get_port_parent_map("Logical_Switch")
    lrp_ips = get_lrp_ip_map()
    virsh_vms = build_virsh_vm_map()
    vm_name_map = get_lsp_vm_name_map()
    pb_map = get_port_binding_map()

    data = rows(nb("_uuid,name,type,addresses,options", "Logical_Switch_Port"))
    if not data:
        print("No logical switch ports found.")
        return

    print(f"{'PORT NAME':<38} {'ATTACHED TO':<14} {'TYPE':<8} "
          f"{'VM DOMAIN':<18} {'CHASSIS BINDING':<20} "
          f"{'ADDRESSES / BINDINGS':<35}")
    print("-" * 135)
    for row in data:
        uuid = _uuid_of(row[0])
        name = row[1]
        switch = lsp_to_switch.get(name, lsp_to_switch.get(uuid, "unknown"))
        p_type = row[2] if row[2] else "vif"
        addrs = extract_ovsdb_set(row[3])
        options = parse_ovsdb_map(row[4])
        addr_str = " ".join(addrs) if addrs else "dynamic / unset"
        vm_domain = _vm_domain(p_type, name, addr_str, virsh_vms, vm_name_map)

        if p_type == "router":
            target = options.get("router-port")
            if target and target in lrp_ips:
                addr_str = f"{addr_str} {lrp_ips[target]} [Gateway: {target}]"
            elif target:
                addr_str = f"{addr_str} [Gateway: {target}]"

        bind = _binding_str(name, p_type, pb_map)
        print(f"{name:<38} {switch:<14} {p_type:<8} {vm_domain:<18} "
              f"{bind:<20} {addr_str:<35}")


def show_route() -> None:
    print("\n" + "=" * 80)
    print(" SHOW ROUTE (OVN Logical Routing Table)")
    print("=" * 80)
    static = rows(nb("ip_prefix,nexthop,output_port,policy",
                     "Logical_Router_Static_Route"))

    print("Codes: C - connected, S - static\n")
    print(f"{'TYPE':<6} {'NETWORK/PREFIX':<22} {'NEXTHOP / PORT':<30}")
    print("-" * 60)

    for row in rows(nb("networks,name,enabled", "Logical_Router_Port")):
        if not parse_ovsdb_bool(row[2], default=True):
            continue
        for net in extract_ovsdb_set(row[0]):
            print(f"{'C':<6} {net:<22} "
                  f"{f'is directly connected, {row[1]}':<30}")

    for row in static:
        target = row[1] if row[1] else (row[2] if row[2] else "")
        print(f"{'S':<6} {row[0]:<22} {f'via {target}':<30}")


def show_policies() -> None:
    print("\n" + "=" * 130)
    print(" SHOW POLICIES (OVN Logical Router Policies -- reroute / "
          "traffic-splitting rules)")
    print("=" * 130)

    router_policies = get_router_policies_map()
    if not router_policies:
        print("No logical routers found.")
        return

    total = 0
    for r_name, policies in router_policies.items():
        print(f"\nROUTER: {r_name:<25} Total Policies: {len(policies)}")
        print("  " + "-" * 126)
        print(f"  {'PRIO':<6} {'ACTION':<10} {'NEXTHOP(S)':<20} {'MATCH':<80}")
        print("  " + "-" * 126)
        if not policies:
            print("  (No policies applied -- routing follows the static route "
                  "table only)")
            continue

        def _prio_key(p):
            try:
                return int(p["priority"])
            except (TypeError, ValueError):
                return -1

        for p in sorted(policies, key=_prio_key, reverse=True):
            nexthops = ",".join(p["nexthops"]) if p["nexthops"] else "-"
            print(f"  {str(p['priority']):<6} {p['action']:<10} "
                  f"{nexthops:<20} {p['match']:<80}")
            total += 1

    print(f"\nTotal policies across all routers: {total}")
    _show_address_sets()


def _show_address_sets() -> None:
    """Expand any $address_set referenced above.

    A match reading `ip4.dst == $as_internal` is unreadable on its own --
    the name says nothing about what is in it, and an operator has no way
    to tell a populated set from a dangling reference. Both look identical
    in the policy list, and one of them silently changes what the policy
    does.
    """
    entries = rows(nb("name,addresses", "Address_Set"))
    if not entries:
        return
    print("")
    print("Address sets referenced above:")
    for row in entries:
        if len(row) < 2:
            continue
        name = str(row[0] or "")
        addrs = extract_ovsdb_set(row[1])
        if not addrs:
            print(f"  ${name:<20} (EMPTY -- any match using it will never "
                  "match)")
            continue
        print(f"  ${name:<20} {len(addrs)} entr{'y' if len(addrs) == 1 else 'ies'}")
        for addr in sorted(addrs):
            print(f"    {addr}")


def _print_acl_rows(refs: list[str], acl_details: dict) -> int:
    print(f"  {'NAME':<20} {'PRIO':<6} {'DIRECTION':<12} {'ACTION':<10} "
          f"{'LOG':<6} {'SEVERITY':<10} {'MATCH':<50}")
    print("  " + "-" * 126)
    if not refs:
        print("  (No ACLs applied)")
        return 0

    blank = {"name": "", "action": "unknown", "direction": "unknown",
             "match": "", "priority": "", "log": False, "severity": ""}
    entries = [acl_details.get(ref, blank) for ref in refs]
    entries.sort(key=_acl_priority_key, reverse=True)
    for r in entries:
        print(f"  {r['name'] or '-':<20} "
              f"{str(r['priority']) if r['priority'] != '' else '-':<6} "
              f"{r['direction']:<12} {r['action']:<10} "
              f"{'yes' if r['log'] else 'no':<6} "
              f"{r['severity'] or '-':<10} {r['match']:<50}")
    return len(entries)


def show_acls() -> None:
    print("\n" + "=" * 130)
    print(" SHOW ACLS (OVN Logical Switch Access Control Lists)")
    print("=" * 130)

    switch_acls = get_switch_acl_map()
    acl_details = get_acl_details_map()

    if not switch_acls:
        print("No logical switches found.")
        return

    total = 0
    for s_name, refs in switch_acls.items():
        print(f"\nSWITCH: {s_name:<25} Total ACLs: {len(refs)}")
        print("  " + "-" * 126)
        total += _print_acl_rows(refs, acl_details)
    print(f"\nTotal switch-level ACLs across all switches: {total}")

    # --- Port-group ACLs (a separate application mechanism) ---
    pg_map = get_port_group_acl_map()
    if not pg_map:
        print("\nNo port groups found.")
        return

    lsp_map = get_lsp_details_map()
    vm_name_map = get_lsp_vm_name_map()
    # The switch and interface views resolve a port to the LIVE libvirt
    # domain and fall back to the vm-name tag; this view used to read the
    # tag only, so the same port appeared as two different machines
    # depending on which section you were looking at. One correlation for
    # all three.
    virsh_vms = build_virsh_vm_map()
    total_pg = 0
    for pg_name, pg_info in pg_map.items():
        refs = pg_info["acls"]
        ports = pg_info["ports"]

        member_names = []
        for p_ref in ports:
            info = lsp_map.get(p_ref)
            base = info["name"] if info else p_ref
            label = ""
            if info:
                label = _vm_domain(info["type"], base, info["addrs"],
                                   virsh_vms, vm_name_map)
                # _vm_domain's sentinels say "nothing correlated"; printing
                # them beside a uuid is worse than printing the uuid alone.
                if label == "Host / Router" or label.startswith("Unknown"):
                    label = ""
            member_names.append(f"{label} ({base})" if label else base)

        print(f"\nPORT GROUP: {pg_name:<25} Members: {len(ports)}  "
              f"Total ACLs: {len(refs)}")
        if member_names:
            # One per line. A comma-joined list of six members and their
            # uuids ran past 300 characters and wrapped wherever the
            # terminal happened to be, which made it impossible to read a
            # membership off the screen or to diff two runs of this
            # command. Sorted, because the db returns them in row order --
            # arbitrary, and it changes as ports are added and removed.
            print("  Member ports:")
            for name in sorted(member_names):
                print(f"    - {name}")
        print("  " + "-" * 126)
        total_pg += _print_acl_rows(refs, acl_details)

    print(f"\nTotal port-group ACLs across all port groups: {total_pg}")


_DISPATCH = {
    "topology": show_topology,
    "chassis": show_chassis,
    "routers": show_routers,
    "switches": show_switches,
    "ip-int-br": show_ip_int_brief,
    "interfaces": show_interfaces,
    "route": show_route,
    "policies": show_policies,
    "acls": show_acls,
}


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.prefix = "ovn-show"
    view = (args.view or "").lower().replace("_", "-")
    if not view:
        for name in VIEWS:
            _DISPATCH[name]()
        return 0

    resolved = _ALIASES.get(view)
    if resolved is None:
        print(f"Unknown view: {args.view}")
        print(f"Known views: {', '.join(VIEWS)}")
        return 1
    _DISPATCH[resolved]()
    return 0