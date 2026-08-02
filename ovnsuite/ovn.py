"""
Thin helpers around ovn-nbctl / ovn-sbctl / ovs-vsctl.

Almost all of these are READ-ONLY queries. Mutating commands stay as
explicit ``ctx.run("ovn-nbctl", ...)`` calls in the command modules so they
remain visible in the --dry-run listing exactly as the shell version
printed them.

The one exception is ``add_acl`` below: it has a version-compatibility
fallback that two separate command modules would otherwise each have to
carry a copy of. It still goes through ctx.run, so it prints under
--dry-run like everything else.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from pathlib import Path

from .context import Ctx


# ---------------------------------------------------------------------------
# ovs-vsctl
# ---------------------------------------------------------------------------
def br_exists(ctx: Ctx, bridge: str) -> bool:
    return ctx.q("ovs-vsctl", "br-exists", bridge).ok


def list_br(ctx: Ctx) -> list[str]:
    return ctx.q("ovs-vsctl", "list-br").lines


def list_ports(ctx: Ctx, bridge: str) -> list[str]:
    return ctx.q("ovs-vsctl", "list-ports", bridge).lines


def iface_type(ctx: Ctx, iface: str) -> str:
    return ctx.qout("ovs-vsctl", "get", "interface", iface, "type").strip('"')


def external_id(ctx: Ctx, key: str) -> str:
    """A single key out of Open_vSwitch external-ids ('' if unset)."""
    res = ctx.q("ovs-vsctl", "get", "open", ".", f"external-ids:{key}")
    return res.stdout.strip('"') if res.ok else ""


def has_external_id(ctx: Ctx, key: str) -> bool:
    return ctx.q("ovs-vsctl", "get", "open", ".", f"external-ids:{key}").ok


def iface_for_iface_id(ctx: Ctx, iface_id: str) -> str:
    """The local OVS interface carrying this OVN logical port, if any."""
    out = ctx.qout("ovs-vsctl", "--bare", "--columns=name", "find", "Interface",
                   f"external-ids:iface-id={iface_id}")
    return out.splitlines()[0].strip() if out.strip() else ""


def iface_id_map(ctx: Ctx) -> dict[str, str]:
    """Every local OVS interface carrying an iface-id: iface-id -> name.

    One query for the whole table. iface_for_iface_id() is the same lookup
    for a single id; use this one when more than a couple are wanted.
    """
    rows = _json_rows(
        ctx.qout("ovs-vsctl", "--format=json", "--columns=name,external_ids",
                 "list", "Interface"), "name,external_ids")
    found: dict[str, str] = {}
    for row in rows:
        if len(row) < 2:
            continue
        for key, value in _json_map(row[1]):
            if key == "iface-id" and value:
                found.setdefault(value, str(row[0]))
    return found


def iface_id_of(ctx: Ctx, iface: str) -> str:
    res = ctx.q("ovs-vsctl", "get", "interface", iface, "external-ids:iface-id")
    return res.stdout.strip('"') if res.ok else ""


def iface_health(ctx: Ctx, iface: str) -> tuple[int, str]:
    """(ofport, error) for an OVS interface. ofport -1 means broken.

    ovs-vswitchd fills `ofport` and clears `error` only once it has really
    opened the netdev. A row can otherwise look entirely correct -- right
    name, right type, right iface-id -- while the datapath has nothing
    behind it, and ovn-controller then has no port to bind. `admin_state`
    reads as the empty set in that state rather than "down", which is easy
    to skim past; ofport is unambiguous.

    Returns (0, "") when the interface does not exist at all, so callers
    can tell "no row" from "row with no datapath".
    """
    res = ctx.q("ovs-vsctl", "--format=json", "--columns=ofport,error",
                "list", "Interface", iface)
    if not res.ok:
        return 0, ""
    rows = _json_rows(res.stdout, "ofport,error")
    if not rows or len(rows[0]) < 2:
        return 0, ""
    raw_port, raw_err = rows[0][0], rows[0][1]
    try:
        # An unset ofport renders as ["set", []]; a set one as an integer.
        ofport = int(raw_port) if not isinstance(raw_port, list) else -1
    except (TypeError, ValueError):
        ofport = -1
    error = "" if isinstance(raw_err, list) else str(raw_err or "")
    return ofport, error


def iface_is_healthy(ctx: Ctx, iface: str) -> bool:
    ofport, _ = iface_health(ctx, iface)
    return ofport > 0


def mirror_exists(ctx: Ctx, name: str) -> bool:
    out = ctx.qout("ovs-vsctl", "--bare", "--columns=_uuid", "find", "Mirror",
                   f"name={name}")
    return bool(out.strip())


# ---------------------------------------------------------------------------
# ovn-nbctl
# ---------------------------------------------------------------------------
def nb_exists(ctx: Ctx, table: str, name: str) -> bool:
    return ctx.q("ovn-nbctl", "list", table, name).ok


def lr_exists(ctx: Ctx, router: str) -> bool:
    return nb_exists(ctx, "Logical_Router", router)


def ls_exists(ctx: Ctx, switch: str) -> bool:
    return nb_exists(ctx, "Logical_Switch", switch)


def lsp_exists(ctx: Ctx, port: str) -> bool:
    return nb_exists(ctx, "Logical_Switch_Port", port)


def lrp_list(ctx: Ctx, router: str) -> str:
    return ctx.qout("ovn-nbctl", "lrp-list", router)


def lrp_present(ctx: Ctx, router: str, port: str) -> bool:
    return port in lrp_list(ctx, router)


def lsp_list(ctx: Ctx, switch: str) -> str:
    return ctx.qout("ovn-nbctl", "lsp-list", switch)


def pg_uuid(ctx: Ctx, name: str) -> str:
    return ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid", "find",
                    "Port_Group", f"name={name}").strip()


def pg_exists(ctx: Ctx, name: str) -> bool:
    return bool(pg_uuid(ctx, name))


def pg_members(ctx: Ctx, name: str) -> list[str]:
    """Port_Group.ports -- LOGICAL_SWITCH_PORT ROW UUIDS, not port names.

    Worth stating plainly, because the two are easy to confuse and the
    confusion is silent: a logical port's NAME is often itself a uuid
    string (this suite names VM ports after the VM's uuid), so comparing
    row uuids against names produces two lists that look like uuids,
    overlap not at all, and give no hint that they are different kinds of
    thing. Use pg_member_names() to compare against port names.
    """
    out = ctx.qout("ovn-nbctl", "--bare", "--columns=ports", "list",
                   "Port_Group", name)
    return out.split()


def lsp_uuid_names(ctx: Ctx) -> dict[str, str]:
    """Logical_Switch_Port row uuid -> logical port name."""
    out: dict[str, str] = {}
    for row in nb_json(ctx, "_uuid,name", "Logical_Switch_Port"):
        if len(row) < 2:
            continue
        uuids = uuid_list(row[0])
        if uuids:
            out[uuids[0]] = str(row[1] or "")
    return out


def pg_member_names(ctx: Ctx, name: str) -> list[str]:
    """The port group's members as logical port NAMES."""
    lookup = lsp_uuid_names(ctx)
    return [lookup.get(u, u) for u in pg_members(ctx, name)]


@dataclass(frozen=True)
class Acl:
    """One row of the ACL table."""

    direction: str
    priority: str
    action: str
    match: str


@dataclass
class PortGroup:
    """A Port_Group row with its references already resolved."""

    name: str
    ports: list[str]          # logical switch port NAMES, not row uuids
    acls: list[Acl]


def _uuid_list(value) -> list[str]:
    """An ovsdb reference column -- one uuid or a set of them -- as ids."""
    if isinstance(value, list) and len(value) == 2:
        if value[0] == "uuid":
            return [str(value[1])]
        if value[0] == "set":
            return [str(v[1]) for v in value[1]
                    if isinstance(v, list) and len(v) == 2 and v[0] == "uuid"]
    return []


#: Public alias -- other modules need to turn an ovsdb reference column
#: into row ids without reaching for a private name.
uuid_list = _uuid_list


def pg_snapshot(ctx: Ctx) -> dict[str, PortGroup]:
    """Every port group in the NB db, members and ACLs resolved.

    Four queries regardless of how many groups exist, rather than three per
    group. 'ports' and 'acls' are fetched separately on purpose: show.py
    records that asking for both reference columns at once returned
    unreliable results for one of them, and a silently short member list
    would read as drift that isn't there.

    Port_Group.ports holds row uuids; they are translated back to logical
    port names here because that is what the inventory and the yaml speak.
    """
    ports_rows = _json_rows(
        ctx.qout("ovn-nbctl", "--format=json", "--columns=name,ports",
                 "list", "Port_Group"), "name,ports")
    acls_rows = _json_rows(
        ctx.qout("ovn-nbctl", "--format=json", "--columns=name,acls",
                 "list", "Port_Group"), "name,acls")
    acl_rows = _json_rows(
        ctx.qout("ovn-nbctl", "--format=json",
                 "--columns=_uuid,direction,priority,action,match", "list",
                 "ACL"), "_uuid,direction,priority,action,match")
    lsp_rows = _json_rows(
        ctx.qout("ovn-nbctl", "--format=json", "--columns=_uuid,name", "list",
                 "Logical_Switch_Port"), "_uuid,name")

    lsp_name = {u: str(row[1]) for row in lsp_rows if len(row) >= 2
                for u in _uuid_list(row[0])}
    acl_by_uuid: dict[str, Acl] = {}
    for row in acl_rows:
        if len(row) < 5:
            continue
        for u in _uuid_list(row[0]):
            acl_by_uuid[u] = Acl(str(row[1] or ""), str(row[2]),
                                 str(row[3] or ""), str(row[4] or ""))

    acls_of = {str(row[0]): _uuid_list(row[1])
               for row in acls_rows if len(row) >= 2}

    groups: dict[str, PortGroup] = {}
    for row in ports_rows:
        if len(row) < 2:
            continue
        name = str(row[0])
        # An unresolvable member uuid is kept as the raw id rather than
        # dropped: a port group pointing at a deleted port is a real fault
        # and hiding it would make the group look correct.
        groups[name] = PortGroup(
            name=name,
            ports=[lsp_name.get(u, u) for u in _uuid_list(row[1])],
            acls=[acl_by_uuid[u] for u in acls_of.get(name, [])
                  if u in acl_by_uuid],
        )
    return groups


def acl_index(ctx: Ctx) -> dict[tuple[str, str, str], dict]:
    """(direction, priority, match) -> the row's presentation columns.

    That triple is what ovn-nbctl's --may-exist treats as an ACL's
    identity, so it is the right key for "have I already created this
    one, and does it carry the name, logging and meter I meant it to?".
    """
    index: dict[tuple[str, str, str], dict] = {}
    cols = "_uuid,direction,priority,match,name,log,severity,meter"
    for row in nb_json(ctx, cols, "ACL"):
        if len(row) < 8:
            continue
        uuids = uuid_list(row[0])
        if not uuids:
            continue
        key = (str(row[1] or ""), str(row[2]), str(row[3] or ""))
        index[key] = {
            "uuid": uuids[0],
            "name": _scalar(row[4]),
            "log": row[5] is True,
            "severity": _scalar(row[6]),
            "meter": _scalar(row[7]),
        }
    return index


def _scalar(value) -> str:
    """An optional ovsdb column: ['set', []] when unset, a bare value when
    set. A bare str() of the unset form yields the literal "['set', []]"."""
    if isinstance(value, list):
        if len(value) == 2 and value[0] == "set":
            return str(value[1][0]) if value[1] else ""
        return ""
    return str(value) if value is not None else ""


# ovn-nbctl grew --name for acl-add alongside the ACL table's name column.
# Probed once per process by trying it: a version check would have to map
# release numbers to behaviour, and the command itself is authoritative.
_acl_name_unsupported = False


def add_acl(ctx: Ctx, group: str, direction: str, priority, match: str,
            action: str, name: str = "", log: bool = False,
            severity: str = "", meter: str = "") -> None:
    """`ovn-nbctl acl-add` against a port group, with its presentation
    options.

    The name is what `ovnctl show` and `ovn-nbctl acl-list` print. Without
    it every rule displays as '-' and the only way to tell two ACLs apart
    is to read their match strings, which is exactly the situation the
    declarative rule names exist to avoid.

    log/severity/meter turn on ovn-controller's acl_log output for this
    one ACL. The name matters twice over once logging is on: it is the
    identifier that appears in every log line, so an unnamed logging ACL
    produces records nobody can trace back to a rule.

    Note for anyone re-reading the history here: logging was removed for a
    while on suspicion of causing ovn-controller's memory blow-up. It was
    not the cause -- a negated destination in a router policy was -- and
    logging is back. A logged drop does compile differently (see
    trace_verdict's _DROP_MARKERS) but it is not expensive.
    """
    global _acl_name_unsupported
    head = ["ovn-nbctl", "--may-exist", "--type=port-group"]
    if log:
        head.append("--log")
        if severity:
            head.append(f"--severity={severity}")
        if meter:
            head.append(f"--meter={meter}")
    tail = ["acl-add", group, direction, str(priority), match, action]

    if name and not _acl_name_unsupported:
        res = ctx.run(*head, f"--name={name}", *tail)
        if res:
            return
        # Only treat this as a version problem if the complaint is about
        # the OPTION. Testing for the word "name" anywhere in stderr was
        # far too loose: "port group name not found" contains it, so a
        # missing port group was reported as an ovn-nbctl that does not
        # support --name, and the real error never appeared.
        err = (res.stderr or "").lower()
        option_problem = any(phrase in err for phrase in (
            "unrecognized option", "unknown option", "invalid option",
            "--name",
        ))
        if not option_problem:
            ctx.warn(f"acl-add failed on {group}: "
                     f"{res.stderr.splitlines()[0] if res.stderr else '?'}")
            return
        _acl_name_unsupported = True
        ctx.warn("This ovn-nbctl does not accept --name on acl-add -- ACLs "
                 "will be created unnamed and `ovnctl show` will print '-' "
                 "in the NAME column.")

    # The unnamed path, and the retry after the above. Report failure:
    # a silent one here is how a port group ends up with no ACLs at all.
    res = ctx.run(*head, *tail)
    if not res:
        ctx.warn(f"acl-add failed on {group} ({direction} {priority}): "
                 f"{res.stderr.splitlines()[0] if res.stderr else '?'}")


def acl_list(ctx: Ctx, target: str) -> list[str]:
    return ctx.q("ovn-nbctl", "acl-list", target).lines


def policy_uuids(ctx: Ctx, priority: int | str) -> list[str]:
    out = ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid", "find",
                   "Logical_Router_Policy", f"priority={priority}")
    return [u for u in out.split() if u]


def policies_with_match(ctx: Ctx, priority: int | str) -> list[tuple[str, str]]:
    """(_uuid, match) pairs for every policy at this priority.

    ``--bare --columns=_uuid,match`` emits one value per line with a blank
    line between records, so records are paired up here rather than with
    the shell version's ``paste - -`` (which silently mis-pairs whenever a
    match contains a newline).
    """
    out = ctx.qout("ovn-nbctl", "--bare", "--columns=_uuid,match", "find",
                   "Logical_Router_Policy", f"priority={priority}")
    pairs: list[tuple[str, str]] = []
    for record in out.split("\n\n"):
        lines = [ln for ln in record.splitlines() if ln.strip()]
        if len(lines) >= 2:
            pairs.append((lines[0].strip(), lines[1].strip()))
        elif len(lines) == 1:
            pairs.append((lines[0].strip(), ""))
    return pairs


def port_security(ctx: Ctx, port: str) -> str:
    return ctx.qout("ovn-nbctl", "--bare", "--columns=port_security", "list",
                    "Logical_Switch_Port", port)


def _json_rows(out: str, columns: str) -> list[list]:
    """`--format=json` output -> rows, in the order the columns were asked for.

    ovsdb reports what it actually returned in "headings"; keying off that
    rather than trusting the order of --columns costs nothing and means a
    reordered response cannot silently shift every field by one.
    """
    if not out:
        return []
    try:
        parsed = json.loads(out)
        data = parsed.get("data", [])
        headings = parsed.get("headings", [])
    except (ValueError, AttributeError):
        return []
    want = [c.strip() for c in columns.split(",")]
    if headings and headings != want and all(c in headings for c in want):
        idx = [headings.index(c) for c in want]
        return [[row[i] if i < len(row) else "" for i in idx] for row in data]
    return data


def _json_map(value) -> list[tuple[str, str]]:
    """An ovsdb map column (['map', [[k, v], ...]]) as pairs."""
    if isinstance(value, list) and len(value) == 2 and value[0] == "map":
        return [(str(p[0]), str(p[1])) for p in value[1] if len(p) == 2]
    return []


def ref_is_set(value) -> bool:
    """True if an ovsdb reference column actually points at a row.

    JSON renders an unset reference as ['set', []] and a set one as
    ['uuid', '...']. A bare truthiness test calls the empty case True.
    """
    if isinstance(value, list) and len(value) == 2 and value[0] == "set":
        return bool(value[1])
    return bool(value)


def nb_json(ctx: Ctx, columns: str, table: str, *extra: str) -> list[list]:
    """`ovn-nbctl --format=json --columns=... list TABLE` -> rows."""
    return _json_rows(
        ctx.qout("ovn-nbctl", "--format=json", f"--columns={columns}",
                 "list", table, *extra), columns)


# ---------------------------------------------------------------------------
# ovn-sbctl
# ---------------------------------------------------------------------------
def chassis_names(ctx: Ctx) -> list[str]:
    return ctx.q("ovn-sbctl", "--bare", "--columns=name", "list", "Chassis").lines


def first_chassis(ctx: Ctx) -> str:
    """The first registered chassis name.

    DO NOT use this to decide what to pin a gateway port to. On a host that
    has drifted there may be a stale row and the 'first' one is whichever
    the db happens to return -- pinning to it is how a pin ends up
    referencing a chassis that no longer exists. Use
    identity.pin_target() instead; this stays for read-only reporting.
    """
    names = chassis_names(ctx)
    return names[0] if names else ""


def chassis_uuid_names(ctx: Ctx) -> dict[str, str]:
    """Chassis row uuid -> chassis name.

    Port_Binding.chassis is a row reference, not a name, so any check that
    wants to know WHICH chassis a port is bound to has to resolve it.
    """
    out: dict[str, str] = {}
    for row in sb_json(ctx, "_uuid,name", "Chassis"):
        if len(row) < 2:
            continue
        uuids = _uuid_list(row[0])
        if uuids:
            out[uuids[0]] = str(row[1] or "")
    return out


def port_binding_chassis(ctx: Ctx, logical_port: str) -> str:
    return ctx.qout("ovn-sbctl", "--bare", "--columns=chassis", "find",
                    "Port_Binding", f"logical_port={logical_port}").strip()


def port_binding_chassis_name(ctx: Ctx, logical_port: str) -> str:
    """The NAME of the chassis a port is bound to ('' if unbound).

    A binding row survives a reboot, so 'has a chassis' is not the same
    question as 'is bound to the chassis this host is currently running
    as'. Only the name can tell those apart.
    """
    uuid = port_binding_chassis(ctx, logical_port)
    if not uuid or uuid == "[]":
        return ""
    return chassis_uuid_names(ctx).get(uuid, uuid[:12])


def port_binding_type(ctx: Ctx, logical_port: str) -> str:
    return ctx.qout("ovn-sbctl", "--bare", "--columns=type", "find",
                    "Port_Binding", f"logical_port={logical_port}").strip()


def port_binding_ports(ctx: Ctx) -> list[str]:
    return ctx.q("ovn-sbctl", "--bare", "--columns=logical_port", "list",
                 "Port_Binding").lines


def sb_json(ctx: Ctx, columns: str, table: str, *extra: str) -> list[list]:
    """`ovn-sbctl --format=json --columns=... list TABLE` -> rows.

    Preferred over sb_records() for multi-column reads: --bare prints an
    empty column as a blank line and uses a blank line as the record
    separator too, so an empty column in the MIDDLE of the list (a VIF's
    'type', an unbound port's 'chassis') is indistinguishable from the end
    of a record. JSON has no such ambiguity.
    """
    return _json_rows(
        ctx.qout("ovn-sbctl", "--format=json", f"--columns={columns}",
                 "list", table, *extra), columns)


def sb_records(ctx: Ctx, columns: str, table: str,
               *find: str) -> list[list[str]]:
    """`ovn-sbctl --bare --columns=a,b find TABLE ...` -> list of records.

    Records are separated by blank lines and each column is on its own
    line. A VIF's 'type' column is an EMPTY STRING, which --bare prints as
    a blank line -- and a blank line is also the record separator. The
    shell version's ``awk RS=""`` split every VIF record in half because of
    this; here the record shape is reconstructed by padding short records
    instead of assuming they are well-formed.
    """
    ncols = len(columns.split(","))
    verb = "find" if find else "list"
    out = ctx.qout("ovn-sbctl", "--bare", f"--columns={columns}", verb, table,
                   *find)
    records: list[list[str]] = []
    for record in out.split("\n\n"):
        if not record.strip():
            continue
        fields = record.splitlines()
        fields += [""] * (ncols - len(fields))
        records.append([f.strip() for f in fields[:ncols]])
    return records


# ---------------------------------------------------------------------------
# ovn-controller's control socket
# ---------------------------------------------------------------------------
#: ovn-controller's log, when it is not going to the journal. ovn-ctl
#: starts it with --log-file, so the daemon's OWN messages (claiming a
#: port, refusing to, connection state) land here -- `journalctl -u
#: ovn-controller` shows only systemd's view of the unit, which is why
#: reading the journal told us nothing but "stopping / starting".
CONTROLLER_LOGS = (
    "/var/log/ovn/ovn-controller.log",
    "/var/log/openvswitch/ovn-controller.log",
)

#: `ovn-appctl -t ovn-controller` resolves the socket in OVN_RUNDIR, which
#: is not always where the socket is -- this host has
#: rundir=/var/run/openvswitch while ovn-controller's pidfile lives under
#: /run/ovn. When the name does not resolve, appctl fails and every caller
#: gets an empty answer that looks like "the controller is not talking".
CTL_DIRS = ("/run/ovn", "/var/run/ovn", "/run/openvswitch",
            "/var/run/openvswitch")


def controller_ctl(ctx: Ctx) -> str:
    """Full path to the RUNNING ovn-controller's control socket.

    Matched to the live pid, not just globbed. A controller that was
    SIGKILLed -- which is what happens when `ovn-ctl stop` times out --
    leaves its socket file behind, so the directory accumulates sockets
    belonging to dead processes. Picking one of those produces "failed to
    connect", which reads as "the controller is not answering" when in
    fact nobody asked it.
    """
    import glob
    pids = ctx.qout("pgrep", "-x", "ovn-controller", timeout=5).split()
    for pid in pids:
        for base in CTL_DIRS:
            path = f"{base}/ovn-controller.{pid}.ctl"
            if Path(path).exists():
                return path

    # No live pid, or its socket is somewhere unexpected: fall back to the
    # most RECENTLY MODIFIED socket rather than the highest-numbered one.
    # Pids wrap, so lexical order says nothing about which is current.
    candidates: list[str] = []
    for base in CTL_DIRS:
        candidates.extend(glob.glob(f"{base}/ovn-controller.*.ctl"))
    if not candidates:
        return ""
    try:
        return max(candidates, key=lambda p: Path(p).stat().st_mtime)
    except OSError:
        return candidates[-1]


def stale_ctl_sockets(ctx: Ctx) -> list[str]:
    """Socket files whose owning process no longer exists."""
    import glob
    live = set(ctx.qout("pgrep", "-x", "ovn-controller", timeout=5).split())
    stale: list[str] = []
    for base in CTL_DIRS:
        for path in glob.glob(f"{base}/ovn-controller.*.ctl"):
            pid = path.rsplit(".", 2)[-2]
            if pid not in live:
                stale.append(path)
    return stale


def appctl(ctx: Ctx, *args: object, timeout: float = 10):
    """ovn-appctl against ovn-controller, by socket PATH not by name.

    Returns the Result so callers can show stderr -- "unknown" is a
    useless thing to print when the command had something to say.
    """
    target = controller_ctl(ctx) or "ovn-controller"
    return ctx.q("ovn-appctl", "-t", target, *args, timeout=timeout)


#: Resident set above which ovn-controller is not merely busy but sick.
#: A single-chassis deployment of this size should sit in the tens of MB;
#: hundreds are unusual, gigabytes mean something is wrong inside the
#: daemon and no amount of waiting will fix it.
CONTROLLER_RSS_WARN_MB = 1024


def controller_rss_mb(ctx: Ctx) -> int:
    """ovn-controller's resident memory in MB (0 if it cannot be read).

    Worth checking before concluding "the controller is busy". Busy is a
    state it comes out of; 14 GB of RSS is a state it does not, and the
    two look identical from the outside -- slow claims, an unresponsive
    control socket, a stop that times out and gets SIGKILLed.
    """
    pid = ctx.qout("pgrep", "-x", "ovn-controller", timeout=5).split()
    if not pid:
        return 0
    try:
        status = Path(f"/proc/{pid[0]}/status").read_text(encoding="utf-8")
    except OSError:
        return 0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) // 1024
    return 0


def sb_table_sizes(ctx: Ctx) -> dict[str, int]:
    """Row counts for the SB tables that explain controller memory.

    MAC_Binding first: it grows from observed traffic rather than from
    configuration, so it is the one table that can be enormous on a
    deployment whose config is tiny -- exactly the shape to look for when
    the daemon's memory does not match the topology.
    """
    sizes: dict[str, int] = {}
    for table in ("MAC_Binding", "Logical_Flow", "Port_Binding",
                  "Datapath_Binding"):
        out = ctx.qout("ovn-sbctl", "--bare", "--columns=_uuid", "list",
                       table, timeout=20)
        sizes[table] = len([ln for ln in out.splitlines() if ln.strip()])
    return sizes


def lflow_cache_stats(ctx: Ctx) -> str:
    """ovn-controller's logical-flow cache usage.

    The cache is populated when a datapath's flows are computed, which is
    exactly what claiming the first VIF on a switch triggers. On OVN
    releases of the 22.x era it has NO memory limit by default --
    external-ids:ovn-memlimit-lflow-cache-kb is unset -- so it can grow
    until the host runs out.

    Read-only, and it may well time out on a controller that is already in
    trouble; that is itself worth reporting rather than hiding.
    """
    res = appctl(ctx, "lflow-cache/show-stats")
    if res.ok and res.stdout.strip():
        return res.stdout.strip()
    return ""


def controller_log_tail(ctx: Ctx, match: str = "", lines: int = 20) -> str:
    """The tail of ovn-controller's own log, optionally filtered."""
    for path in CONTROLLER_LOGS:
        out = ctx.qout("tail", "-n", "400", path, timeout=10)
        if not out.strip():
            continue
        rows = [ln for ln in out.splitlines()
                if not match or match in ln or "|binding|" in ln
                or "|ofctrl|" in ln or "ERR" in ln or "WARN" in ln]
        return "\n".join((rows or out.splitlines())[-lines:])
    return ""


# ---------------------------------------------------------------------------
# northd synchronisation
# ---------------------------------------------------------------------------
def sync_sb(ctx: Ctx, timeout: int = 30) -> bool:
    """Block until ovn-northd has compiled the NB db into the SB db.

    ovn-nbctl returns as soon as the Northbound db is written. northd then
    compiles that into Southbound logical flows asynchronously, and
    ovn-trace reads the SOUTHBOUND db -- so a trace run immediately after
    creating an ACL can legitimately report the behaviour from before it
    existed. That is not a flaky test, it is a race, and on a busy or
    freshly-purged db the window is comfortably long enough to hit.

    `--wait=sb sync` is the supported way to close it: it returns when
    northd has caught up with everything written so far.
    """
    res = ctx.q("ovn-nbctl", f"--timeout={timeout}", "--wait=sb", "sync",
                timeout=timeout + 5)
    if not res.ok:
        ctx.warn(f"ovn-nbctl --wait=sb sync did not complete in {timeout}s -- "
                 "northd may be down or behind.")
        ctx.warn("Any verification that follows is reading a Southbound db "
                 "that is not up to date.")
    return res.ok


# ---------------------------------------------------------------------------
# ovn-trace
# ---------------------------------------------------------------------------
#: ovn-trace walks the whole compiled pipeline, so it gets slower as the
#: deployment grows -- on a few hundred thousand flows it can take tens of
#: seconds. The default 15s query ceiling was low enough to time this out
#: routinely, and a timed-out trace produced empty output that every
#: caller then read as ALLOW.
TRACE_TIMEOUT = 60


def trace(ctx: Ctx, datapath: str, expr: str,
          timeout: float = TRACE_TIMEOUT) -> str:
    """Run ovn-trace and return combined output (stderr included).

    ovn-trace reports parse errors on stderr, and a trace that failed to
    parse -- or to finish -- must not be read as ALLOW. Pair this with
    trace_verdict, which returns UNKNOWN rather than guessing.
    """
    res = ctx.q("ovn-trace", datapath, expr, timeout=timeout)
    return "\n".join(p for p in (res.stdout, res.stderr) if p)