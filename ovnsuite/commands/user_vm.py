"""
ovnctl user-vm -- self-service VM slots on an isolated segment.

Ten slots, user-vm1 .. user-vm10, on their own switch behind lr-core:

    172.31.255.0/28   gateway 172.31.255.1   hosts .2 - .11

The policy for every slot is identical and is NOT negotiable per VM:

  * OUT to defended terrain -- allowed. Nothing matches, and the default
    route sends it to the ASA like everything else.
  * to each other -- DENIED. The slots share a subnet, and a shared subnet
    is normally the one place ACLs do not reach, so the drop is written
    against the whole segment rather than against "internal".
  * to or from our internal networks -- DENIED.
  * INBOUND management -- allowed from the management source only, on the
    protocols chosen at creation time: --ssh, --rdp, --http, --https, in
    any combination.

Only the inbound protocols are per VM, because that is the only choice
that does not weaken anyone else's isolation.

    ovnctl user-vm --create --ssh              take the next free slot
    ovnctl user-vm --create --ssh --rdp        more than one
    ovnctl user-vm --create --http --https     a web box
    ovnctl user-vm --list                      what is allocated
    ovnctl user-vm --show user-vm3             reprint its virsh XML
    ovnctl user-vm --delete user-vm3           free the slot
    ovnctl user-vm --reapply                   rebuild every slot in OVN

Allocation is recorded in state/user-vms.json. That file is the source of
truth for which slots are taken and what UUID/MAC each was given -- OVN
holds the same facts but is wiped by `delete --purge-db`, and a slot's
identity has to outlive that or the libvirt domain pointing at it breaks.
`--reapply` rebuilds OVN from the file, and `deploy` calls it.

ONE AT A TIME, deliberately. Each creation ends in a block of XML someone
has to paste into `virsh edit`, and a command that emitted three of those
at once would be a command whose output nobody reads to the end.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import netcalc, ovn, paths
from ..context import Abort, Ctx
from ..inventory import Inventory
from ..steps import StepRunner, add_step_args

NAME = "user-vm"
HELP = "allocate, wire and tear down user-supplied VM slots"

STATE_NAME = "user-vms.json"

#: QEMU/KVM's registered OUI. Using anything else works but makes the MAC
#: look like a hardware NIC in captures, which is misleading.
MAC_PREFIX = "52:54:00"

#: Inbound protocols a slot may be given, and their default TCP ports.
#: Adding one here is all it takes -- the CLI switch, the per-slot ACL, the
#: `--list` column and the teardown are all generated from this.
ACCESS_PORTS = {
    "ssh": "22",
    "rdp": "3389",
    "http": "80",
    "https": "443",
}

VIRSH_XML = """\
<interface type='bridge'>
  <source bridge='{br_int}'/>
  <virtualport type='openvswitch'>
    <parameters interfaceid='{uuid}'/>
  </virtualport>
  <target dev='{tap}'/>
  <model type='virtio'/>
  <mac address='{mac}'/>
</interface>"""


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--create", action="store_true",
                      help="allocate the next free slot")
    mode.add_argument("--list", action="store_true",
                      help="show every slot and its state")
    mode.add_argument("--show", metavar="NAME",
                      help="reprint the virsh configuration for a slot")
    mode.add_argument("--delete", metavar="NAME",
                      help="release a slot and remove its OVN port")
    mode.add_argument("--reapply", action="store_true",
                      help="rebuild every allocated slot in OVN "
                           "(after delete --purge-db)")

    # Generated from ACCESS_PORTS so the switches and the rules they
    # create cannot drift apart.
    for proto, port in ACCESS_PORTS.items():
        p.add_argument(f"--{proto}", action="store_true",
                       help=f"permit inbound {proto.upper()} (tcp/{port} by "
                            f"default) from the management source")
    p.add_argument("--label", metavar="TEXT", default="",
                   help="free-text note recorded against the slot "
                        "(whose VM it is, what it is for)")
    p.add_argument("--yes", action="store_true",
                   help="skip the confirmation prompt on --delete")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


# ---------------------------------------------------------------------------
# allocation record
# ---------------------------------------------------------------------------
class Allocations:
    """state/user-vms.json -- which slots are taken, and with what identity.

    Deliberately separate from the deployment tracker. The tracker records
    which COMMANDS have run and is erased by a teardown; this records
    identities that must survive one, because a libvirt domain on someone
    else's desk references the UUID and MAC by value.
    """

    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.path = paths.state_dir() / STATE_NAME
        self.data = self._load()

    def _load(self) -> dict:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"slots": {}}
        except (OSError, ValueError) as exc:
            raise Abort(
                f"Could not read {self.path}: {exc}\n"
                "It records which VM slots are allocated. Fix or remove it; "
                "removing it makes every slot look free and will hand out "
                "UUIDs that are already in use."
            )
        raw.setdefault("slots", {})
        return raw

    def save(self) -> None:
        if self.ctx.dry_run:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
        tmp.replace(self.path)

    def get(self, name: str) -> dict | None:
        return self.data["slots"].get(name)

    def taken(self) -> list[str]:
        return sorted(self.data["slots"], key=_slot_number)

    def put(self, name: str, record: dict) -> None:
        self.data["slots"][name] = record

    def drop(self, name: str) -> None:
        self.data["slots"].pop(name, None)


def _slot_number(name: str) -> int:
    digits = "".join(c for c in name if c.isdigit())
    return int(digits) if digits else 0


# ---------------------------------------------------------------------------
class UserVM:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.br_int = c.cfg("topology", "br_int")
        self.lr_core = c.cfg("topology", "lr_core")

        self.prefix = c.cfg_opt("user_vms", "name_prefix", "user-vm")
        self.count = int(c.cfg_opt("user_vms", "slots", "10"))
        self.subnet = c.cfg_opt("user_vms", "subnet", "172.31.255.0/28")
        self.gateway = c.cfg_opt("user_vms", "gateway", "172.31.255.1")
        self.first_ip = c.cfg_opt("user_vms", "first_ip", "172.31.255.2")
        self.switch = c.cfg_opt("user_vms", "switch", "ls-user-vm")
        self.lrp = c.cfg_opt("user_vms", "lrp", "lrp-user-vm")
        self.lrp_mac = c.cfg_opt("user_vms", "lrp_mac", "00:00:00:00:01:04")
        self.pg_name = c.cfg_opt("user_vms", "pg_name", "pg_user_vms")
        self.mgmt_src = c.cfg_opt("user_vms", "management_source",
                                  "172.31.0.0/27")
        self.drop_priority = c.cfg_opt("user_vms", "drop_priority", "1000")
        self.access_priority = c.cfg_opt("user_vms", "access_priority", "1100")
        # Deliberately above every priority [acls] uses. See segment_acls.
        self.icmp_priority = c.cfg_opt("user_vms", "icmp_priority", "3000")
        self.icmp_sources = [r for r in
                             c.cfg_opt("user_vms", "icmp_sources",
                                       "172.31.1.9,172.31.0.0/27")
                             .replace(",", " ").split() if r]

        # Per-protocol port overrides, e.g. [user_vms].port_http: 8080 for
        # a segment whose web services do not sit on 80. Defaults are the
        # well-known ports.
        self.ports = {
            proto: c.cfg_opt("user_vms", f"port_{proto}", default)
            for proto, default in ACCESS_PORTS.items()
        }

        if self.icmp_sources and int(self.icmp_priority) <= int(self.access_priority):
            raise Abort(
                f"[user_vms].icmp_priority ({self.icmp_priority}) must be "
                f"HIGHER than access_priority ({self.access_priority}).\n"
                f"The troubleshooting ping rule only works if nothing "
                f"outranks it; below the access rules it is decorative.")
        if int(self.access_priority) <= int(self.drop_priority):
            raise Abort(
                f"[user_vms].access_priority ({self.access_priority}) must be "
                f"HIGHER than drop_priority ({self.drop_priority}).\n"
                "The management rules are exceptions to the isolation drops; "
                "at or below that priority they never take effect and every "
                "slot silently becomes unreachable."
            )

        self.internal_ranges = self._load_internal_ranges()
        self.alloc = Allocations(ctx)

    def _load_internal_ranges(self) -> list[str]:
        """The same list vm-isolation blocks against.

        Read from the same place rather than duplicated, so a range added
        for one isolation mechanism is not silently missing from the other.
        """
        ctx = self.ctx
        ranges = ctx.config.cfg_array("internal_ranges", "ranges")
        if ranges:
            return ranges
        raise Abort(
            "No [internal_ranges].ranges in ovn-settings.yaml.\n"
            "The user-VM segment is defined by what it is forbidden to "
            "reach; without that list there is nothing to forbid and the "
            "slots would be wide open to the internal networks."
        )

    # ------------------------------------------------------------------
    # slot arithmetic
    # ------------------------------------------------------------------
    def next_free(self) -> str:
        taken = set(self.alloc.taken())
        for n in range(1, self.count + 1):
            name = f"{self.prefix}{n}"
            if name not in taken:
                return name
        raise Abort(
            f"All {self.count} slots are allocated.\n"
            f"Release one with `ovnctl user-vm --delete {self.prefix}N`, or "
            f"raise [user_vms].slots -- but check the subnet has room first: "
            f"{self.subnet} holds {_usable(self.subnet)} host addresses."
        )

    def ip_for(self, slot: int) -> str:
        """Slot N gets first_ip + (N-1), and must stay inside the subnet."""
        base = ipaddress.ip_address(self.first_ip)
        addr = base + (slot - 1)
        net = ipaddress.ip_network(self.subnet, strict=False)
        if addr not in net or addr == net.broadcast_address:
            raise Abort(
                f"Slot {slot} would need {addr}, which is outside "
                f"{self.subnet}.\n"
                f"[user_vms].slots ({self.count}) does not fit the subnet."
            )
        if str(addr) == self.gateway:
            raise Abort(f"Slot {slot} collides with the gateway "
                        f"{self.gateway}.")
        return str(addr)

    def new_mac(self) -> str:
        """A MAC nothing else in this deployment holds.

        Random within the QEMU OUI, generated per allocation rather than
        derived from the slot number -- a re-issued slot must not inherit
        the previous occupant's address, or a stale ARP entry somewhere
        sends the new VM's traffic to the old policy.

        Checked against the allocated slots AND the static [vm_config]
        inventory. Those VMs use the same 52:54:00 prefix, so restricting
        the check to user slots would leave 24 bits of entropy colliding
        with a namespace it cannot see. The odds are small; the failure --
        two ports with one MAC on a shared L2 -- is intermittent and
        miserable to diagnose, which is the combination worth spending ten
        lines on.
        """
        used = {r["mac"].lower() for r in self.records()}
        try:
            used |= {vm.mac.lower() for vm in Inventory(self.ctx.config).all
                     if vm.mac}
        except Abort:
            pass  # No [vm_config] at all -- nothing more to avoid.

        for _ in range(100):
            mac = MAC_PREFIX + ":" + ":".join(
                f"{random.randint(0, 255):02x}" for _ in range(3))
            if mac.lower() not in used:
                return mac
        raise Abort(
            "Could not generate an unused MAC after 100 attempts -- "
            "something is very wrong with the allocation record."
        )

    # ------------------------------------------------------------------
    # infrastructure -- idempotent, run before every mutation
    # ------------------------------------------------------------------
    def ensure_segment(self) -> None:
        ctx = self.ctx
        ctx.dr_head("User-VM segment")

        if not ovn.nb_exists(ctx, "Logical_Router", self.lr_core) \
                and not ctx.dry_run:
            raise Abort(
                f"Logical router '{self.lr_core}' does not exist.\n"
                "Run `ovnctl deploy` (or at least `ovnctl setup`) first -- "
                "the user-VM segment hangs off it."
            )

        ctx.run("ovn-nbctl", "--may-exist", "ls-add", self.switch)

        prefix = self.subnet.split("/")[1]
        cidr = f"{self.gateway}/{prefix}"
        if self.lrp not in ovn.lrp_list(ctx, self.lr_core):
            ctx.run("ovn-nbctl", "lrp-add", self.lr_core, self.lrp,
                    self.lrp_mac, cidr)

        peer = f"{self.switch}-to-lr"
        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.switch, peer)
        ctx.run("ovn-nbctl", "lsp-set-type", peer, "router")
        ctx.run("ovn-nbctl", "lsp-set-addresses", peer, "router")
        ctx.run("ovn-nbctl", "lsp-set-options", peer, f"router-port={self.lrp}")

        # NOT `--may-exist`: ovn-nbctl does not accept that option on
        # pg-add, and the whole command fails if it is passed. The port
        # group then never exists, every acl-add against it fails with
        # "port group name not found", and the segment ends up with a
        # switch and no policy. Check for existence instead -- and do NOT
        # delete-and-recreate the way acl.py does, because that would
        # discard the members and ACLs on every run.
        if not ovn.pg_exists(ctx, self.pg_name):
            ctx.run("ovn-nbctl", "pg-add", self.pg_name)
            ctx.log(f"Created port group {self.pg_name}.")
        self.segment_acls()

    def segment_acls(self) -> None:
        """The two drops every slot lives under.

        Note the destination set includes the user-VM subnet ITSELF. That
        is the part that is easy to leave out: slots share a subnet, so
        traffic between them never reaches the router and no rule about
        "internal networks" would ever see it. Without the subnet in this
        set, user-vm1 could talk to user-vm2 freely.
        """
        ctx = self.ctx
        blocked = list(self.internal_ranges)
        if self.subnet not in blocked:
            blocked.append(self.subnet)
        block_set = netcalc.set_literal(blocked)

        ovn.add_acl(ctx, self.pg_name, "from-lport", self.drop_priority,
                    f"inport == @{self.pg_name} && ip4 && "
                    f"ip4.dst == {block_set}", "drop",
                    name="uservm-drop-out", log=True, severity="info")
        ovn.add_acl(ctx, self.pg_name, "to-lport", self.drop_priority,
                    f"outport == @{self.pg_name} && ip4 && "
                    f"ip4.src == {block_set}", "drop",
                    name="uservm-drop-in", log=True, severity="info")
        ctx.log(f"Isolation ACLs on {self.pg_name} (blocking {len(blocked)} "
                "range(s), including this segment itself).")

    # ------------------------------------------------------------------
    # create
    # ------------------------------------------------------------------
    def create(self, access: list[str], label: str) -> int:
        ctx = self.ctx
        name = self.next_free()
        ip = self.ip_for(_slot_number(name))

        # Generated here and recorded, never derived. A UUID that could be
        # recomputed from the slot number would collide with the previous
        # occupant of that slot on any host that had ever used it.
        port_uuid = str(uuid.uuid4())
        mac = self.new_mac()

        self.ensure_segment()

        stale = self.ports_named(name)
        if stale:
            raise Abort(
                f"{name} is free in the tracker but {len(stale)} logical "
                f"port(s) on {self.switch} are already tagged with it:\n"
                + "\n".join(f"  {p}" for p in stale)
                + f"\n\nBuilding another would give one slot two ports and "
                f"two sets of ACLs, which is what\nan interrupted create "
                f"leaves behind: the port is wired before the tracker is\n"
                f"written, so a failure in between is invisible to "
                f"--list.\n\nClear the orphan first:\n"
                + "\n".join(f"  ovn-nbctl --if-exists lsp-del {p}"
                            for p in stale)
                + f"\n  ovnctl user-vm --reapply     "
                f"# resync {self.pg_name} membership\n"
                f"\n`ovnctl acl --verify` lists the ACLs left pointing at "
                f"it.")

        ctx.dr_head(f"Create {name}")
        self.wire_port(name, port_uuid, mac, ip, access)
        self.sync_pg_members(extra=port_uuid)

        record = {
            "name": name,
            "uuid": port_uuid,
            "mac": mac,
            "ip": ip,
            "access": access,
            "label": label,
            "created": datetime.now(timezone.utc).astimezone()
                               .isoformat(timespec="seconds"),
        }
        self.alloc.put(name, record)
        self.alloc.save()

        ctx.log(f"Allocated {name}: {ip} ({port_uuid})")
        self.print_instructions(record)
        return 0

    def ports_named(self, name: str) -> list[str]:
        """Logical ports on the segment already tagged with this slot name.

        The tracker is written after the port is wired, so an interrupted
        create leaves a port the tracker has never heard of. Asking the db
        rather than the tracker is the only way to see it.
        """
        known = {r["uuid"] for r in self.records()}
        out: list[str] = []
        for row in ovn.nb_json(self.ctx, "name,external_ids",
                               "Logical_Switch_Port"):
            if len(row) < 2 or not row[0] or row[0] in known:
                continue
            if dict(ovn._json_map(row[1])).get("vm-name") == name:
                out.append(row[0])
        return out

    def wire_port(self, name: str, port_uuid: str, mac: str, ip: str,
                  access: list[str]) -> None:
        """Create the logical port and its per-VM access rules."""
        ctx = self.ctx
        ctx.run("ovn-nbctl", "--may-exist", "lsp-add", self.switch, port_uuid)

        # CHECK these two. ctx.run does not raise, so a failure here used
        # to be silent -- and what it leaves behind is a port that exists,
        # joins the port group and is matched by the isolation ACLs, but
        # has `dynamic / unset` addresses. It can neither send nor receive,
        # and because the record is only written at the END of create(),
        # the tracker never learns about it: the next --create sees the
        # slot as free and builds a SECOND port for the same name.
        addr = ctx.run("ovn-nbctl", "lsp-set-addresses", port_uuid,
                       f"{mac} {ip}")
        # Port security is what stops a user's VM forging a source address.
        # These are machines we do not administer, on a segment whose whole
        # policy is written in terms of ip4.src -- without it, isolation is
        # a suggestion.
        sec = ctx.run("ovn-nbctl", "lsp-set-port-security", port_uuid,
                      f"{mac} {ip}")
        if not addr or not sec:
            failed = "addresses" if not addr else "port security"
            ctx.run("ovn-nbctl", "--if-exists", "lsp-del", port_uuid)
            raise Abort(
                f"Could not set {failed} on {name} ({port_uuid}).\n"
                f"The half-built port has been removed so the slot stays "
                f"free. Nothing was recorded.")
        ctx.run("ovn-nbctl", "set", "Logical_Switch_Port", port_uuid,
                f"external-ids:vm-name={name}")
        self.access_acls(name, port_uuid, access)

    def sync_pg_members(self, extra: str = "",
                        only: list[str] | None = None) -> None:
        """Set the port group's membership to exactly the allocated slots.

        NOT `--if-exists`: ovn-nbctl does not accept that option on
        pg-set-ports and rejects the whole command, which is how the group
        ended up with 35 ACLs and zero members -- every rule compiled
        against an empty group, so nothing was isolated and nothing was
        reachable. Same mistake as `--may-exist pg-add`; both were silent
        because the failure was never checked.

        Membership is set wholesale rather than added to, so a slot
        released outside this command cannot linger in the group.
        """
        ctx = self.ctx
        if only is not None:
            members = list(only)
        else:
            members = [r["uuid"] for r in self.records()]
            if extra and extra not in members:
                members.append(extra)

        res = ctx.run("ovn-nbctl", "pg-set-ports", self.pg_name, *members)
        if not res:
            ctx.warn(f"Could not set members on {self.pg_name}: "
                     f"{res.stderr.splitlines()[0] if res.stderr else '?'}")
            ctx.warn("The ACLs on that group match nothing until this "
                     "succeeds -- the slots are neither isolated nor "
                     "reachable.")
            return
        ctx.log(f"{self.pg_name} membership: {len(members)} port(s).")

    def access_acls(self, name: str, port_uuid: str,
                    access: list[str]) -> None:
        """Inbound management for this ONE port, as a single rule.

        The match names the port explicitly rather than the port group:
        every slot is in the same group, so a group-scoped rule would open
        the chosen protocol on all ten. Two slots asking for different
        protocols is the normal case, not the exception.

        Within a slot, though, the protocols differ only in tcp.dst --
        same direction, priority, action, source and outport -- so they
        collapse into one ACL with a port set, the way [acls] writes the
        FreeIPA rules. Four near-identical rows per slot was forty rows
        for ten slots, all of which had to be read to see what one slot
        could do.

        Written destructively: the slot's existing access ACLs are removed
        first. `acl-add --may-exist` keys on the MATCH, so changing a
        slot's access list would otherwise add a second rule beside the
        old one and leave both in force -- and with a port set, changing
        ANY protocol changes the match.
        """
        ctx = self.ctx
        self.del_acl_prefixed(f"{_acl_stem(name)}-")
        if not access:
            ctx.warn(f"{name} has NO management access configured. It can "
                     "reach defended terrain")
            ctx.warn("but nothing can reach it. Re-create with --ssh and/or "
                     "--rdp if that is not what you want.")
            return

        ports = [self.ports[p] for p in ACCESS_PORTS if p in access]
        dst = f"{{{','.join(ports)}}}" if len(ports) > 1 else ports[0]
        ovn.add_acl(
            ctx, self.pg_name, "to-lport", self.access_priority,
            f'outport == "{port_uuid}" && ip4 && '
            f'ip4.src == {self.mgmt_src} && tcp && tcp.dst == {dst}',
            "allow-related", name=f"{_acl_stem(name)}-access-in",
            log=True, severity="info")
        listed = ", ".join(f"{p.upper()}/{self.ports[p]}"
                           for p in ACCESS_PORTS if p in access)
        ctx.log(f"  {listed} in from {self.mgmt_src} -- allowed.")

    # ------------------------------------------------------------------
    # delete
    # ------------------------------------------------------------------
    def delete(self, name: str, assume_yes: bool) -> int:
        ctx = self.ctx
        record = self.alloc.get(name)
        if record is None:
            raise Abort(f"{name} is not allocated. `ovnctl user-vm --list` "
                        "shows what is.")

        if not assume_yes and not ctx.dry_run:
            print(f"Delete {name} ({record['ip']}, {record['uuid']})?")
            print("The libvirt domain using this interface will lose its "
                  "network.")
            if input("Type the slot name to confirm: ").strip() != name:
                ctx.log("Not confirmed -- nothing changed.")
                return 1

        ctx.dr_head(f"Delete {name}")
        # One prefix, not one per protocol. It matches the collapsed
        # rule, the old per-protocol rules and the port-suffixed ones a
        # previous version wrote, so a slot deleted after any of them
        # leaves nothing behind.
        self.del_acl_prefixed(f"{_acl_stem(name)}-")
        ctx.run("ovn-nbctl", "--if-exists", "lsp-del", record["uuid"])

        remaining = [r["uuid"] for r in self.records() if r["name"] != name]
        if remaining:
            self.sync_pg_members(only=remaining)
        else:
            # KEEP the empty port group and its ACLs.
            #
            # Deleting it left the segment half-built: ls-user-vm and
            # lrp-user-vm still there, but nothing enforcing isolation on
            # them. The next `--create` would rebuild it, but between the
            # two the switch exists with no policy at all, and `ovnctl
            # show` reports a segment with no ACLs -- which is
            # indistinguishable from having forgotten to write them.
            #
            # An empty group costs nothing: its ACLs match `@pg_user_vms`,
            # which resolves to no ports, so they compile to nothing.
            self.sync_pg_members(only=[])
            ctx.log(f"{self.pg_name} is now empty; its ACLs are kept so the "
                    "segment stays complete.")

        self.alloc.drop(name)
        self.alloc.save()
        ctx.log(f"{name} released. The slot can be re-issued; the next "
                "occupant gets a new UUID and MAC.")
        return 0

    def del_acl_prefixed(self, stem: str) -> None:
        """Remove every ACL whose name starts with this stem.

        acl-del matches on direction/priority/match, none of which are
        convenient here, so find the rows by the name we gave them.

        PREFIX, not equality. Callers pass the slot stem with its
        trailing dash, which matches the current `uservmN-access-in`, the
        older `uservmN-ssh-in` per-protocol rules, and the port-suffixed
        `uservmN-ssh-in-a1b2c3d4` form in between. A slot deleted after
        any of them leaves nothing behind.

        The trailing dash is what makes it safe: "uservm10-ssh-in" does
        not start with "uservm1-", because the next character is a digit
        and not the dash. Without it, deleting slot 1 would take slot 10's
        rules with it.
        """
        ctx = self.ctx
        for row in ovn.nb_json(ctx, "_uuid,name", "ACL"):
            if len(row) < 2 or not str(row[1] or "").startswith(stem):
                continue
            uuids = ovn.uuid_list(row[0])
            if not uuids:
                continue
            ctx.run("ovn-nbctl", "remove", "port_group", self.pg_name, "acls",
                    uuids[0])
            ctx.run("ovn-nbctl", "--if-exists", "destroy", "acl", uuids[0])
            ctx.log(f"  removed ACL {row[1]}")

    # ------------------------------------------------------------------
    # reapply / list / show
    # ------------------------------------------------------------------
    def reapply(self) -> int:
        """Rebuild every allocated slot in OVN.

        `delete --purge-db` wipes the databases but not this record, and
        the libvirt domains keep pointing at the UUIDs it holds. Without
        this, a purge silently disconnects every user VM and the only
        repair is re-creating them with new identities and editing
        somebody else's domain XML.
        """
        ctx = self.ctx
        records = self.records()
        if not records:
            # No slots. If the segment was built at some point it must
            # still be COMPLETE -- a switch with no port group is a switch
            # with no isolation, and the next slot created on it would be
            # unprotected for as long as it took someone to notice.
            if ovn.nb_exists(ctx, "Logical_Switch", self.switch):
                ctx.log(f"No slots allocated, but {self.switch} exists -- "
                        "re-asserting the segment's ACLs.")
                self.ensure_segment()
                return 0
            ctx.log(f"No slots allocated in {self.alloc.path} -- nothing to "
                    "rebuild.")
            ctx.log("The segment is created on the first "
                    "`ovnctl user-vm --create`.")
            return 0

        self.ensure_segment()
        for record in records:
            ctx.dr_head(f"Reapply {record['name']}")
            self.wire_port(record["name"], record["uuid"], record["mac"],
                           record["ip"], record.get("access", []))

        # ONCE, and only after every port exists.
        #
        # This used to run inside wire_port, i.e. once per slot. On the
        # first slot the other nine logical ports had not been created
        # yet, so pg-set-ports -- which sets membership wholesale and
        # therefore names all ten -- failed with "port UUID not found",
        # nine times, and only succeeded on the last iteration. The end
        # state was correct and the output was nine alarming warnings
        # about isolation not being applied.
        self.sync_pg_members()
        ctx.log(f"Rebuilt {len(records)} slot(s) from {self.alloc.path}.")
        return 0

    def records(self) -> list[dict]:
        return [self.alloc.data["slots"][n] for n in self.alloc.taken()]

    def list_slots(self) -> int:
        records = {r["name"]: r for r in self.records()}
        print("")
        print(f"{'SLOT':<12} {'IP':<16} {'ACCESS':<10} {'LABEL':<20} PORT UUID")
        for n in range(1, self.count + 1):
            name = f"{self.prefix}{n}"
            record = records.get(name)
            if record is None:
                print(f"{name:<12} {'-':<16} {'-':<10} {'(free)':<20} -")
                continue
            access = ",".join(record.get("access", [])) or "none"
            print(f"{name:<12} {record['ip']:<16} {access:<10} "
                  f"{(record.get('label') or '-')[:20]:<20} {record['uuid']}")
        print("")
        print(f"{len(records)}/{self.count} allocated.  "
              f"Gateway {self.gateway}, management from {self.mgmt_src}.")
        return 0

    def show(self, name: str) -> int:
        record = self.alloc.get(name)
        if record is None:
            raise Abort(f"{name} is not allocated.")
        self.print_instructions(record)
        return 0

    # ------------------------------------------------------------------
    def print_instructions(self, record: dict) -> None:
        name = record["name"]
        tap = f"vnet-{name}"
        access = record.get("access", [])
        print("")
        print("=" * 72)
        print(f" {name} -- configure the guest, then attach the interface")
        print("=" * 72)
        print("")
        print(f"  IP address   {record['ip']}/{self.subnet.split('/')[1]}")
        print(f"  Gateway      {self.gateway}")
        print(f"  MAC          {record['mac']}")
        print(f"  OVN port     {record['uuid']}")
        reach = ", ".join(f"{a.upper()}/{self.ports[a]}" for a in access
                          if a in self.ports)
        print(f"  Reachable    {reach or 'NOTHING'} from {self.mgmt_src}")
        print("")
        print(f"1. virsh edit <your-domain>  and add inside <devices>:")
        print("")
        for line in VIRSH_XML.format(br_int=self.br_int, uuid=record["uuid"],
                                     tap=tap, mac=record["mac"]).splitlines():
            print(f"      {line}")
        print("")
        print("   The interfaceid MUST be exactly the UUID above -- that is")
        print("   what binds the tap to this OVN port and therefore to this")
        print("   policy. A typo there produces a VM with no connectivity")
        print("   and no error message.")
        print("")
        print("2. Inside the guest, configure the address STATICALLY:")
        print("")
        print(f"      address  {record['ip']}/{self.subnet.split('/')[1]}")
        print(f"      gateway  {self.gateway}")
        print("")
        print("   There is no DHCP on this segment. Port security also pins")
        print(f"   the port to {record['mac']} / {record['ip']}, so a guest")
        print("   configured with any other address is dropped silently.")
        print("")
        print("3. Start the VM, then:  ovnctl vm-attach")
        print("")


# ---------------------------------------------------------------------------
def _usable(subnet: str) -> int:
    net = ipaddress.ip_network(subnet, strict=False)
    return max(net.num_addresses - 2, 0)


def _acl_stem(name: str) -> str:
    """ACL names may not contain characters OVN's lexer rejects."""
    return name.replace("-", "")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-user-vm")

    cmd = UserVM(ctx)

    if args.list:
        return cmd.list_slots()
    if args.show:
        return cmd.show(args.show)

    ctx.require_root()
    ctx.require_cmd("ovn-nbctl")

    if args.delete:
        return cmd.delete(args.delete, args.yes)
    if args.reapply:
        return cmd.reapply()
    if args.create:
        access = [p for p in ACCESS_PORTS if getattr(args, p, False)]
        if not access:
            flags = ", ".join(f"--{p}" for p in ACCESS_PORTS)
            raise Abort(
                f"Choose at least one access method: {flags}.\n"
                "A slot with none can reach defended terrain but nothing "
                "can reach it, which is almost never what is wanted. If it "
                "really is, say so explicitly by deleting the slot's access "
                "rules afterwards."
            )
        return cmd.create(access, args.label)

    return cmd.list_slots()