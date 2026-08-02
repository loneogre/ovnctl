"""
The VM inventory, shared by vm-config, vm-attach, vm-isolation, acl, pcap
and diagnose.

Format in ovn-settings.yaml:
  [vm_config].internal_vms / external_vms   "name uuid mac ip"
  [vm_isolation].isolated_vms               "name uuid ip"   (no MAC)

Selectors accepted wherever a group of VMs is named:
  all | internal | external | isolated | all-except-isolated
  names=vm1,vm2   ips=1.2.3.4,5.6.7.8
"""

from __future__ import annotations

import json

from dataclasses import dataclass

from .config import Config
from .context import Abort


#: Where `ovnctl user-vm` records its slot allocations. Read from here by
#: anything that needs to treat those slots as ordinary VMs -- they are
#: allocated at runtime rather than declared in [vm_config], but they have
#: a name, a uuid, a MAC and an address like everything else.
USER_VM_STATE = "user-vms.json"


def user_vm_slots() -> list["VM"]:
    """Allocated user-VM slots as VM records ([] if none).

    Lives here rather than in one of the commands so that vm-attach and
    pcap read the same list. Two copies of this loader would eventually
    disagree about which slots exist, and the symptom -- a VM that is
    captured but not attached, or vice versa -- would be baffling.
    """
    from . import paths

    path = paths.state_dir() / USER_VM_STATE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[VM] = []
    for record in (data.get("slots") or {}).values():
        if not record.get("uuid") or not record.get("mac"):
            continue
        out.append(VM(name=record.get("name", "user-vm"),
                      uuid=record["uuid"], mac=record["mac"],
                      ip=record.get("ip", ""), group="user",
                      switch=record.get("switch", "")))
    return sorted(out, key=lambda v: _slot_order(v.name))


def _slot_order(name: str) -> tuple[str, int]:
    """user-vm10 sorts after user-vm9, not between 1 and 2."""
    digits = "".join(c for c in name if c.isdigit())
    return (name.rstrip("0123456789"), int(digits) if digits else 0)


@dataclass(frozen=True)
class VM:
    name: str
    uuid: str
    mac: str
    ip: str
    group: str          # "internal" | "external"
    switch: str

    @property
    def mac_lc(self) -> str:
        return self.mac.lower()


class Inventory:
    """Every VM declared in the settings file, plus isolation membership."""

    def __init__(self, cfg: Config, ls_int: str = "", ls_ext: str = ""):
        self.cfg = cfg
        self.ls_int = ls_int or cfg.cfg_opt("topology", "ls_int", "ls-int-vm")
        self.ls_ext = ls_ext or cfg.cfg_opt("topology", "ls_ext", "ls-ext-vm")

        self.internal: list[VM] = []
        self.external: list[VM] = []
        self.isolated_uuids: list[str] = []
        self.isolated_entries: list[tuple[str, str, str]] = []  # name, uuid, ip
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        for entry in self.cfg.cfg_list("vm_config", "internal_vms"):
            vm = self._parse_vm(entry, "internal", self.ls_int)
            if vm:
                self.internal.append(vm)
        for entry in self.cfg.cfg_list("vm_config", "external_vms"):
            vm = self._parse_vm(entry, "external", self.ls_ext)
            if vm:
                self.external.append(vm)
        for entry in self.cfg.cfg_list("vm_isolation", "isolated_vms"):
            parts = entry.split()
            if len(parts) >= 2:
                name, uuid = parts[0], parts[1]
                ip = parts[2] if len(parts) > 2 else ""
                self.isolated_entries.append((name, uuid, ip))
                self.isolated_uuids.append(uuid)

    @staticmethod
    def _parse_vm(entry: str, group: str, switch: str) -> VM | None:
        parts = entry.split()
        if len(parts) < 4:
            return None
        name, uuid, mac, ip = parts[0], parts[1], parts[2], parts[3]
        return VM(name=name, uuid=uuid, mac=mac, ip=ip, group=group, switch=switch)

    # ------------------------------------------------------------------
    @property
    def all(self) -> list[VM]:
        return self.internal + self.external

    @property
    def isolated(self) -> list[VM]:
        return [vm for vm in self.all if vm.uuid in self.isolated_uuids]

    @property
    def non_isolated(self) -> list[VM]:
        return [vm for vm in self.all if vm.uuid not in self.isolated_uuids]

    def by_name(self, name: str) -> VM | None:
        return next((vm for vm in self.all if vm.name == name), None)

    def by_ip(self, ip: str) -> VM | None:
        return next((vm for vm in self.all if vm.ip == ip), None)

    def by_uuid(self, uuid: str) -> VM | None:
        return next((vm for vm in self.all if vm.uuid == uuid), None)

    def by_mac(self, mac: str) -> VM | None:
        low = mac.lower()
        return next((vm for vm in self.all if vm.mac_lc == low), None)

    # ------------------------------------------------------------------
    def select(self, selector: str) -> list[VM]:
        """Resolve a selector to a list of VMs.

        Raises Abort on an unknown selector or an unresolvable name/IP --
        silently returning an empty group is how a port group ends up with
        no members and an ACL ends up applying to nothing.
        """
        sel = (selector or "").strip()
        if sel == "all":
            return list(self.all)
        if sel == "internal":
            return list(self.internal)
        if sel == "external":
            return list(self.external)
        if sel == "isolated":
            return list(self.isolated)
        if sel == "all-except-isolated":
            return list(self.non_isolated)

        if sel.startswith("names="):
            wanted = [n for n in sel[len("names="):].replace(",", " ").split() if n]
            out: list[VM] = []
            for name in wanted:
                vm = self.by_name(name)
                if vm is None:
                    raise Abort(f"No VM named '{name}' in [vm_config].")
                out.append(vm)
            return out

        if sel.startswith("ips="):
            wanted = [a for a in sel[len("ips="):].replace(",", " ").split() if a]
            out = []
            for ip in wanted:
                vm = self.by_ip(ip)
                if vm is None:
                    raise Abort(f"No VM with IP '{ip}' in [vm_config].")
                out.append(vm)
            return out

        raise Abort(f"Unknown selector '{selector}'.")