"""
ovnctl acl --audit -- conformance test for the ACLs in ovn-settings.yaml.

Every rule in [acls].rules is a test case. The expected match string is
rebuilt with ACLManager.build_match -- the same code that deploys it -- so
the audit cannot pass a rule that the deployer would write differently. A
separate reimplementation here would agree with the yaml and disagree with
reality, which is the one failure mode an audit must not have.

Three questions, in order:

  1. Is the configuration itself sound? Direction, priority range, action,
     port-set and port-group references, CIDR syntax, priority collisions.
     No db access -- a rule that cannot be right is worth catching before
     asking whether it is deployed.
  2. Is every configured rule in the Northbound db, with the same
     direction, priority, action and match?
  3. Does the db hold anything the configuration does not account for?
     An ACL nobody declared is policy nobody reviewed. This matters more
     than it looks: the deployer uses `acl-add --may-exist`, so EDITING a
     rule's match adds a second ACL and leaves the original in force. The
     old one is invisible to every other command in the suite.

Output contract: a pass is one line. A failure prints what was expected,
what is actually there, and the command that fixes it, because whoever
reads the failure is usually not whoever wrote the rule.

Exit status is 1 if any check failed, so this can gate a deployment.
"""

from __future__ import annotations

from .. import netcalc, ovn
from ..context import Abort, Colour, Ctx

_DIRECTIONS = ("to-lport", "from-lport")
_ACTIONS = ("allow", "allow-related", "allow-stateless", "drop", "reject")
_PRIO_MIN, _PRIO_MAX = 0, 32767

# Tokens build_match() understands but that carry no operand.
_BARE_SPECS = ("icmp", "any", "src=any", "dst=any")


def _norm(match: str) -> str:
    """Whitespace-insensitive form of a match string.

    ovn-nbctl stores the match exactly as given, so a hand-written ACL can
    differ from a generated one by spacing alone. That is worth reporting,
    but not as the same failure as a genuinely different rule.
    """
    return " ".join(match.split())


def _first_diff(a: str, b: str) -> int:
    """1-based column where two strings first differ."""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i + 1
    return min(len(a), len(b)) + 1


def _join(items: list[str], limit: int = 6) -> str:
    if not items:
        return "(none)"
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", ... (+{len(items) - limit} more)"


class ACLAudit:
    """Compares [acls] in the settings file against the Northbound db."""

    def __init__(self, mgr) -> None:
        self.mgr = mgr
        self.ctx: Ctx = mgr.ctx
        self.c = Colour()
        self.passes = 0
        self.failures = 0
        self.warnings = 0
        self._matches: dict[int, str | None] = {}

        # Port groups this file does not own. vm_isolation creates and
        # manages its own group, and it is not drift just because [acls]
        # has never heard of it -- telling someone to pg-del it would tear
        # down the isolation policy.
        cfg = self.ctx.config
        owned_elsewhere = cfg.cfg_opt("vm_isolation", "pg_name", "").strip()
        self.foreign_pgs = {owned_elsewhere} if owned_elsewhere else set()
        # These, by contrast, are meant to be gone: vm_isolation deletes
        # them on every apply.
        self.legacy_pgs = [p.strip() for p
                           in cfg.cfg_list("vm_isolation", "legacy_pg_names")
                           if p.strip() and p.strip() not in self.foreign_pgs]

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------
    def section(self, title: str) -> None:
        print(f"\n{self.c.bold}--- {title} ---{self.c.rst}")

    def ok(self, label: str, extra: str = "") -> None:
        c = self.c
        line = f"{c.grn}[ OK ]{c.rst} {label}"
        if extra:
            line += f"  {c.dim}{extra}{c.rst}"
        print(line)
        self.passes += 1

    def fail(self, label: str, *detail: str) -> None:
        c = self.c
        print(f"{c.red}{c.bold}[FAIL]{c.rst} {label}")
        for line in detail:
            print(f"       {line}")
        self.failures += 1

    def warn(self, label: str, *detail: str) -> None:
        c = self.c
        print(f"{c.ylw}[WARN]{c.rst} {label}")
        for line in detail:
            print(f"       {line}")
        self.warnings += 1

    def skip(self, label: str) -> None:
        print(f"{self.c.dim}[SKIP]{self.c.rst} {label}")

    # ------------------------------------------------------------------
    def run(self) -> int:
        c = self.c
        print(f"\n{c.bold}=== ACL audit: ovn-settings.yaml vs OVN Northbound "
              f"==={c.rst}")
        print(f"      settings: {self.ctx.cfg_file}")

        rules = self.mgr.parsed_rules()
        db = ovn.pg_snapshot(self.ctx)

        if not self.mgr.enabled:
            self._audit_disabled(db)
        else:
            self._check_syntax(rules, db)
            self._check_groups(db)
            self._check_rules(rules, db)
            self._check_drift(rules, db)
        return self._summary()

    # ------------------------------------------------------------------
    # 0. acls.enabled is false -- the expectation inverts
    # ------------------------------------------------------------------
    def _audit_disabled(self, db: dict) -> None:
        self.section("acls.enabled is false -- expecting nothing deployed")
        declared = [pg for pg, _sel in self.mgr.group_defs if pg]
        live = [pg for pg in declared if pg in db]
        if not live:
            self.ok("no ACL port groups in the db",
                    "consistent with acls.enabled: false")
            return
        for pg in live:
            group = db[pg]
            # Named explicitly, one group at a time. There is no longer a
            # flag that clears the lot -- see the note in acl.py's
            # register() -- and a remedy line is not the place to hand
            # someone a shortcut past that.
            self.fail(f"{pg} is still deployed",
                      "acls.enabled is false, but this port group is present "
                      "and its ACLs are still being enforced.",
                      f"members     {len(group.ports)}",
                      f"acls        {len(group.acls)}",
                      f"remedy      ovn-nbctl pg-del {pg}")

    # ------------------------------------------------------------------
    # 1. is the configuration sound?
    # ------------------------------------------------------------------
    def _check_syntax(self, rules: list, db: dict) -> None:
        self.section(f"rule syntax ({len(rules)} rule(s))")
        if not rules:
            self.skip("no rules declared in acls.rules")
            return

        declared = {pg for pg, _sel in self.mgr.group_defs if pg}
        first_named: dict[str, int] = {}
        slots: dict[tuple[str, str, str], list[tuple[str, str]]] = {}

        for rule in rules:
            if rule.error:
                self.fail(f"acls.rules[{rule.index}]", rule.error,
                          f'rule:  "{rule.raw}"')
                continue

            problems: list[str] = []
            if rule.direction not in _DIRECTIONS:
                problems.append(
                    f"direction '{rule.direction}' is not one of "
                    f"{' / '.join(_DIRECTIONS)}")
            if not rule.priority.isdigit() or \
                    not _PRIO_MIN <= int(rule.priority) <= _PRIO_MAX:
                problems.append(
                    f"priority '{rule.priority}' is not an integer in "
                    f"{_PRIO_MIN}..{_PRIO_MAX}")
            if rule.action not in _ACTIONS:
                problems.append(
                    f"action '{rule.action}' is not one of "
                    f"{' / '.join(_ACTIONS)}")
            if rule.group not in declared:
                if rule.group in self.foreign_pgs:
                    problems.append(
                        f"targets port group '{rule.group}', which belongs to "
                        "[vm_isolation] -- its membership is managed there, "
                        "and `ovnctl vm-isolation` recreates it, dropping any "
                        "ACL attached here")
                elif rule.group in db:
                    problems.append(
                        f"targets port group '{rule.group}', which exists in "
                        "the db but is not declared in acls.port_groups -- "
                        "its membership is not managed here")
                else:
                    problems.append(
                        f"targets port group '{rule.group}', which is not "
                        "declared in acls.port_groups")
            for spec in rule.specs:
                problems.extend(self._spec_problems(spec))

            if rule.name in first_named:
                self.warn(f"{rule.name}",
                          f"duplicate rule name, also at "
                          f"acls.rules[{first_named[rule.name]}]",
                          "Both are applied; the name is only a label, so this "
                          "is confusing rather than broken.")
            else:
                first_named[rule.name] = rule.index

            slot = (rule.group, rule.direction, rule.priority)
            if not problems:
                slots.setdefault(slot, []).append((rule.name, rule.action))

            if problems:
                self.fail(rule.name or f"acls.rules[{rule.index}]", *problems,
                          f'rule:  "{rule.raw}"')
            else:
                self.ok(f"{rule.name:<16}",
                        f"{rule.direction} {rule.priority} {rule.action} "
                        f"{rule.group}")

        # A shared priority is only ambiguous when the outcomes differ. Two
        # allow-related rules at 2100 on tcp and udp are the normal way to
        # write a service, and warning about those trains people to ignore
        # the warning that matters.
        for (group, direction, priority), occupants in sorted(slots.items()):
            actions = {action for _name, action in occupants}
            if len(occupants) < 2 or len(actions) < 2:
                continue
            self.warn(
                f"priority {priority} on {group} has conflicting actions",
                f"{direction} {priority}: " + ", ".join(
                    f"{name} ({action})" for name, action in occupants),
                "OVN does not define which of two equal-priority ACLs wins, "
                "so the effective policy here depends on translation order.")

    def _spec_problems(self, spec: str) -> list[str]:
        if spec in _BARE_SPECS:
            return []

        for proto in ("tcp=", "udp="):
            if spec.startswith(proto):
                val = spec[4:]
                if val.startswith("@"):
                    if val[1:] not in self.mgr.port_sets:
                        return [f"'{spec}' references port set '{val}', which "
                                "is not defined in acls.port_sets"]
                    return []
                bad = [p for p in val.split(",")
                       if not p.isdigit() or not 0 <= int(p) <= 65535]
                return [f"'{spec}' has invalid port(s): {', '.join(bad)}"] \
                    if bad else []

        if spec.startswith(("src=", "dst=")):
            body = spec[4:]
            if body == "internal":
                if not self.mgr.internal_ranges:
                    return [f"'{spec}' expands from [internal_ranges].ranges, "
                            "which is empty -- the match would be 'ip4.src == "
                            "{}'"]
                return []
            bad = [p for p in body.split(",") if not netcalc.cidr_valid(p)]
            return [f"'{spec}' is not a valid address/CIDR: {', '.join(bad)}"] \
                if bad else []

        # build_match() warns and moves on, which means the rule deploys
        # WITHOUT the constraint the author thought they wrote.
        return [f"unrecognised token '{spec}' -- it is dropped when the match "
                "is built, so the rule is broader than it looks"]

    # ------------------------------------------------------------------
    # 2a. port groups
    # ------------------------------------------------------------------
    def _check_groups(self, db: dict) -> None:
        defs = [(pg, sel) for pg, sel in self.mgr.group_defs if pg]
        self.section(f"port groups ({len(defs)})")
        if not defs:
            self.skip("no port groups declared in acls.port_groups")
            return

        names = {vm.uuid: vm.name for vm in self.mgr.inv.all}

        def label(ids: list[str]) -> str:
            """Port names read better than logical-port ids in a diff."""
            return _join([names.get(i, i) for i in ids])

        for pg, sel in defs:
            try:
                want = sorted(vm.uuid for vm in self.mgr.inv.select(sel))
            except Abort as exc:
                self.fail(pg, f"selector '{sel}' does not resolve:",
                          *str(exc).splitlines())
                continue

            if pg not in db:
                self.fail(pg,
                          "declared in acls.port_groups but absent from the db "
                          "-- every rule targeting it is inert",
                          f"selector    {sel}",
                          f"expected    {len(want)} member(s): {label(want)}",
                          "remedy      ovnctl acl --only port-groups")
                continue

            have = sorted(db[pg].ports)
            if have == want:
                self.ok(f"{pg:<16}",
                        f"{len(want)} member(s)  [{sel}]")
                continue

            missing = [p for p in want if p not in have]
            extra = [p for p in have if p not in want]
            self.fail(pg,
                      "membership has drifted from the inventory",
                      f"selector    {sel}",
                      f"in yaml     {len(want)}: {label(want)}",
                      f"in db       {len(have)}: {label(have)}",
                      f"missing     {label(missing)}",
                      f"unexpected  {label(extra)}",
                      "remedy      ovnctl acl --only port-groups  "
                      "(rebuilds from [vm_config])")

    # ------------------------------------------------------------------
    # 2b. every configured rule, against the db
    # ------------------------------------------------------------------
    def _check_rules(self, rules: list, db: dict) -> None:
        live = [r for r in rules if not r.error]
        self.section(f"deployed rules ({len(live)})")
        if not live:
            self.skip("nothing to compare")
            return

        # Which deployed ACLs some rule already accounts for. Several rules
        # legitimately share a direction+priority (tcp, udp and icmp for one
        # service), so without this a rule that is simply missing gets
        # reported as "the match differs" against its neighbour's ACL.
        claimed = {(r.group, r.direction, r.priority, _norm(m))
                   for r, m in ((r, self._match_or_none(r)) for r in live)
                   if m is not None}

        for rule in live:
            group = db.get(rule.group)
            if group is None:
                self.fail(rule.name,
                          f"port group '{rule.group}' is not in the db, so "
                          "this rule enforces nothing",
                          "remedy      ovnctl acl")
                continue
            expect = self._match_or_none(rule)
            if expect is None:
                continue
            self._compare(rule, expect, group.acls, claimed)

    def _match_or_none(self, rule) -> str | None:
        """build_match(), reporting a yaml that cannot produce one.

        Cached: three passes ask for the same match, and both the failure
        report and build_match's own warnings should appear once.
        """
        if rule.index in self._matches:
            return self._matches[rule.index]
        try:
            match = self.mgr.build_match(rule.direction, rule.group,
                                         rule.specs)
        except Abort as exc:
            self.fail(rule.name, "match cannot be built from the yaml:",
                      *str(exc).splitlines())
            match = None
        self._matches[rule.index] = match
        return match

    def _compare(self, rule, expect: str, acls: list, claimed: set) -> None:
        want = _norm(expect)
        exact = [a for a in acls if a.direction == rule.direction
                 and a.priority == rule.priority and _norm(a.match) == want]
        # Near-miss candidates: same slot, but not already explained by a
        # different rule in the file.
        slot = [a for a in acls
                if a.direction == rule.direction and a.priority == rule.priority
                and (rule.group, a.direction, a.priority,
                     _norm(a.match)) not in claimed]

        if exact:
            hit = exact[0]
            if hit.action != rule.action:
                self.fail(rule.name,
                          "deployed with the wrong action",
                          f"group       {rule.group}",
                          f"slot        {rule.direction} {rule.priority}",
                          f"configured  {rule.action}",
                          f"deployed    {hit.action}",
                          f"match       {expect}",
                          f"remedy      {self._readd(rule, hit.match)}")
                return
            if len(exact) > 1:
                self.warn(rule.name,
                          f"{len(exact)} identical ACLs on {rule.group} "
                          f"({rule.direction} {rule.priority})",
                          "Harmless, but it means the db was written to more "
                          "than once outside this tool.")
                return
            if hit.match != expect:
                self.warn(rule.name,
                          "same rule, different spacing -- hand-edited?",
                          f"configured  {expect}",
                          f"deployed    {hit.match}")
                return
            self.ok(f"{rule.name:<16}",
                    f"{rule.direction} {rule.priority} {rule.action} "
                    f"{rule.group}")
            return

        # No exact hit. Say as precisely as possible what is there instead.
        elsewhere = [a for a in acls if _norm(a.match) == want]
        if elsewhere:
            a = elsewhere[0]
            self.fail(rule.name,
                      "the match is deployed, but in the wrong slot",
                      f"group       {rule.group}",
                      f"configured  {rule.direction} {rule.priority} "
                      f"{rule.action}",
                      f"deployed    {a.direction} {a.priority} {a.action}",
                      f"match       {expect}",
                      "A priority change does not move an ACL: the old one "
                      "stays and the new one is added beside it.",
                      f"remedy      {self._readd(rule, a.match, a.direction, a.priority)}")
            return

        if slot:
            a = slot[0]
            col = _first_diff(expect, a.match)
            self.fail(rule.name,
                      "an ACL holds this direction+priority but the match "
                      "differs",
                      f"group       {rule.group}",
                      f"configured  {expect}",
                      f"deployed    {a.match}",
                      f"            first differs at column {col}",
                      f"action      configured {rule.action}, deployed "
                      f"{a.action}",
                      f"remedy      {self._readd(rule, a.match)}")
            return

        self.fail(rule.name,
                  "not deployed at all",
                  f"group       {rule.group}",
                  f"configured  {rule.direction} {rule.priority} {rule.action}",
                  f"match       {expect}",
                  "remedy      ovnctl acl --only rules")

    @staticmethod
    def _readd(rule, deployed_match: str, direction: str = "",
               priority: str = "") -> str:
        """The two commands that replace a wrong ACL with the right one.

        acl-add is --may-exist, so re-running the deploy on its own will
        add the correct ACL and leave the wrong one in place. The stale one
        has to go first.
        """
        return (f"ovn-nbctl acl-del {rule.group} "
                f"{direction or rule.direction} {priority or rule.priority} "
                f"'{deployed_match}' && ovnctl acl --only rules")

    # ------------------------------------------------------------------
    # 3. anything in the db the yaml does not account for
    # ------------------------------------------------------------------
    def _check_drift(self, rules: list, db: dict) -> None:
        self.section("drift (present in OVN, absent from the yaml)")
        declared = {pg for pg, _sel in self.mgr.group_defs if pg}

        expected: dict[str, set[tuple[str, str, str]]] = {}
        for rule in rules:
            if rule.error or rule.group not in declared:
                continue
            match = self._match_or_none(rule)
            if match is None:
                continue
            expected.setdefault(rule.group, set()).add(
                (rule.direction, rule.priority, _norm(match)))

        clean = True
        for pg in sorted(declared):
            group = db.get(pg)
            if group is None:
                continue
            known = expected.get(pg, set())
            for acl in group.acls:
                if (acl.direction, acl.priority, _norm(acl.match)) in known:
                    continue
                clean = False
                self.fail(f"{pg}: unmanaged ACL",
                          f"{acl.direction} {acl.priority} {acl.action}",
                          f"match       {acl.match}",
                          "No rule in acls.rules produces this. Either it was "
                          "added by hand, or a rule was edited -- acl-add is "
                          "--may-exist, so an edited match adds a second ACL "
                          "and the original keeps being enforced.",
                          f"remedy      ovn-nbctl acl-del {pg} {acl.direction} "
                          f"{acl.priority} '{acl.match}'")

        for legacy in self.legacy_pgs:
            group = db.get(legacy)
            if group is None:
                continue
            clean = False
            self.fail(f"{legacy}: legacy port group still present",
                      f"{len(group.ports)} member(s), {len(group.acls)} ACL(s)",
                      "vm_isolation.legacy_pg_names lists this for deletion. "
                      "The hyphen means it could never be referenced as "
                      f"@{legacy} in a match -- OVN's lexer rejects it -- so "
                      "whatever it left behind was never scoped to its "
                      "members and applies switch-wide.",
                      f"remedy      ovnctl vm-isolation  (deletes it on apply)"
                      f"  |  ovn-nbctl pg-del {legacy}")

        for pg in sorted(db):
            if pg in declared or pg in self.legacy_pgs:
                continue
            group = db[pg]
            if pg in self.foreign_pgs:
                self.skip(f"{pg:<16}  owned by [vm_isolation] -- "
                          f"{len(group.ports)} member(s), {len(group.acls)} "
                          "ACL(s), not audited here")
                continue
            clean = False
            self.warn(f"{pg} is not declared in acls.port_groups",
                      f"{len(group.ports)} member(s), {len(group.acls)} ACL(s)",
                      "Not managed from this file, and not one of the groups "
                      "another part of the suite owns. Fine if something "
                      "outside it owns the group; drift if it is a leftover.",
                      f"remedy      ovn-nbctl pg-del {pg}  (if it is stale)")

        if clean:
            self.ok("nothing unaccounted for",
                    "every deployed ACL traces back to a rule")

    # ------------------------------------------------------------------
    def _summary(self) -> int:
        c = self.c
        print("")
        if self.failures:
            print(f"{c.red}{c.bold}AUDIT FAILED{c.rst} -- {self.failures} "
                  f"check(s) failed, {self.warnings} warning(s), "
                  f"{self.passes} passed.")
            print("The running policy is not the policy in ovn-settings.yaml.")
            return 1
        if self.warnings:
            print(f"{c.ylw}AUDIT PASSED{c.rst} with {self.warnings} "
                  f"warning(s) -- {self.passes} check(s) passed.")
            return 0
        print(f"{c.grn}AUDIT PASSED{c.rst} -- {self.passes} check(s); the "
              f"deployment matches ovn-settings.yaml.")
        return 0