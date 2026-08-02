"""
ovnctl acl -- port of ovn-acl.sh

Applies the declarative ACL rules in ovn-settings.yaml [acls].

Port groups are built from the VM inventory (so membership can never drift
from [vm_config]), and every rule is scoped to its group with
inport/outport == @group -- without that scoping an ACL applies to every
port on the switch.

Rule format:
  <name> <direction> <priority> <action> <group> <spec>...
    direction  to-lport   evaluated on the way IN to a group member
               from-lport evaluated on the way OUT of a group member
    action     allow | allow-related | drop | reject
    spec       src=CIDR[,CIDR]   dst=CIDR[,CIDR]   src=any
               src=internal / dst=internal  expands to [internal_ranges]
               tcp=PORT | tcp=@portset   udp=PORT | udp=@portset   icmp
               log            log every packet this rule matches
               log=SEVERITY   the same, at alert|warning|notice|info|debug
               meter=NAME     rate-limit this rule's logging with a meter

Logging is per rule and off by default: on a busy segment an allow rule
that logs is a firehose. See [acl_log] in ovn-settings.yaml for where the
records end up.

Higher priority wins. Anything with no matching rule is ALLOWED (OVN's
default), so these rules only constrain what they name.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass

from .. import ovn
from ..context import (Abort, Colour, Ctx, acl_priority_matched,
                       acl_priority_of, trace_acl_priorities,
                       trace_verdict)
from ..inventory import Inventory
from ..state import ACLS, Tracker, record
from ..steps import StepRunner, add_step_args
from .acl_audit import ACLAudit, _norm

NAME = "acl"
HELP = "declarative micro-segmentation ACLs"

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

# ovn-controller's acl_log severities, in the order OVN documents them.
SEVERITIES = ("alert", "warning", "notice", "info", "debug")

# Written to /etc/rsyslog.d/. The 'stop' matters: without it every ACL
# record is ALSO appended to /var/log/messages, which is how a chatty
# allow rule takes out the system log rather than just its own file.
RSYSLOG_CONF = """\
# Managed by ovnctl acl. Do not edit -- rewritten on every run.
# ovn-controller emits ACL records through its vlog 'acl_log' module.
:msg, contains, "acl_log" {target}
& stop
"""



@dataclass
class ParsedRule:
    """One entry of [acls].rules, split into its fields.

    `error` is set instead of raising so a single bad line can be reported
    against its own name rather than stopping the whole run.
    """

    name: str
    direction: str
    priority: str
    action: str
    group: str
    specs: list[str]
    raw: str
    index: int = 0
    error: str = ""
    # Logging is a property of the rule, not of the match, so these are
    # split out of the spec tokens before the match is built.
    log: bool = False
    severity: str = ""
    meter: str = ""


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--remove", action="store_true",
                   help="remove the groups and their ACLs")
    g.add_argument("--verify", action="store_true",
                   help="ovn-trace every configured rule, plus verify_pairs")
    g.add_argument("--list", dest="do_list", action="store_true",
                   help="show what is currently applied")
    g.add_argument("--audit", action="store_true",
                   help="test every rule in the yaml against what is deployed")
    p.add_argument("--quick", action="store_true",
                   help="with --verify: one probe per rule instead of one "
                        "per port (a 7-port set is 7 traces)")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class ACLManager:
    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        c = ctx.config

        self.enabled = c.cfg_bool("acls", "enabled", False)
        self.ls_int = c.cfg("topology", "ls_int")
        self.ls_ext = c.cfg("topology", "ls_ext")

        self.internal_ranges = c.cfg_list("internal_ranges", "ranges")
        self.port_sets = self._parse_port_sets(c.cfg_list("acls", "port_sets"))
        self.group_defs = [self._split2(d) for d in c.cfg_list("acls", "port_groups")]
        self.rules = c.cfg_list("acls", "rules")
        self.verify_pairs = c.cfg_list("acls", "verify_pairs")

        # --- [acl_log] --------------------------------------------------
        # Defaults for any rule that says 'log' without saying more. The
        # meter is applied to every logging rule unless one names its own,
        # because an unmetered logging ACL on a busy segment can fill a
        # disk faster than anyone notices.
        self.log_severity = c.cfg_opt("acl_log", "severity", "info")
        if self.log_severity not in SEVERITIES:
            ctx.warn(f"[acl_log].severity '{self.log_severity}' is not one of "
                     f"{', '.join(SEVERITIES)} -- using 'info'.")
            self.log_severity = "info"
        self.meter_name = c.cfg_opt("acl_log", "meter", "acl-log-meter")
        self.log_rate = c.cfg_opt("acl_log", "rate_pps", "100")
        self.log_burst = c.cfg_opt("acl_log", "burst", "50")
        self.log_dir = c.cfg_opt("acl_log", "directory", "/var/log/ovn-acl")
        self.log_file = c.cfg_opt("acl_log", "filename", "acl.log")
        self.manage_sink = c.cfg_bool("acl_log", "manage_sink", True)


        self.inv = Inventory(c, self.ls_int, self.ls_ext)
        self.created: list[str] = []

        # --verify tallies. They live on the manager rather than in
        # do_verify's locals so the per-rule reporter can count without
        # threading a result object through every helper.
        self.v_ok = self.v_fail = self.v_warn = self.v_shadow = 0
        self.v_skip = 0
        self.quick_verify = False
        self.c = Colour()

    @staticmethod
    def _split2(entry: str) -> tuple[str, str]:
        parts = entry.split(None, 1)
        return (parts[0], parts[1].strip() if len(parts) > 1 else "")

    @staticmethod
    def _parse_port_sets(entries: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for entry in entries:
            parts = entry.split(None, 1)
            if len(parts) == 2:
                out[parts[0]] = parts[1].strip()
        return out

    # ------------------------------------------------------------------
    # rule parsing
    # ------------------------------------------------------------------
    def expand_ports(self, spec: str) -> str:
        """Resolve @name to a named port set from [acls].port_sets."""
        if not spec.startswith("@"):
            return spec
        name = spec[1:]
        if name not in self.port_sets:
            raise Abort(f"Unknown port set '{spec}'.")
        return self.port_sets[name]

    def expand_cidrs(self, spec: str) -> str:
        if spec == "internal":
            return ",".join(self.internal_ranges)
        return spec

    def build_match(self, direction: str, group: str, specs: list[str]) -> str:
        if direction == "to-lport":
            match = f"outport == @{group}"
        else:
            match = f"inport == @{group}"
        match += " && ip4"

        for spec in specs:
            if spec in ("src=any", "dst=any", "any"):
                continue
            if spec.startswith("src="):
                match += f" && ip4.src == {{{self.expand_cidrs(spec[4:])}}}"
            elif spec.startswith("dst="):
                match += f" && ip4.dst == {{{self.expand_cidrs(spec[4:])}}}"
            elif spec.startswith("tcp="):
                val = self.expand_ports(spec[4:])
                match += (f" && tcp && tcp.dst == {{{val}}}" if "," in val
                          else f" && tcp && tcp.dst == {val}")
            elif spec.startswith("udp="):
                val = self.expand_ports(spec[4:])
                match += (f" && udp && udp.dst == {{{val}}}" if "," in val
                          else f" && udp && udp.dst == {val}")
            elif spec == "icmp":
                match += " && icmp4"
            else:
                self.ctx.warn(f"Ignoring unrecognised rule token '{spec}'.")
        return match

    # ------------------------------------------------------------------
    # logging
    # ------------------------------------------------------------------
    def logging_rules(self) -> list[ParsedRule]:
        return [r for r in self.parsed_rules() if r.log and not r.error]

    def log_meter(self) -> None:
        """Create the meter that rate-limits acl_log output.

        Without one, a logging ACL writes a line per matching packet. That
        is fine for a drop rule nobody expects to fire and catastrophic for
        an allow rule on a busy segment -- it is the same disk the captures
        are going to.
        """
        ctx = self.ctx
        wanted = {r.meter for r in self.logging_rules() if r.meter}
        if not wanted:
            ctx.log("No logging rules -- no meter needed.")
            return
        ctx.dr_head("ACL log rate-limiting")
        for meter in sorted(wanted):
            # --may-exist leaves an existing meter's rate alone, which is
            # what you want: someone may have tuned it by hand after
            # watching the real volume.
            ctx.run("ovn-nbctl", "--may-exist", "meter-add", meter, "drop",
                    self.log_rate, "pktps", self.log_burst)
            ctx.log(f"  meter {meter}: {self.log_rate} pkt/s, "
                    f"burst {self.log_burst}")

    def log_sink(self) -> None:
        """Point acl_log records at a file of our own.

        OVN has no per-ACL log destination. `log=true` makes ovn-controller
        emit an acl_log record through its own vlog, and that is the end of
        what OVN offers -- the records land wherever ovn-controller's log
        goes, mixed in with everything else it has to say.

        So the directory in [acl_log] is implemented with rsyslog: tell
        ovn-controller to send acl_log to syslog, and give rsyslog a rule
        that files anything containing 'acl_log' separately and stops it
        propagating to /var/log/messages. The alternative -- repointing
        ovn-controller's --log-file -- would move ALL of its output, not
        just the ACL records.
        """
        ctx = self.ctx
        if not self.log_sink_wanted():
            return

        ctx.dr_head("ACL log sink")
        target = f"{self.log_dir}/{self.log_file}"
        ctx.run("mkdir", "-p", self.log_dir)

        # vlog levels are runtime state and do NOT survive an
        # ovn-controller restart. `ovnctl reconcile` re-applies this at
        # boot; without that the logging silently stops at the next
        # restart while the ACLs still say log=true.
        if ctx.have("ovn-appctl"):
            res = ovn.appctl(ctx, "vlog/set",
                             f"acl_log:syslog:{self.log_severity}")
            if res.returncode == 124:
                ctx.warn("ovn-controller did not answer within 10s -- it is "
                         "busy, not broken.")
                ctx.warn("The ACLs are deployed and logging is enabled on "
                         "them; only the vlog")
                ctx.warn("level was not raised, so records may not reach "
                         "syslog yet. Re-run:")
                ctx.warn("  ovnctl acl --only log-sink")
            elif not res:
                ctx.warn("Could not set the acl_log vlog level.")
                ctx.warn(f"  socket: {ovn.controller_ctl(ctx) or 'NOT FOUND'}")
                if res.stderr:
                    ctx.warn(f"  ovn-appctl: {res.stderr.splitlines()[0]}")
                stale = ovn.stale_ctl_sockets(ctx)
                if stale:
                    ctx.warn(f"  {len(stale)} socket file(s) belong to dead "
                             "processes and can be removed:")
                    for path in stale[:3]:
                        ctx.warn(f"    rm -f {path}")
                ctx.warn("  ACL logging is enabled on the rules regardless; "
                         "only the vlog")
                ctx.warn("  level is unset, so records may not reach syslog.")
        else:
            ctx.warn("ovn-appctl not found -- cannot raise the acl_log vlog "
                     "level, so records may never reach syslog.")

        if not ctx.have("rsyslogd"):
            ctx.warn("rsyslogd not found. ACL records will go to "
                     "ovn-controller's own log")
            ctx.warn(f"instead of {target}. Set [acl_log].manage_sink: false "
                     "to stop this warning,")
            ctx.warn("or file them yourself from journalctl -u ovn-controller.")
            return

        conf = RSYSLOG_CONF.format(target=target)
        path = "/etc/rsyslog.d/10-ovn-acl.conf"
        if ctx.dry_run:
            print(f"cat > {path} <<'EOF'")
            print(conf, end="")
            print("EOF")
            ctx.run("systemctl", "restart", "rsyslog")
            return

        from pathlib import Path
        try:
            existing = Path(path).read_text(encoding="utf-8")
        except OSError:
            existing = ""
        if existing == conf:
            ctx.log(f"{path} is already correct.")
            return
        try:
            Path(path).write_text(conf, encoding="utf-8")
        except OSError as exc:
            ctx.warn(f"Could not write {path}: {exc}")
            return
        ctx.changes += 1
        ctx.log(f"Wrote {path} -> {target}")
        if not ctx.run("systemctl", "restart", "rsyslog", timeout=30):
            ctx.warn("Could not restart rsyslog -- the rule is written but "
                     "not loaded.")

    def log_sink_wanted(self) -> bool:
        ctx = self.ctx
        if not self.logging_rules():
            ctx.log("No rule requests logging -- not touching the log sink.")
            return False
        if not self.manage_sink:
            ctx.log("[acl_log].manage_sink is false -- leaving syslog "
                    "configuration alone.")
            return False
        return True

    # ------------------------------------------------------------------
    # apply
    # ------------------------------------------------------------------
    def port_groups(self) -> None:
        ctx = self.ctx
        if not self.group_defs:
            ctx.log("No [acls].port_groups defined -- nothing to do.")
            return

        ctx.dr_head("ACL port groups")
        for pg, sel in self.group_defs:
            if not pg:
                continue
            if not _IDENT_RE.match(pg):
                raise Abort(
                    f"Port group name '{pg}' is not a valid OVN identifier.\n"
                    f"It must be referenceable as @{pg} in a match (no hyphens)."
                )

            members = self.inv.select(sel)
            if not members:
                ctx.warn(f"Port group {pg} ({sel}) has no members -- skipping.")
                continue

            # Recreate so membership always matches the inventory. pg-del
            # also clears the group's ACLs, re-added immediately below.
            if ovn.pg_exists(ctx, pg):
                ctx.run("ovn-nbctl", "pg-del", pg)
            ctx.run("ovn-nbctl", "pg-add", pg, *[vm.uuid for vm in members])
            self.created.append(pg)
            ctx.log(f"Port group {pg} ({sel}): {len(members)} member(s).")

    def parsed_rules(self) -> list[ParsedRule]:
        """[acls].rules split into fields, in file order.

        The deployer and the auditor both come through here. If they parsed
        separately, a rule could mean one thing when applied and another
        when checked, and the audit would be worth nothing.
        """
        out: list[ParsedRule] = []
        for idx, raw in enumerate(self.rules):
            if not raw.strip():
                continue
            parts = raw.split()
            if len(parts) < 5:
                out.append(ParsedRule(
                    "", "", "", "", "", [], raw, idx,
                    "needs at least 5 fields: <name> <direction> <priority> "
                    "<action> <group> [spec...]"))
                continue
            name, direction, priority, action, group = parts[:5]
            specs, log, severity, meter = self._split_log_tokens(parts[5:])
            out.append(ParsedRule(name, direction, priority, action, group,
                                  specs, raw, idx, log=log, severity=severity,
                                  meter=meter))
        return out

    def _split_log_tokens(self, tokens: list[str]) -> tuple[list[str], bool,
                                                            str, str]:
        """Pull log/log=SEV/meter=NAME out of the spec list.

        They sit among the specs because that is where a rule's optional
        trailing words go, but they say nothing about which packets match
        -- they say what to do when one does. Leaving them in would put
        'log' into the match string, and build_match would (rightly) warn
        about an unrecognised token.
        """
        specs: list[str] = []
        log = False
        severity = ""
        meter = self.meter_name
        for tok in tokens:
            if tok == "log":
                log = True
            elif tok.startswith("log="):
                log = True
                severity = tok[4:].strip()
                if severity not in SEVERITIES:
                    self.ctx.warn(
                        f"Unknown log severity '{severity}' -- expected one "
                        f"of {', '.join(SEVERITIES)}. Using "
                        f"'{self.log_severity}'.")
                    severity = ""
            elif tok == "nolog":
                log = False
            elif tok.startswith("meter="):
                meter = tok[6:].strip()
            else:
                specs.append(tok)
        if log and not severity:
            severity = self.log_severity
        if not log:
            meter = ""
        return specs, log, severity, meter

    def acl_rules(self) -> None:
        ctx = self.ctx
        ctx.dr_head("ACL rules")
        for rule in self.parsed_rules():
            if rule.error:
                ctx.warn(f"Skipping malformed rule: {rule.raw}")
                continue
            name, direction, priority = rule.name, rule.direction, rule.priority
            action, group = rule.action, rule.group

            # Accept a group created moments ago in this same run without
            # re-querying it; only fall back to the db for groups defined
            # elsewhere.
            if group not in self.created and not ctx.dry_run:
                if not ovn.pg_exists(ctx, group):
                    ctx.warn(f"Rule '{name}' targets unknown port group "
                             f"'{group}' -- skipping.")
                    continue

            match = self.build_match(direction, group, rule.specs)
            ovn.add_acl(ctx, group, direction, priority, match, action,
                        name=name, log=rule.log, severity=rule.severity,
                        meter=rule.meter)
            flag = f"  log={rule.severity}" if rule.log else ""
            ctx.log(f"  {name}: [{priority}] {direction} {action}{flag}")
            ctx.log(f"      {match}")

        self.name_existing_rules()

    def name_existing_rules(self) -> None:
        """Backfill the name on ACLs that were created without one.

        --may-exist makes acl-add a no-op when the (direction, priority,
        match) triple already exists, which means it does NOT apply a name
        to a row that predates named ACLs. Every deployment built before
        this change is in exactly that state, so reconcile the column
        directly rather than making people tear their ACLs down to get
        readable output.
        """
        ctx = self.ctx
        if ctx.dry_run:
            return
        index = ovn.acl_index(ctx)
        if not index:
            return
        fixed = 0
        for rule in self.parsed_rules():
            if rule.error or not rule.name:
                continue
            match = self.build_match(rule.direction, rule.group, rule.specs)
            entry = index.get((rule.direction, str(rule.priority), match))
            if not entry:
                continue
            wanted = {
                "name": rule.name,
                "log": rule.log,
                "severity": rule.severity if rule.log else "",
                "meter": rule.meter if rule.log else "",
            }
            changes = [k for k, v in wanted.items() if entry.get(k) != v]
            if not changes:
                continue
            argv = ["ovn-nbctl", "set", "acl", entry["uuid"]]
            for key in changes:
                value = wanted[key]
                if key == "log":
                    argv.append(f"log={'true' if value else 'false'}")
                elif value:
                    argv.append(f"{key}={value}")
                else:
                    # An empty optional column is CLEARED, not set to "".
                    # `severity=""` is a schema error, and leaving a stale
                    # severity on a rule whose logging was turned off is
                    # how a disabled rule keeps writing records.
                    ctx.run("ovn-nbctl", "clear", "acl", entry["uuid"], key)
            if len(argv) > 4 and not ctx.run(*argv):
                ctx.warn(f"Could not update ACL {entry['uuid']} "
                         f"({', '.join(changes)}).")
            else:
                fixed += 1
        if fixed:
            ctx.log(f"Reconciled name/logging on {fixed} existing ACL(s).")

    # ------------------------------------------------------------------
    def do_list(self) -> None:
        ctx = self.ctx
        print("=== Applied ACLs ===")
        for pg, sel in self.group_defs:
            if not pg:
                continue
            n = len(ovn.pg_members(ctx, pg))
            print("")
            print(f"{pg}  ({sel})  members: {n}")
            for line in ovn.acl_list(ctx, pg):
                print(f"    {line}")

    def do_remove(self) -> None:
        ctx = self.ctx
        ctx.log("Removing ACL port groups and their rules...")
        for pg, _sel in self.group_defs:
            if not pg:
                continue
            if ovn.pg_exists(ctx, pg):
                if ctx.run("ovn-nbctl", "pg-del", pg):
                    ctx.log(f"Removed {pg} (and its ACLs).")
            else:
                ctx.log(f"{pg} does not exist.")
        Tracker(ctx).unmark(ACLS)
        ctx.log("Done. VM-to-VM traffic is unrestricted again.")

    # ------------------------------------------------------------------
    # generated coverage
    # ------------------------------------------------------------------
    # Every rule in [acls].rules becomes its own set of traces, built from
    # the rule's own fields. verify_pairs still exists and is still run,
    # but it is a hand-maintained list: it says nothing when a rule is
    # added and nothing when one is edited, so on its own it can only ever
    # prove that yesterday's policy still works.
    #
    # --audit already answers "is this rule in the db, byte for byte".
    # This answers the different question of whether it DOES anything: an
    # ACL can be deployed exactly as written and still be dead, because a
    # higher-priority rule matches the same packets first.

    def _sample_ip(self, spec: str) -> str:
        """One concrete address to trace from inside a CIDR or literal.

        ovn-trace needs an address, not a prefix. A /32 is itself; anything
        wider yields its first usable host, which for the /30s in this
        topology is the useful end of the link rather than the network
        address.
        """
        import ipaddress
        spec = spec.strip()
        if not spec:
            return ""
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return ""
        if net.prefixlen >= 31:
            return str(net.network_address)
        return str(next(net.hosts(), net.network_address))

    def _spec_of(self, rule: ParsedRule, prefix: str) -> str:
        for spec in rule.specs:
            if spec.startswith(prefix):
                return spec[len(prefix):]
        return ""

    def _group_members(self, group: str) -> list:
        for name, selector in self.group_defs:
            if name == group:
                try:
                    return self.inv.select(selector)
                except Abort:
                    return []
        return []

    def _rule_probes(self, rule: ParsedRule) -> tuple[list[tuple], str]:
        """(probes, skip_reason) for one rule.

        A probe is (label, peer_ip, proto_expr, local_vm). The rule's own
        group supplies the local end; src=/dst= supplies the far end. For
        a to-lport rule the group is the DESTINATION -- that is what
        `outport == @group` means -- and the packet therefore arrives at
        the switch already routed, which changes both the inport and the
        TTL. Getting that backwards produces a trace that fails for
        reasons that have nothing to do with the rule.
        """
        members = self._group_members(rule.group)
        if not members:
            return [], f"port group {rule.group} resolves to no VMs"

        inbound = rule.direction == "to-lport"
        local = members[0]
        far_spec = self._spec_of(rule, "src=" if inbound else "dst=")
        far_spec = self.expand_cidrs(far_spec) if far_spec else ""

        if not far_spec or far_spec == "any":
            # An unconstrained end means the rule is about lateral traffic
            # between group members. Trace member -> member, which is the
            # case these rules exist to catch; with only one member there
            # is no such packet and the rule cannot be exercised.
            peer = next((v for v in members if v.ip != local.ip), None)
            if peer is None:
                return [], f"{rule.group} has one member -- no lateral peer"
            peers = [peer.ip]
        else:
            known = {vm.ip: vm for vm in self.inv.all if vm.ip}
            peers = self._addr_samples(far_spec, known, local.ip)
            if not peers:
                return [], f"could not derive an address from '{far_spec}'"

        protos: list[tuple[str, str]] = []
        tcp = self._spec_of(rule, "tcp=")
        udp = self._spec_of(rule, "udp=")
        if tcp:
            protos += [(f"tcp/{p}", f"tcp && tcp.dst=={p}")
                       for p in self.expand_ports(tcp).split(",") if p]
        if udp:
            protos += [(f"udp/{p}", f"udp && udp.dst=={p}")
                       for p in self.expand_ports(udp).split(",") if p]
        if "icmp" in rule.specs:
            protos.append(("icmp", "icmp4"))
        if not protos:
            protos = [("ip", "")]
        if self.quick_verify:
            protos = protos[:1]

        probes = []
        for peer_ip in peers:
            for plabel, pexpr in protos:
                probes.append((plabel, peer_ip, pexpr, local))
        return probes, ""

    @staticmethod
    def _fld(rec, field: str) -> str:
        """One accessor for both an inventory VM and a db port record."""
        return rec[field] if isinstance(rec, dict) else getattr(rec, field)

    def _trace_expr(self, direction: str, local, peer_ip: str, proto: str,
                    by_ip: dict, lrp_mac: dict):
        """(datapath, expr), or (None, reason) if the endpoint is unusable.

        Both passes come through here. If they built expressions
        separately, a rule could be traced one way when it comes from the
        yaml and another way when it comes from the db, and the two
        results would disagree for reasons that have nothing to do with
        the policy.

        The direction is what decides the shape. `to-lport` means
        `outport == @group`, so the group is the DESTINATION: the packet
        has already been routed, which puts it on the switch's router port
        with a decremented TTL. Getting that backwards produces a trace
        that fails for reasons unrelated to the rule under test.
        """
        f = self._fld
        switch = f(local, "switch")
        peer = by_ip.get(peer_ip)
        gw_mac = lrp_mac.get(switch, "")

        # An empty field here produces `eth.src== && ...`, which ovn-trace
        # rejects with "Syntax error at `&&\' expecting constant" -- a
        # message that says nothing about the actual problem, which is a
        # port with no addresses or a switch with no router port. Say
        # which one is missing instead of emitting a broken flow.
        missing = [name for name, val in (("switch", switch),
                                          ("MAC", f(local, "mac")),
                                          ("address", f(local, "ip")))
                   if not val]
        if not missing and not gw_mac and (
                peer is None or f(peer, "switch") != switch):
            missing.append(f"router-port MAC for {switch}")
        if missing:
            return None, f"port has no {', '.join(missing)}"

        if direction == "to-lport":
            datapath = switch
            if peer is not None and f(peer, "switch") == switch:
                inport, src_mac, ttl = (f(peer, "uuid"), f(peer, "mac"), 64)
            else:
                inport, src_mac, ttl = f"{switch}-to-lr", gw_mac, 63
            eth_dst, src_ip, dst_ip = f(local, "mac"), peer_ip, f(local, "ip")
        else:
            datapath = switch
            inport, src_mac, ttl = f(local, "uuid"), f(local, "mac"), 64
            eth_dst = (f(peer, "mac") if peer is not None
                       and f(peer, "switch") == switch else gw_mac)
            src_ip, dst_ip = f(local, "ip"), peer_ip

        expr = (f'inport=="{inport}" && eth.src=={src_mac} && '
                f'eth.dst=={eth_dst} && ip4.src=={src_ip} && '
                f'ip4.dst=={dst_ip} && ip.ttl=={ttl}')
        if proto:
            expr += f" && {proto}"
        return datapath, expr

    # ------------------------------------------------------------------
    # deployed-ACL coverage
    # ------------------------------------------------------------------
    # [acls].rules is not the whole policy. `user-vm` installs the two
    # segment drops and a per-slot access rule itself, `vm-isolation`
    # owns pg_isolated, and anything added by hand is real policy too.
    # Enumerating only the yaml therefore verifies the part of the
    # firewall that was easiest to verify, which is the wrong part.
    #
    # So the second pass reads the db, skips whatever the first pass
    # already covered, and probes the rest. Slot rules are generated at
    # create time and cannot be listed from any config file -- the db is
    # the only place they exist.

    _M_SCOPE = re.compile(r'(inport|outport)\s*==\s*(?:@(\S+)|"([^"]+)")')
    _M_ADDR = re.compile(r'ip4\.(src|dst)\s*==\s*(\{[^}]*\}|[^\s&]+)')
    _M_L4 = re.compile(r'(tcp|udp)\.dst\s*==\s*(\{[^}]*\}|\d+)')

    @staticmethod
    def _ovsdb_set(value) -> list[str]:
        """Scalars out of an ovsdb column that may or may not be a set."""
        if isinstance(value, str):
            return [value] if value and value != "uuid" else []
        if isinstance(value, list):
            if len(value) == 2 and value[0] in ("set", "map"):
                out: list[str] = []
                for item in value[1]:
                    out.extend(ACLManager._ovsdb_set(item))
                return out
            if len(value) == 2 and value[0] == "uuid":
                return [value[1]]
            out = []
            for item in value:
                out.extend(ACLManager._ovsdb_set(item))
            return out
        return []

    def _db_ports(self) -> tuple[dict, dict]:
        """(port table, ip index) covering every logical switch port.

        Built from the db rather than from Inventory because Inventory is
        constructed over the internal and external switches only -- it has
        never heard of a user-VM slot, so a probe for one cannot be
        assembled from it at all.
        """
        ctx = self.ctx
        parent: dict[str, str] = {}
        for row in ovn.nb_json(ctx, "name,ports", "Logical_Switch"):
            if not row or not row[0]:
                continue
            for uuid in self._ovsdb_set(row[1]):
                parent[uuid] = row[0]

        table: dict[str, dict] = {}
        by_ip: dict[str, dict] = {}
        for row in ovn.nb_json(ctx, "_uuid,name,type,addresses",
                               "Logical_Switch_Port"):
            if not row:
                continue
            uuid = self._ovsdb_set(row[0])
            uuid = uuid[0] if uuid else ""
            name, ptype = row[1], (row[2] or "vif")
            if ptype not in ("", "vif"):
                continue
            addrs = " ".join(self._ovsdb_set(row[3])).split()
            mac = next((a for a in addrs if a.count(":") == 5), "")
            ip = next((a for a in addrs if a.count(".") == 3), "")
            rec = {"name": name, "uuid": name, "mac": mac, "ip": ip,
                   "switch": parent.get(uuid, "")}
            table[name] = rec
            if uuid:
                table[uuid] = rec
            if ip:
                by_ip[ip] = rec
        return table, by_ip

    def _switch_lrp_mac(self) -> dict[str, str]:
        """Logical switch -> the MAC of the router port it is attached to.

        _trace_expr used to pick between the internal and external LRP
        MACs, which is right for exactly the two switches this file knows
        about and wrong for the user-VM segment. Ask the db instead.
        """
        ctx = self.ctx
        lrp_mac: dict[str, str] = {}
        for row in ovn.nb_json(ctx, "name,mac", "Logical_Router_Port"):
            if row and row[0]:
                macs = self._ovsdb_set(row[1])
                lrp_mac[row[0]] = macs[0] if macs else ""

        parent: dict[str, str] = {}
        for row in ovn.nb_json(ctx, "name,ports", "Logical_Switch"):
            if not row or not row[0]:
                continue
            for uuid in self._ovsdb_set(row[1]):
                parent[uuid] = row[0]

        out: dict[str, str] = {}
        for row in ovn.nb_json(ctx, "_uuid,name,type,options",
                               "Logical_Switch_Port"):
            if not row or (row[2] or "") != "router":
                continue
            uuid = self._ovsdb_set(row[0])
            switch = parent.get(uuid[0] if uuid else "", "")
            target = dict(ovn._json_map(row[3])).get("router-port", "")
            if switch and target in lrp_mac:
                out[switch] = lrp_mac[target]
        return out

    def _members_of(self, group: str) -> list[str]:
        for row in ovn.nb_json(self.ctx, "name,ports", "Port_Group"):
            if row and row[0] == group:
                return self._ovsdb_set(row[1])
        return []

    def _addr_samples(self, blob: str, known: dict | None = None,
                      exclude: str = "") -> list[str]:
        """Sample addresses out of an `ip4.src == {a, b, c}` operand.

        A range that actually contains a port is probed AT that port
        rather than at its first host. It matters most for the user-VM
        self-block: the segment lists its own subnet, whose first host is
        the router, so sampling naively would trace slot -> gateway and
        never test the slot -> slot case the rule exists to stop.
        """
        import ipaddress
        out: list[str] = []
        for part in blob.strip().strip("{}").replace(",", " ").split():
            pick = ""
            if known:
                try:
                    net = ipaddress.ip_network(part, strict=False)
                except ValueError:
                    net = None
                if net is not None:
                    for addr in known:
                        if addr == exclude:
                            continue
                        try:
                            if ipaddress.ip_address(addr) in net:
                                pick = addr
                                break
                        except ValueError:
                            continue
            pick = pick or self._sample_ip(part)
            if pick:
                out.append(pick)
        return out

    def _db_acl_probes(self, direction: str, match: str,
                       ports: dict, by_ip: dict) -> tuple[list[tuple], str]:
        scope = self._M_SCOPE.search(match)
        if not scope:
            return [], "match names no inport/outport"
        group, explicit = scope.group(2), scope.group(3)

        if explicit:
            local = ports.get(explicit)
            if local is None:
                return [], f"port {explicit[:12]}... is not a VIF in the db"
            locals_ = [local]
        else:
            members = [ports[m] for m in self._members_of(group) if m in ports]
            if not members:
                return [], f"port group {group} has no VIF members"
            locals_ = members[:1]

        inbound = direction == "to-lport"
        far_side = "src" if inbound else "dst"
        addrs = {side: blob for side, blob in self._M_ADDR.findall(match)}
        if far_side in addrs:
            peers = self._addr_samples(addrs[far_side], by_ip,
                                       locals_[0]["ip"])
            if not peers:
                return [], f"no usable address in ip4.{far_side}"
        else:
            peer = next((m for m in
                         ([ports[x] for x in self._members_of(group)
                           if x in ports] if group else [])
                        if m["ip"] and m["ip"] != locals_[0]["ip"]), None)
            if peer is None:
                return [], "unconstrained match with no peer to trace from"
            peers = [peer["ip"]]

        protos: list[tuple[str, str]] = []
        for proto, blob in self._M_L4.findall(match):
            for port in blob.strip().strip("{}").replace(",", " ").split():
                protos.append((f"{proto}/{port}",
                               f"{proto} && {proto}.dst=={port}"))
        if "icmp4" in match:
            protos.append(("icmp", "icmp4"))
        if not protos:
            protos = [("ip", "")]
        if self.quick_verify:
            protos = protos[:1]

        probes = []
        for local in locals_:
            for peer_ip in peers:
                for plabel, pexpr in protos:
                    probes.append((plabel, peer_ip, pexpr, local))
        return probes, ""

    def _verify_deployed_acls(self) -> None:
        ctx = self.ctx
        acls = ovn.nb_json(ctx, "_uuid,name,direction,priority,action,match",
                           "ACL")
        if not acls:
            return

        # Whatever the first pass already probed, by match. Rebuilt with
        # build_match -- the same call the deployer makes -- so a rule
        # cannot be counted as covered here and written differently there.
        covered = set()
        for rule in self.parsed_rules():
            if rule.error:
                continue
            try:
                covered.add(_norm(self.build_match(rule.direction, rule.group,
                                                   rule.specs)))
            except Abort:
                continue

        pending = [a for a in acls if _norm(a[5] or "") not in covered]
        if not pending:
            return

        owner: dict[str, str] = {}
        for row in ovn.nb_json(ctx, "name,acls", "Port_Group"):
            if row and row[0]:
                for uuid in self._ovsdb_set(row[1]):
                    owner[uuid] = row[0]

        print(f"  {self.c.bold}--- deployed ACLs not declared in [acls].rules ---{self.c.rst}")
        ports, by_ip = self._db_ports()
        lrp_mac = self._switch_lrp_mac()

        for row in pending:
            uuid = self._ovsdb_set(row[0])
            uuid = uuid[0] if uuid else ""
            name = " ".join(self._ovsdb_set(row[1])) or "(unnamed)"
            direction, priority, action, match = row[2], str(row[3]), row[4], row[5]
            group = owner.get(uuid, "?")
            label = f"{name} [{group}] ({direction} {priority} {action})"

            probes, skip = self._db_acl_probes(direction, match or "",
                                               ports, by_ip)
            if skip:
                self.v_skip += 1
                print(f"  {self.tag('skip')} {label:<46} {self.c.dim}{skip}{self.c.rst}")
                continue

            expect = "DROP" if action in ("drop", "reject") else "ALLOW"
            want_prio = int(priority) if str(priority).isdigit() else -1
            side = "out" if direction == "to-lport" else "in"
            results = []
            for plabel, peer_ip, pexpr, local in probes:
                dp, expr = self._trace_expr(direction, local, peer_ip, pexpr,
                                            by_ip, lrp_mac)
                if dp is None:
                    results.append((plabel, peer_ip, expect, "SKIP",
                                    [], [], expr))
                    continue
                out = ovn.trace(ctx, dp, expr)
                results.append((plabel, peer_ip, expect, trace_verdict(out),
                                trace_acl_priorities(out, side),
                                trace_acl_priorities(out), out))
            self._report_case(label, want_prio, results, direction)
        print("")

    def _verify_every_rule(self, lrp_int_mac: str, lrp_ext_mac: str) -> None:
        rules = [r for r in self.parsed_rules() if not r.error]
        if not rules:
            print("  (no rules configured)")
            return

        print(f"  {self.c.bold}--- per-rule coverage (generated from [acls].rules) ---{self.c.rst}")
        by_ip = {vm.ip: vm for vm in self.inv.all if vm.ip}
        lrp_mac = dict(self._switch_lrp_mac())
        lrp_mac.setdefault(self.ls_int, lrp_int_mac)
        lrp_mac.setdefault(self.ls_ext, lrp_ext_mac)
        for rule in rules:
            probes, skip = self._rule_probes(rule)
            if skip:
                self.v_skip += 1
                print(f"  {self.tag('skip')} {rule.name:<46} {self.c.dim}{skip}{self.c.rst}")
                continue

            expect = "DROP" if rule.action in ("drop", "reject") else "ALLOW"
            want_prio = int(rule.priority) if rule.priority.isdigit() else -1
            side = "out" if rule.direction == "to-lport" else "in"
            results = []
            for plabel, peer_ip, pexpr, local in probes:
                datapath, expr = self._trace_expr(
                    rule.direction, local, peer_ip, pexpr, by_ip, lrp_mac)
                if datapath is None:
                    results.append((plabel, peer_ip, expect, "SKIP",
                                    [], [], expr))
                    continue
                out = ovn.trace(self.ctx, datapath, expr)
                results.append((plabel, peer_ip, expect, trace_verdict(out),
                                trace_acl_priorities(out, side),
                                trace_acl_priorities(out), out))
            label = (f"{rule.name} ({rule.direction} {rule.priority} "
                     f"{rule.action})")
            self._report_case(label, want_prio, results, rule.direction)
        print("")

    def _report_case(self, label: str, want_prio: int,
                     results: list, direction: str = "") -> None:
        """One line per rule when it is healthy, detail when it is not.

        Collapsing the probes is deliberate. A rule with a seven-port set
        produces seven traces, and printing seven OK lines for each of
        fifty-eight rules buries the two that matter.

        The classification asks two questions, not one. "Did the packet
        end up the way the rule says" is not enough on its own: with no
        default-deny an allow rule and a missing allow rule give the same
        verdict, and a drop rule gets the credit for a packet some other
        rule dropped first. So it also asks whether THIS rule is the one
        that decided, which needs the northd priority offset applied --
        see acl_priority_matched.
        """
        ok = []
        bad = []
        shadowed = []
        unmeasured = []
        skipped = []
        unreachable = []
        for plabel, peer_ip, expect, verdict, mine, every, out in results:
            decided_here = [p for p in mine if p > 0]
            decided_any = [p for p in every if p > 0]
            if verdict == "SKIP":
                skipped.append((plabel, peer_ip, out))
            elif verdict == "UNKNOWN":
                unmeasured.append((plabel, peer_ip, out))
            elif want_prio >= 0 and acl_priority_matched(decided_here,
                                                         want_prio):
                # Our rule matched. Now the verdict has to agree with it.
                (ok if verdict == expect else bad).append(
                    (plabel, peer_ip, verdict, expect, out))
            elif (direction == "to-lport" and decided_any
                  and verdict == "DROP"):
                # The egress ACLs never ran: something in the INGRESS
                # pipeline dropped the packet first, and ls_in is
                # evaluated before ls_out. That says nothing about this
                # rule -- it says the probe cannot reach it. Counting it
                # as shadowed blames a rule for not deciding a packet it
                # was never offered. The usual cause is the paired
                # from-lport rule at the same priority doing its job.
                unreachable.append((plabel, peer_ip, max(decided_any)))
            elif decided_any:
                shadowed.append((plabel, peer_ip, max(decided_any), verdict))
            elif want_prio >= 0:
                # Nothing in the ACL stage claimed the packet at all.
                shadowed.append((plabel, peer_ip, 0, verdict))
            else:
                (ok if verdict == expect else bad).append(
                    (plabel, peer_ip, verdict, expect, out))

        n = len(results)
        if bad:
            self.v_fail += 1
            print(f"  {self.tag('fail')} {label:<46} {len(bad)}/{n} probes wrong")
            for plabel, peer_ip, verdict, expect, out in bad[:3]:
                print(f"         {peer_ip} {plabel}: {verdict}, "
                      f"expected {expect}")
                for line in out.splitlines()[-4:]:
                    print(f"           {line}")
        elif skipped and len(skipped) == n:
            self.v_skip += 1
            print(f"  {self.tag('skip')} {label:<46} "
                  f"{self.c.dim}{skipped[0][2]}{self.c.rst}")
        elif unreachable and not ok and not shadowed:
            self.v_skip += 1
            print(f"  {self.tag('skip')} {label:<46} {self.c.dim}"
                  f"every probe was dropped in ingress -- the egress ACLs "
                  f"never ran{self.c.rst}")
        elif unmeasured and len(unmeasured) == n:
            self.v_warn += 1
            print(f"  {self.tag('warn')} {label:<46} no verdict (trace failed/timed out)")
            for line in (unmeasured[0][2].splitlines()[-4:] or ["(no output)"]):
                print(f"         {line}")
        elif shadowed:
            self.v_shadow += 1
            first = shadowed[0]
            where = (f"priority {acl_priority_of(first[2])}" if first[2]
                     else "no ACL matched")
            print(f"  {self.tag('dead')} {label:<46} {len(shadowed)}/{n} "
                  f"decided by {self.c.mag}{where}{self.c.rst}")
            for plabel, peer_ip, prio, verdict in shadowed[:3]:
                print(f"         {self.c.dim}{peer_ip} {plabel}: {verdict} "
                      + (f"from priority {acl_priority_of(prio)}"
                         if prio else "with no ACL match")
                      + self.c.rst)
        else:
            self.v_ok += 1
            notes = []
            if skipped:
                notes.append(f"{len(skipped)} unprobeable")
            if unreachable:
                notes.append(f"{len(unreachable)} never reached egress")
            extra = ", " + ", ".join(notes) if notes else ""
            print(f"  {self.tag('ok')} {label:<46} {self.c.dim}{len(ok)}/{n} probe(s){extra}{self.c.rst}")

    _TAGS = {"ok": ("[ OK ]", "grn", False), "fail": ("[FAIL]", "red", True),
             "warn": ("[WARN]", "ylw", False), "dead": ("[DEAD]", "mag", False),
             "skip": ("[SKIP]", "dim", False)}

    def tag(self, kind: str) -> str:
        """A coloured status tag, matching --audit's palette exactly.

        The colour wraps the tag only, never the padded label. Escape
        codes inside an f-string field width count toward that width, so
        colouring the label instead would shorten every line by the
        length of the escape sequence and stagger the column.
        """
        text, colour, bold = self._TAGS[kind]
        c = self.c
        return f"{getattr(c, colour)}{c.bold if bold else ''}{text}{c.rst}"

    def _check(self, label: str, expect: str, datapath: str, expr: str) -> None:
        c = self.c
        out = ovn.trace(self.ctx, datapath, expr)
        verdict = trace_verdict(out)
        if verdict == expect:
            print(f"  {self.tag('ok')} {label:<46} {c.dim}{verdict}{c.rst}")
        elif verdict == "UNKNOWN":
            # Not a failure of the policy -- a failure to measure it.
            # Printing FAIL here would send you to fix a rule that is fine.
            print(f"  {self.tag('warn')} {label:<46} "
                  f"no verdict (trace failed/timed out)")
            for line in (out.splitlines()[-6:] or ["(no output)"]):
                print(f"         {c.dim}{line}{c.rst}")
        else:
            print(f"  {self.tag('fail')} {label:<46} {c.red}{verdict}{c.rst} "
                  f"(expected {expect})")
            for line in out.splitlines()[-6:]:
                print(f"         {c.dim}{line}{c.rst}")

    def do_verify(self) -> int:
        ctx = self.ctx
        ctx.require_cmd("ovn-trace")

        # ovn-trace reads the Southbound db, which northd populates from
        # the Northbound one asynchronously. Verifying immediately after
        # applying rules can therefore trace the pipeline as it was before
        # they existed and report failures that are pure timing.
        ovn.sync_sb(ctx)

        if len(self.inv.internal) < 2 or len(self.inv.external) < 1:
            raise Abort("Need at least 2 internal and 1 external VM in the "
                        "inventory.")

        v1, v2 = self.inv.internal[0], self.inv.internal[1]
        ev = self.inv.external[0]

        host_ip = ctx.cfg("setup", "host_if_ip")
        lrp_int_mac = ctx.cfg("setup", "lrp_int_mac")
        lrp_ext_mac = ctx.cfg("setup", "lrp_ext_mac")

        print("")
        print(f"{self.c.bold}=== ACL verification ==={self.c.rst}")

        # Management SSH in -- must be allowed.
        self._check(f"host {host_ip} -> {v1.name} :22", "ALLOW", self.ls_int,
                    f'inport=="{self.ls_int}-to-lr" && eth.src=={lrp_int_mac} && '
                    f'eth.dst=={v1.mac} && ip4.src=={host_ip} && '
                    f'ip4.dst=={v1.ip} && ip.ttl==63 && tcp && tcp.dst==22')

        self._check(f"workstation 172.31.0.5 -> {v1.name} :22", "ALLOW",
                    self.ls_int,
                    f'inport=="{self.ls_int}-to-lr" && eth.src=={lrp_int_mac} && '
                    f'eth.dst=={v1.mac} && ip4.src==172.31.0.5 && '
                    f'ip4.dst=={v1.ip} && ip.ttl==63 && tcp && tcp.dst==22')

        # Lateral SSH -- must be dropped.
        self._check(f"{v1.name} -> {v2.name} :22 (same subnet)", "DROP",
                    self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={v2.mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={v2.ip} && ip.ttl==64 && tcp && tcp.dst==22')

        self._check(f"{v1.name} -> {ev.name} :22 (across subnets)", "DROP",
                    self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={lrp_int_mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={ev.ip} && ip.ttl==64 && tcp && tcp.dst==22')

        self._check(f"{v1.name} -> host {host_ip} :22", "DROP", self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={lrp_int_mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={host_ip} && ip.ttl==64 && tcp && tcp.dst==22')

        # Non-SSH between VMs is untouched.
        self._check(f"{v1.name} -> {v2.name} :443 (non-SSH unaffected)", "ALLOW",
                    self.ls_int,
                    f'inport=="{v1.uuid}" && eth.src=={v1.mac} && '
                    f'eth.dst=={v2.mac} && ip4.src=={v1.ip} && '
                    f'ip4.dst=={v2.ip} && ip.ttl==64 && tcp && tcp.dst==443')

        self._verify_every_rule(lrp_int_mac, lrp_ext_mac)
        self._verify_deployed_acls()
        self._verify_configured_pairs(lrp_int_mac, lrp_ext_mac)

        # Engagement traffic out must survive.
        self._check(f"{ev.name} -> 203.0.113.10 :22 (external OK)", "ALLOW",
                    self.ls_ext,
                    f'inport=="{ev.uuid}" && eth.src=={ev.mac} && '
                    f'eth.dst=={lrp_ext_mac} && ip4.src=={ev.ip} && '
                    f'ip4.dst==203.0.113.10 && ip.ttl==64 && tcp && tcp.dst==22')

        total = self.v_ok + self.v_fail + self.v_warn + self.v_shadow
        c = self.c
        def n(count: int, colour: str) -> str:
            # A zero is good news for every counter but the first, so
            # only colour the ones that are actually saying something.
            return f"{colour}{count}{c.rst}" if count else str(count)
        print(f"  {c.bold}{total} rule(s) exercised{c.rst}: "
              f"{n(self.v_ok, c.grn)} ok, "
              f"{n(self.v_fail, c.red)} failed, "
              f"{n(self.v_shadow, c.mag)} dead/shadowed, "
              f"{n(self.v_warn, c.ylw)} unmeasured, "
              f"{n(self.v_skip, c.dim)} skipped")
        if self.v_fail or self.v_shadow:
            print(f"  {c.dim}A DEAD rule is deployed correctly but never "
                  f"decides anything -- check for a{c.rst}")
            print(f"  {c.dim}higher-priority rule matching the same packets, "
                  f"or raise this rule above it.{c.rst}")
            print(f"  {c.dim}Priorities are shown as they appear in the yaml, "
                  f"not as northd's offset flows.{c.rst}")
        print("")

        # DEAD does not fail the run. [acls] documents two rules as
        # deliberate no-ops -- recorded intent for a policy that will be
        # tightened later -- and a check that cannot tell an intentional
        # no-op from an accidental one must not be the thing that blocks a
        # deploy. It reports; you decide. A wrong VERDICT is different:
        # the rule matched and did the opposite of what it says.
        return 1 if self.v_fail else 0

    def _verify_configured_pairs(self, lrp_int_mac: str, lrp_ext_mac: str) -> None:
        """Declarative pairs from [acls].verify_pairs.

        Format: "<name> <src-ip> <dst-ip> <tcp|udp|icmp> <port|-> <ALLOW|DROP>"
        """
        if not self.verify_pairs:
            return
        print(f"  {self.c.bold}--- configured checks ---{self.c.rst}")
        for pair in self.verify_pairs:
            parts = pair.split()
            if len(parts) < 6:
                continue
            pname, psrc, pdst, pproto, pport, pexp = parts[:6]

            src_vm = self.inv.by_ip(psrc)
            dst_vm = self.inv.by_ip(pdst)
            ttl = 64

            if src_vm is None:
                # Source is not a VM (a workstation, the host, anything
                # off-switch). Such traffic arrives already routed, so the
                # trace enters the DESTINATION switch via its router port
                # with a decremented TTL.
                if dst_vm is None:
                    print(f"  {self.tag('skip')} {pname:<46} {self.c.dim}neither {psrc} nor {pdst} is a VM{self.c.rst}")
                    continue
                datapath = dst_vm.switch
                inport = f"{dst_vm.switch}-to-lr"
                src_mac = lrp_int_mac if dst_vm.switch == self.ls_int else lrp_ext_mac
                eth_dst = dst_vm.mac
                ttl = 63
            else:
                datapath = src_vm.switch
                inport = src_vm.uuid
                src_mac = src_vm.mac
                if dst_vm is not None and dst_vm.switch == src_vm.switch:
                    # Same switch -> address the peer directly.
                    eth_dst = dst_vm.mac
                elif src_vm.switch == self.ls_int:
                    eth_dst = lrp_int_mac
                else:
                    eth_dst = lrp_ext_mac

            if pproto == "tcp":
                proto = f"tcp && tcp.dst=={pport}"
            elif pproto == "udp":
                proto = f"udp && udp.dst=={pport}"
            elif pproto == "icmp":
                proto = "icmp4"
            else:
                print(f"  {self.tag('skip')} {pname:<46} {self.c.dim}unknown protocol {pproto}{self.c.rst}")
                continue

            src_label = src_vm.name if src_vm else psrc
            dst_label = dst_vm.name if dst_vm else pdst
            port_label = f"/{pport}" if pport and pport != "-" else ""
            label = f"{pname}: {src_label} -> {dst_label} {pproto}{port_label}"

            self._check(label, pexp, datapath,
                        f'inport=="{inport}" && eth.src=={src_mac} && '
                        f'eth.dst=={eth_dst} && ip4.src=={psrc} && '
                        f'ip4.dst=={pdst} && ip.ttl=={ttl} && {proto}')
        print("")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.load_config("ovn-acl")
    ctx.require_cfg("acls:enabled", "setup:host_if_ip", "setup:lrp_ext_mac",
                    "setup:lrp_int_mac", "topology:ls_ext", "topology:ls_int")

    ctx.require_root()
    ctx.require_cmd("ovn-nbctl")

    cmd = ACLManager(ctx)

    # Before the enabled check on purpose. "We turned ACLs off -- is the
    # policy actually gone?" is exactly the question an audit should be
    # able to answer.
    if args.audit:
        return ACLAudit(cmd).run()

    # --list-steps is documentation: answer it even when the feature is
    # switched off, or "what would this do?" is unanswerable precisely
    # when you are deciding whether to switch it on.
    if not cmd.enabled and not ctx.listing:
        ctx.log("acls.enabled is false -- nothing to do.")
        return 0

    if args.remove:
        cmd.do_remove()
        return 0
    if args.verify:
        cmd.quick_verify = bool(getattr(args, "quick", False))
        return cmd.do_verify()
    if args.do_list:
        cmd.do_list()
        return 0

    if not cmd.group_defs and not ctx.listing:
        ctx.log("No [acls].port_groups defined -- nothing to do.")
        return 0

    runner = StepRunner(ctx, "acl")
    runner.add("port-groups", "rebuild the port groups from the inventory",
               cmd.port_groups)
    runner.add("log-meter", "rate-limit meter for logging rules",
               cmd.log_meter)
    runner.add("rules", "apply the ACL rules", cmd.acl_rules)
    runner.add("log-sink", "file acl_log records into [acl_log].directory",
               cmd.log_sink)

    if not runner.run(args):
        return 0

    record(ctx, ACLS, runner)
    if ctx.dry_run:
        return 0

    if ctx.verbose:
        print("")
        cmd.do_list()
    ctx.finish(f"{len(cmd.group_defs)} port group(s), "
               f"{len(cmd.rules)} rule(s) applied")
    return 0