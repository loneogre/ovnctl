"""
Shared behaviour for every subcommand -- the port of ovn-common.sh and
ovn-dryrun.sh.

OUTPUT CONTRACT (unchanged from the shell suite)
  success  : one summary line, nothing else
  -v       : the full step-by-step narration
  --dry-run: the commands that would run, and nothing else
  warnings : always, on stderr
  errors   : always, on stderr, then exit non-zero

Nothing here is optional or best-effort. If the settings file is missing
the run stops with a clear message rather than silently falling back to
built-in defaults and producing a deployment that does not match the
configuration.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import paths
from .config import Config, ConfigError

# Characters that never need quoting in the dry-run listing.
_SAFE_RE = re.compile(r"^[A-Za-z0-9_./:=@%+,-]+$")


def shquote(arg: str) -> str:
    """Port of _dr_quote: shell-safe, but readable for the common case."""
    if arg == "":
        return "''"
    if _SAFE_RE.match(arg):
        return arg
    return "'" + arg.replace("'", "'\\''") + "'"


def format_cmd(argv: list[str]) -> str:
    return " ".join(shquote(str(a)) for a in argv)


class Colour:
    """ANSI codes, but only when stdout is a terminal and NO_COLOR is unset.

    `ovnctl --no-color` exports NO_COLOR before the subcommand runs, so
    honouring the variable covers the flag too, and a redirected run
    (`ovnctl acl --audit > report.txt`) stays plain text without anyone
    having to remember the flag.
    """

    def __init__(self) -> None:
        enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.red = "\033[31m" if enabled else ""
        self.grn = "\033[32m" if enabled else ""
        self.ylw = "\033[33m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.rst = "\033[0m" if enabled else ""


class Abort(Exception):
    """Fatal error -- message already formatted, exit non-zero."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class Result:
    """Outcome of a command invocation."""

    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def __bool__(self) -> bool:  # so `if ctx.run(...)` reads naturally
        return self.ok

    @property
    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


@dataclass
class Ctx:
    """Per-run state: flags, counters, and the configuration."""

    prefix: str = "ovn"
    verbose: bool = False
    dry_run: bool = False
    # True for --list-steps. The listing is documentation, so it must work
    # on a laptop with no OVN installed and no root -- the preconditions
    # below are skipped rather than turning "what does this do?" into an
    # error about a missing binary.
    listing: bool = False
    changes: int = 0
    warnings: int = 0
    # Ceiling for read-only queries. ovn-nbctl and ovn-sbctl wait on the db
    # forever by default, and the commands that query them are the ones run
    # while that db is unreachable.
    query_timeout: float = 15.0
    _config: Config | None = field(default=None, repr=False)

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------
    @property
    def cfg_file(self) -> Path:
        return self._config.path if self._config else paths.settings_file()

    def load_config(self, prefix: str | None = None) -> Config:
        """Port of ovn_common_init: set the log prefix and load the yaml."""
        if prefix:
            self.prefix = prefix
        if self._config is None:
            self._config = Config().load()
        return self._config

    @property
    def config(self) -> Config:
        if self._config is None:
            self._config = Config().load()
        return self._config

    # Thin pass-throughs so command modules read like the shell did.
    def cfg(self, section: str, key: str) -> str:
        return self.config.cfg(section, key)

    def cfg_opt(self, section: str, key: str, default: str = "") -> str:
        return self.config.cfg_opt(section, key, default)

    def cfg_int(self, section: str, key: str) -> int:
        return self.config.cfg_int(section, key)

    def cfg_bool(self, section: str, key: str, default: bool = False) -> bool:
        return self.config.cfg_bool(section, key, default)

    def cfg_array(self, section: str, key: str) -> list[str] | None:
        return self.config.cfg_array(section, key)

    def cfg_list(self, section: str, key: str) -> list[str]:
        return self.config.cfg_list(section, key)

    def require_cfg(self, *pairs: str) -> None:
        self.config.require(*pairs)

    # ------------------------------------------------------------------
    # output
    # ------------------------------------------------------------------
    def log(self, *parts: object) -> None:
        """Step narration. Shown only with -v, never in a dry-run listing."""
        if self.verbose and not self.dry_run:
            print(f"[{self.prefix}] {' '.join(str(p) for p in parts)}")

    def say(self, *parts: object) -> None:
        """Something the operator must see even on a quiet successful run."""
        if not self.dry_run:
            print(f"[{self.prefix}] {' '.join(str(p) for p in parts)}")

    def out(self, *parts: object) -> None:
        """Plain output (tables, summaries) -- suppressed under --dry-run."""
        if not self.dry_run:
            print(" ".join(str(p) for p in parts) if parts else "")

    def warn(self, *parts: object) -> None:
        self.warnings += 1
        print(f"[{self.prefix}] WARNING: {' '.join(str(p) for p in parts)}",
              file=sys.stderr)

    def err(self, *parts: object) -> None:
        print(f"[{self.prefix}] ERROR: {' '.join(str(p) for p in parts)}",
              file=sys.stderr)

    def note_stderr(self, text: str, indent: str = "        ") -> None:
        for line in str(text).splitlines():
            print(f"{indent}{line}", file=sys.stderr)

    def die(self, *parts: object) -> "Abort":
        """Raise, don't exit -- the CLI turns this into the exit status."""
        raise Abort(" ".join(str(p) for p in parts))

    def finish(self, *parts: object) -> None:
        """The single success line. Call at the end of a successful run."""
        if self.dry_run:
            return
        extra = f" ({self.changes} commands)" if self.changes > 0 else ""
        msg = " ".join(str(p) for p in parts)
        if self.warnings > 0:
            print(f"[{self.prefix}] OK: {msg} -- {self.warnings} warning(s){extra}")
        else:
            print(f"[{self.prefix}] OK: {msg}{extra}")

    def dr_head(self, *parts: object) -> None:
        """Section heading, dry-run listings only."""
        if self.dry_run:
            print(f"\n# {' '.join(str(p) for p in parts)}")

    def dr_banner(self, *parts: object) -> None:
        if self.dry_run:
            print(f"# {' '.join(str(p) for p in parts)}")
            print("# Commands reflect the current state -- "
                  "already-configured items are omitted.")

    # ------------------------------------------------------------------
    # command execution
    # ------------------------------------------------------------------
    def run(self, *argv: object, check: bool = False,
            stdin: str | None = None,
            timeout: float | None = None) -> Result:
        """A MUTATING command: printed under --dry-run, executed otherwise.

        timeout is optional and defaults to none, because most mutations
        are ovn-nbctl calls that either return promptly or fail. Pass one
        for anything that talks to a DAEMON'S CONTROL SOCKET -- ovn-appctl
        in particular, which blocks indefinitely when ovn-controller is
        too busy to service it, and which will therefore hang a whole
        deploy at the exact moment the system is already struggling.
        """
        cmd = [str(a) for a in argv]
        if self.dry_run:
            print(format_cmd(cmd))
            return Result(0)
        self.changes += 1
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, input=stdin, check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # rc 124 matches timeout(1), so callers that only test .ok
            # behave as they always did.
            return Result(124, "", f"timed out after {timeout}s: "
                                   f"{format_cmd(cmd)}")
        except FileNotFoundError:
            res = Result(127, "", f"{cmd[0]}: command not found")
            if check:
                raise Abort(f"{cmd[0]}: command not found") from None
            return res
        res = Result(proc.returncode, (proc.stdout or "").strip(),
                     (proc.stderr or "").strip())
        if check and not res.ok:
            raise Abort(
                f"command failed ({res.returncode}): {format_cmd(cmd)}\n"
                f"{res.stderr}"
            )
        return res

    def q(self, *argv: object, timeout: float | None = None) -> Result:
        """A read-only QUERY.

        Never wrapped by dry-run: the printed command list has to reflect
        what would actually change given the current state of the system,
        which means the queries that decide that must really run.

        Always bounded. A hung query is worse than a failed one: `diagnose`
        runs twenty-odd checks and a single blocking ovn-sbctl call means
        none of the remaining ones ever report. Timing out yields a normal
        failed Result (rc 124, as timeout(1) uses), so every existing
        `if not res.ok` path already handles it.
        """
        cmd = [str(a) for a in argv]
        limit = self.query_timeout if timeout is None else timeout
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  check=False, timeout=limit)
        except FileNotFoundError:
            return Result(127, "", f"{cmd[0]}: command not found")
        except subprocess.TimeoutExpired:
            return Result(124, "",
                          f"timed out after {limit:g}s: {format_cmd(cmd)}")
        except OSError as exc:  # found, but not runnable (126, as a shell does)
            return Result(126, "", f"{cmd[0]}: {exc}")
        return Result(proc.returncode, (proc.stdout or "").strip(),
                      (proc.stderr or "").strip())

    def qout(self, *argv: object, timeout: float | None = None) -> str:
        """Query, returning stdout only ('' on failure)."""
        return self.q(*argv, timeout=timeout).stdout

    # ------------------------------------------------------------------
    # preconditions
    # ------------------------------------------------------------------
    def require_root(self) -> None:
        if self.dry_run or self.listing:
            return
        if os.geteuid() != 0:
            raise Abort("must be run as root (try: sudo ovnctl ...)")

    def require_cmd(self, *cmds: str) -> None:
        if self.listing:
            return
        missing = [c for c in cmds if shutil.which(c) is None]
        if missing:
            raise Abort(f"required command(s) not found: {' '.join(missing)}")

    @staticmethod
    def have(cmd: str) -> bool:
        return shutil.which(cmd) is not None

    # ------------------------------------------------------------------
    # systemd
    # ------------------------------------------------------------------
    def unit_exists(self, unit: str) -> bool:
        """Does a systemd unit exist?

        NOT "systemctl list-unit-files | grep -q": grep exits on the first
        match, systemctl takes SIGPIPE, and the pipeline then reports
        failure despite matching. Query the one unit and read the output.
        """
        if not self.have("systemctl"):
            return False
        res = self.q("systemctl", "list-unit-files", f"{unit}.service",
                     "--no-legend", "--no-pager")
        return bool(res.stdout.strip())

    def unit_active(self, unit: str) -> bool:
        if not self.have("systemctl"):
            return False
        return self.q("systemctl", "is-active", "--quiet", unit).ok


# Every shape northd compiles an ACL drop into. There are more than one,
# and which you get depends on options that have nothing to do with the
# verdict:
#
#   drop;                          stateless pipeline, unnamed ACL
#   ct_commit { ct_mark.blocked = 1; }
#                                  stateful pipeline, established branch
#   log(... verdict=drop); /* drop */
#                                  once the ACL carries a name or logging,
#                                  northd emits the log action and leaves
#                                  the drop implicit -- as a COMMENT. On the
#                                  new-connection branch (reg0[9]) there is
#                                  no ct_commit either, so NEITHER of the
#                                  first two forms appears anywhere.
#
# That last case is why naming the ACLs made every isolation check report
# "not blocked" on a deployment that was enforcing correctly: the drop was
# real, the packet died, and the only textual evidence was a C comment.
_DROP_MARKERS = (
    "ct_mark.blocked = 1",
    "/* drop */",
    "/* reject */",
    "verdict=drop",
    "verdict=reject",
)


def trace_verdict(output: str) -> str:
    """ALLOW / DROP / UNKNOWN from an ovn-trace.

    A drop reaches the trace in one of several forms depending on whether
    the pipeline is stateful and whether the ACL is named or logged -- see
    _DROP_MARKERS. Matching only "drop;" reports the others as ALLOW,
    which is the worst direction to be wrong in.

    UNKNOWN exists because this used to return ALLOW for ANY output it did
    not recognise -- including empty output. A trace that timed out, hit a
    parse error, or never ran at all was therefore indistinguishable from
    a packet that was permitted, and every caller reported it as a policy
    failure. On a large Southbound db ovn-trace is slow enough for that to
    be routine rather than exotic.

    So the ALLOW verdict now requires positive evidence: real ovn-trace
    output always contains an "ingress(dp=..." line. No pipeline, no
    verdict.
    """
    text = output.strip()
    if not text:
        return "UNKNOWN"
    # ovn-trace prefixes its own errors this way; normal output never does.
    for line in text.splitlines():
        if line.startswith("ovn-trace:") or line.startswith("timed out"):
            return "UNKNOWN"
    if any(marker in output for marker in _DROP_MARKERS):
        return "DROP"
    for line in output.splitlines():
        if re.match(r"^\s*(drop|reject)\s*[;{]", line.strip()):
            return "DROP"
    if "ingress(dp=" not in output:
        return "UNKNOWN"
    return "ALLOW"