"""
ovnctl runbook -- port of ovn-runbook.sh

Emits every command the automation would run, as a single clean,
copy-pasteable shell script. Unlike ``--dry-run`` on one subcommand (a
single component) or ``ovnctl -n deploy`` (chained, with banners), this
produces a self-contained runbook you can hand to someone who does not
have the tooling, paste into a change record, or diff between two
configurations.

IMPORTANT: the output reflects the CURRENT state of the system, because
every subcommand queries before deciding what to change. On a fully
deployed host you get only the delta. For the full build sequence,
generate it from a clean host, or after a teardown.

    ovnctl runbook                  deployment commands to stdout
    ovnctl runbook -o runbook.sh    write to a file
    ovnctl runbook --teardown       the teardown sequence instead
    ovnctl runbook --all            deployment then teardown
    ovnctl runbook --no-header      commands only, no comments
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import socket
import subprocess
from datetime import datetime
from pathlib import Path

from ..context import Abort, Ctx

NAME = "runbook"
HELP = "emit every command as a copy-pasteable shell script"

RULE = "=" * 74
HARD_RULE = "#" * 74

# (argv, description) -- the order matters, it is the deployment order.
DEPLOY_STEPS = (
    (["setup"], "base topology, host segment, logical router"),
    (["localnet-internal"], "br-internal uplink to the workstation LAN"),
    (["localnet-external"], "ASA split path + policy tiers"),
    (["vm-config"], "VM logical switch ports"),
    (["vm-isolation"], "isolation port group and its scoped ACLs"),
    (["acl"], "micro-segmentation ACLs"),
    (["vm-attach"], "re-attach running VM taps"),
    (["pcap", "--start"], "packet capture mirrors"),
)

TEARDOWN_STEPS = (
    (["delete"], "remove everything this deployment created"),
)


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--teardown", action="store_true",
                      help="emit the teardown sequence instead")
    mode.add_argument("--all", action="store_true",
                      help="emit deployment, then teardown")
    p.add_argument("--no-header", dest="header", action="store_false",
                   default=True,
                   help="commands only -- no comments, no shebang")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write to FILE (and make it executable)")
    p.set_defaults(func=main)
    return p


# ---------------------------------------------------------------------------
def _capture(argv: list[str], passthru: list[str]) -> tuple[str, int]:
    """Run one subcommand in dry-run and capture what it would print.

    stderr is discarded on purpose: warnings about the live system are
    noise in a document that is meant to be a command list. The exit
    code comes back so an empty-and-failed generation can be reported
    rather than silently producing a gap in the runbook.
    """
    from .. import cli  # local import: cli imports this module

    buf = io.StringIO()
    rc = 0
    try:
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = cli.run_argv(passthru + ["--dry-run"] + argv)
    except Abort as exc:
        rc = exc.code
    except SystemExit as exc:
        rc = int(exc.code or 0)
    except Exception:
        # One component failing to generate must not lose the rest of the
        # runbook; the section note below records that it happened.
        rc = 1
    return buf.getvalue().rstrip("\n"), rc


def _strip_comments(body: str) -> str:
    keep = [ln for ln in body.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]
    return "\n".join(keep)


def _chassis_id() -> str:
    try:
        res = subprocess.run(
            ["ovs-vsctl", "get", "open", ".", "external-ids:system-id"],
            capture_output=True, text=True, check=False)
        return res.stdout.strip().strip('"')
    except (OSError, subprocess.SubprocessError):
        return ""


class Runbook:
    def __init__(self, ctx: Ctx, args: argparse.Namespace):
        self.ctx = ctx
        self.header = args.header
        self.lines: list[str] = []
        self.passthru: list[str] = []
        if getattr(args, "config", None):
            self.passthru += ["--config", args.config]
        if getattr(args, "state_file", None):
            self.passthru += ["--state-file", args.state_file]
        # Colour would end up as escape sequences inside the document.
        self.passthru.append("--no-color")

    def emit(self, *lines: str) -> None:
        self.lines.extend(lines)

    # ------------------------------------------------------------------
    def emit_header(self) -> None:
        if not self.header:
            return
        try:
            when = datetime.now().astimezone().isoformat(timespec="seconds")
        except Exception:
            when = datetime.now().isoformat(timespec="seconds")
        try:
            host = socket.gethostname()
        except OSError:
            host = "unknown"
        chassis = _chassis_id() or "<not set>"

        self.emit(
            "#!/usr/bin/env bash",
            "#",
            "# OVN lab -- manual command runbook",
            "#",
            f"# Generated : {when}",
            f"# Host      : {host}",
            f"# Chassis   : {chassis}",
            f"# Settings  : {self.ctx.cfg_file}",
            "#",
            "# These are the exact commands the automation would run, in order.",
            "# They reflect the state of the system at generation time -- anything",
            "# already configured is absent, so on a fully deployed host this shows",
            "# only the remaining delta.",
            "#",
            "# Review before running. Nothing here is idempotent-checked once it is",
            "# separated from the scripts that generated it.",
            "",
            "set -euo pipefail",
            "",
        )

    def emit_section(self, label: str, description: str, body: str) -> None:
        if self.header:
            self.emit(f"# {RULE}", f"# {label}", f"# {description}",
                      f"# {RULE}", "")
        else:
            body = _strip_comments(body)

        if not body.strip():
            if self.header:
                self.emit("# (nothing to do -- already in the desired state)", "")
            return
        self.emit(body, "")

    def run_steps(self, steps) -> None:
        for argv, description in steps:
            label = "ovnctl " + " ".join(argv)
            body, rc = _capture(argv, self.passthru)
            if rc != 0 and not body.strip():
                if self.header:
                    self.emit(
                        f"# --- {label}: exited {rc} during generation, "
                        "no commands captured ---", "")
                continue
            self.emit_section(label, description, body)

    def generate(self, mode: str) -> str:
        self.emit_header()
        if mode == "deploy":
            self.run_steps(DEPLOY_STEPS)
        elif mode == "teardown":
            self.run_steps(TEARDOWN_STEPS)
        else:  # all
            self.run_steps(DEPLOY_STEPS)
            if self.header:
                self.emit(
                    f"# {HARD_RULE}",
                    "# TEARDOWN -- everything below REVERSES everything above.",
                    f"# {HARD_RULE}", "")
            self.run_steps(TEARDOWN_STEPS)
        text = "\n".join(self.lines).rstrip("\n")
        return text + "\n" if text else ""


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    # Load the settings so the header can report which file this was built
    # from -- the runbook is only meaningful alongside its configuration.
    ctx.load_config("ovn-runbook")

    mode = "teardown" if args.teardown else ("all" if args.all else "deploy")

    # This command generates text; it never touches the system itself, so
    # a global --dry-run has nothing to suppress here.
    was_dry, ctx.dry_run = ctx.dry_run, False
    try:
        text = Runbook(ctx, args).generate(mode)
    finally:
        ctx.dry_run = was_dry

    if not args.output:
        print(text, end="")
        return 0

    path = Path(os.path.expanduser(args.output))
    try:
        path.write_text(text)
        path.chmod(path.stat().st_mode | 0o111)
    except OSError as exc:
        raise Abort(f"cannot write {path}: {exc}") from exc

    count = len([ln for ln in text.splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")])
    print(f"[ovn-runbook] Wrote {path} ({count} commands)")
    return 0
