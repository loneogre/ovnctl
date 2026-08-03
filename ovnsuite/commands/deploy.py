"""
ovnctl deploy -- port of ovn-deploy.sh

Runs the deployment in order. Required stages abort the run if they fail;
optional stages report and continue, so a missing host-side tool (no
libvirt CLI, no tcpdump) cannot silently swallow everything after it.

    ovnctl deploy                    the whole thing
    ovnctl -n deploy                 preview every command
    ovnctl deploy --list-steps       the stage list
    ovnctl deploy --from vm-config   resume a partial deployment
    ovnctl deploy --skip pcap        everything except the capture mirrors
    ovnctl deploy --verify           run diagnose afterwards

Each stage is the corresponding subcommand, re-entered in-process with
the same global flags, so ``ovnctl deploy --from acl`` and ``ovnctl acl``
do exactly the same work.
"""

from __future__ import annotations

import argparse
import os
import sys

from ..context import Abort, Ctx
from ..steps import StepRunner, add_step_args

NAME = "deploy"
HELP = "run the full deployment, in order"

REQUIRED = "required"
OPTIONAL = "optional"

# (step name, subcommand argv, kind, description) -- the order is the
# deployment order and it is the reason this command exists.
STAGES = (
    ("setup", ["setup"], REQUIRED,
     "base topology, host segment, logical router"),
    ("localnet-internal", ["localnet-internal"], REQUIRED,
     "br-internal uplink to the workstation LAN"),
    ("localnet-external", ["localnet-external"], REQUIRED,
     "ASA reroute policy tiers"),
    ("vm-config", ["vm-config"], REQUIRED,
     "VM logical switch ports"),
    ("vm-isolation", ["vm-isolation"], REQUIRED,
     "isolation port group and its scoped ACLs"),
    ("acl", ["acl"], REQUIRED,
     "micro-segmentation ACLs"),
    # Rebuilds the user-VM segment and every allocated slot from
    # state/user-vms.json. REQUIRED, not optional: `delete --purge-db`
    # wipes the logical ports while the operator-owned libvirt domains
    # keep pointing at their UUIDs, so a deploy that skipped this would
    # leave those VMs silently disconnected with no error anywhere. It is
    # a no-op when nothing is allocated.
    ("user-vm", ["user-vm", "--reapply"], REQUIRED,
     "user-VM slots recorded in state/user-vms.json"),
    # Boot persistence. Nothing in the deployment depends on it, and
    # nothing fails today if it is missing -- which is exactly why it got
    # skipped: the only symptom is that the next reboot drops the runtime
    # state, and by then whoever ran the deploy has moved on. Installing
    # it every time costs a file write and makes the omission impossible.
    #
    # OPTIONAL because a host without systemd, or with a read-only /etc,
    # must still be able to complete a deployment; --install-unit already
    # returns non-zero rather than raising in those cases. A skip here is
    # called out by name in the summary instead of scrolling past as one
    # more WARN line.
    ("persistence", ["reconcile", "--install-unit"], OPTIONAL,
     "boot-time reconcile unit (ovn-reconcile.service)"),
    # Host-side helpers. These depend on things outside OVN (libvirt,
    # tcpdump, running VMs) and are expected to no-op on some hosts.
    ("vm-attach", ["vm-attach"], OPTIONAL,
     "re-attach running VM taps"),
    ("pcap", ["pcap", "--start"], OPTIONAL,
     "packet capture mirrors"),
)


def register(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(NAME, help=HELP, description=__doc__,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--verify", action="store_true",
                   help="run 'ovnctl diagnose' once the deployment finishes")
    add_step_args(p)
    p.set_defaults(func=main)
    return p


class _Colour:
    """ANSI codes, but only when stdout is a terminal and NO_COLOR is unset."""

    def __init__(self) -> None:
        enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.red = "\033[31m" if enabled else ""
        self.grn = "\033[32m" if enabled else ""
        self.ylw = "\033[33m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.rst = "\033[0m" if enabled else ""


def _passthru(args: argparse.Namespace) -> list[str]:
    """The global flags this invocation was given, to hand to each stage."""
    out: list[str] = []
    if getattr(args, "verbose", False):
        out.append("--verbose")
    if getattr(args, "dry_run", False):
        out.append("--dry-run")
    if getattr(args, "config", None):
        out += ["--config", args.config]
    if getattr(args, "state_file", None):
        out += ["--state-file", args.state_file]
    if getattr(args, "no_color", False):
        out.append("--no-color")
    return out


class Deploy:
    def __init__(self, ctx: Ctx, args: argparse.Namespace):
        self.ctx = ctx
        self.args = args
        self.c = _Colour()
        self.passthru = _passthru(args)
        self.ok: list[str] = []
        self.skipped: list[str] = []
        self.failed: list[str] = []

    # ------------------------------------------------------------------
    def banner(self, text: str) -> None:
        if self.ctx.dry_run:
            # In a dry run the output is a command listing; a banner has
            # to be a comment or the result is not pasteable.
            print(f"\n# ===== {text} =====")
        else:
            print(f"\n{self.c.bold}===== {text} ====={self.c.rst}")

    def _invoke(self, argv: list[str]) -> int:
        """Re-enter the CLI in-process.

        A fresh Ctx per stage is deliberate: the change counter, the
        warning counter and the log prefix are per-command, exactly as
        they were when these were separate processes.
        """
        from .. import cli  # local import: cli imports this module

        try:
            return cli.run_argv(self.passthru + argv)
        except Abort as exc:
            print(f"[{argv[0]}] ERROR: {exc.message}", file=sys.stderr)
            return exc.code
        except SystemExit as exc:  # argparse inside a stage
            return int(exc.code or 0)

    def stage(self, label: str, argv: list[str], kind: str) -> None:
        # The stage's own name, not its argv. A stage whose command needs a
        # flag ("user-vm --reapply") otherwise announces itself as
        # something the operator did not ask for and has never run, which
        # reads as the deploy doing something surprising rather than as a
        # step with an unfortunate flag name.
        self.banner(label)
        rc = self._invoke(argv)
        if rc == 0:
            self.ok.append(label)
            return
        if kind == REQUIRED:
            self.failed.append(f"{label} (exit {rc})")
            raise Abort(
                f"{self.c.red}FAILED{self.c.rst}  {label} (exit {rc}) -- "
                "required, aborting."
            )
        print(f"{self.c.ylw}WARN{self.c.rst}    {label} exited {rc} -- "
              "optional, continuing.", file=sys.stderr)
        self.skipped.append(f"{label} (exit {rc})")

    # ------------------------------------------------------------------
    def summary(self) -> None:
        self.banner("Summary")
        parts = [f"{self.c.grn}{len(self.ok)} completed{self.c.rst}"]
        if self.skipped:
            parts.append(f"{self.c.ylw}{len(self.skipped)} skipped{self.c.rst}")
        if self.failed:
            parts.append(f"{self.c.red}{len(self.failed)} failed{self.c.rst}")
        print(", ".join(parts))
        for s in self.skipped:
            print(f"  skipped: {s}")
        for s in self.failed:
            print(f"  failed:  {s}")
        print("")

        # A skipped optional stage is usually fine. This one is not: it is
        # the only stage whose absence has no effect until the host next
        # reboots, at which point the runtime state is gone and the deploy
        # that failed to install it is long forgotten.
        if any(s.startswith("persistence") for s in self.skipped + self.failed):
            print(f"{self.c.ylw}The boot-time reconcile unit was NOT "
                  f"installed.{self.c.rst}")
            print("Everything deployed will be lost on reboot until you "
                  "run:")
            print("  ovnctl reconcile --install-unit")
            print("")

        print("Verify with:  ovnctl diagnose")


def main(ctx: Ctx, args: argparse.Namespace) -> int:
    ctx.prefix = "ovn-deploy"

    dep = Deploy(ctx, args)
    runner = StepRunner(ctx, "deploy")
    for name, argv, kind, desc in STAGES:
        suffix = "" if kind == REQUIRED else "  [optional]"
        runner.add(
            name, f"{desc}{suffix}",
            # default-arg binding, not a closure over the loop variable
            lambda n=name, a=argv, k=kind: dep.stage(n, a, k),
        )

    try:
        if not runner.run(args):
            return 0
    except Abort:
        # A required stage failed. Still print the tally -- knowing which
        # stages got through is the first thing you need in order to fix
        # it, and losing that to a bare abort makes the failure harder to
        # act on than it needs to be.
        dep.summary()
        return 1

    dep.summary()

    if args.verify:
        dep.banner("diagnose")
        rc = dep._invoke(["diagnose"])
        if rc != 0:
            print(f"[ovn-deploy] diagnose reported problems (exit {rc}).",
                  file=sys.stderr)
            return rc

    return 1 if dep.failed else 0
