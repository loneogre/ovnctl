"""
ovnctl -- the single entry point for the suite.

Every original script is a subcommand, and every subcommand is further
divided into named steps:

    ovnctl --help                     the subcommand list
    ovnctl setup --list-steps         what setup does, step by step
    ovnctl setup --only host-interface
    ovnctl localnet-external --from policy
    ovnctl -n deploy                  preview the whole deployment

Global flags come before the subcommand (``ovnctl -n setup``), but for
muscle-memory reasons they are also accepted after it (``ovnctl setup
-n``) -- see _split_globals.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys

from . import __version__, paths
from .commands import MODULES
from .config import ConfigError
from .context import Abort, Ctx

PROG = "ovnctl"

EPILOG = """\
examples:
  ovnctl deploy                     run the full deployment in order
  ovnctl -n deploy                  preview it without changing anything
  ovnctl setup --list-steps         list the steps of one command
  ovnctl setup --only switches      re-run a single step
  ovnctl localnet-external --trace  verify the policy tiers with ovn-trace
  ovnctl diagnose                   layer-by-layer health check
  ovnctl show switches              read-only view of the logical topology
  ovnctl runbook -o runbook.sh      emit a copy-pasteable command list
  ovnctl delete --purge-db          tear everything down

Configuration is read from:
  {settings}
Override with --config PATH, or the OVN_CONFIG_FILE / OVN_CONF_DIR
environment variables.
"""

# Global flags that may also legally appear after the subcommand.
_GLOBAL_FLAGS = {"-v", "--verbose", "-n", "--dry-run", "--no-color",
                 "--no-colour"}
_GLOBAL_OPTS = {"--config", "--state-file"}


def _load(module_name: str):
    return importlib.import_module(f".commands.{module_name}", __package__)


def build_parser() -> argparse.ArgumentParser:
    try:
        settings = str(paths.settings_file())
    except Exception:  # never let help rendering fail on a path problem
        settings = "<unresolved>"

    parser = argparse.ArgumentParser(
        prog=PROG,
        description="OVN lab deployment, diagnostics and teardown.",
        epilog=EPILOG.format(settings=settings),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="narrate every step (default: one summary line)")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="print the commands that would run, change nothing")
    parser.add_argument("--config", metavar="PATH",
                        help=f"path to ovn-settings.yaml (default: {settings})")
    parser.add_argument("--state-file", metavar="PATH",
                        help="path to the deployment tracker")
    parser.add_argument("--no-color", "--no-colour", dest="no_color",
                        action="store_true", help="never emit ANSI colour")
    parser.add_argument("--version", action="version",
                        version=f"{PROG} {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    for module_name in MODULES:
        _load(module_name).register(subparsers)
    return parser


def _split_globals(argv: list[str]) -> list[str]:
    """Hoist post-subcommand global flags to the front.

    argparse puts global options on the root parser only, so ``ovnctl
    setup -n`` would otherwise be an error. Everyone types it that way,
    so accept it: pull the known global flags out and re-insert them
    ahead of the subcommand. Anything after a bare ``--`` is left alone.
    """
    globals_found: list[str] = []
    rest: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            rest.extend(argv[i:])
            break
        if tok in _GLOBAL_FLAGS and rest:
            globals_found.append(tok)
        elif tok in _GLOBAL_OPTS and rest and i + 1 < len(argv):
            globals_found.extend([tok, argv[i + 1]])
            i += 1
        else:
            rest.append(tok)
        i += 1
    return globals_found + rest


def _apply_path_overrides(args: argparse.Namespace) -> None:
    """--config / --state-file are just friendlier spellings of the env
    variables the path resolver already honours."""
    if getattr(args, "config", None):
        os.environ["OVN_CONFIG_FILE"] = os.path.abspath(
            os.path.expanduser(args.config))
    if getattr(args, "state_file", None):
        os.environ["OVN_STATE_FILE"] = os.path.abspath(
            os.path.expanduser(args.state_file))
    if getattr(args, "no_color", False):
        os.environ["NO_COLOR"] = "1"


def run_argv(argv: list[str]) -> int:
    """Parse and dispatch one invocation. Used by ovnctl deploy/runbook to
    re-enter the CLI in-process instead of re-executing the interpreter."""
    parser = build_parser()
    args = parser.parse_args(_split_globals(argv))

    if not getattr(args, "command", None) or not hasattr(args, "func"):
        parser.print_help()
        return 2

    _apply_path_overrides(args)
    ctx = Ctx(verbose=args.verbose, dry_run=args.dry_run,
              listing=bool(getattr(args, "list_steps", False)))
    rc = args.func(ctx, args)
    return 0 if rc is None else int(rc)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return run_argv(argv)
    except Abort as exc:
        print(f"[{PROG}] ERROR: {exc.message}", file=sys.stderr)
        return exc.code
    except ConfigError as exc:
        print(f"[{PROG}] ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # `ovnctl show | head` -- not an error worth a traceback.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
