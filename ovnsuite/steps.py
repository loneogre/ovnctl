"""
Step framework.

The shell suite ran each script as an all-or-nothing sequence of
``step_N_*`` functions. Here those same steps are registered by name so a
single part can be re-run without executing the whole command:

    ovnctl setup --list-steps
    ovnctl setup --only host-interface
    ovnctl setup --from logical-router
    ovnctl setup --skip ovn-controller

Steps stay in declaration order regardless of the order they are named on
the command line -- selecting steps changes *which* run, never the
sequence, because the sequence is the part that has to hold.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Callable

from .context import Abort, Ctx


@dataclass
class Step:
    name: str
    desc: str
    fn: Callable[[], None]


class StepRunner:
    def __init__(self, ctx: Ctx, title: str = ""):
        self.ctx = ctx
        self.title = title
        self.steps: list[Step] = []
        # True once run() has executed a subset rather than the whole
        # sequence. Callers use it to decide whether recording the
        # component as deployed would be honest.
        self.partial = False

    def add(self, name: str, desc: str, fn: Callable[[], None]) -> None:
        self.steps.append(Step(name, desc, fn))

    # ------------------------------------------------------------------
    def names(self) -> list[str]:
        return [s.name for s in self.steps]

    def list_steps(self) -> None:
        heading = self.title or "steps"
        print(f"Available steps for {heading} (in run order):")
        width = max((len(s.name) for s in self.steps), default=0)
        for i, s in enumerate(self.steps, 1):
            print(f"  {i:2}. {s.name:<{width}}  {s.desc}")
        print("\nSelect with --only NAME[,NAME...], --from NAME, or --skip NAME[,NAME...].")

    # ------------------------------------------------------------------
    def _resolve(self, spec: str | None) -> list[str]:
        if not spec:
            return []
        wanted = [p.strip() for p in spec.split(",") if p.strip()]
        known = set(self.names())
        unknown = [w for w in wanted if w not in known]
        if unknown:
            raise Abort(
                f"unknown step(s): {', '.join(unknown)}\n"
                f"known steps: {', '.join(self.names())}"
            )
        return wanted

    def select(self, only: str | None = None, skip: str | None = None,
               start: str | None = None) -> list[Step]:
        chosen = self.steps
        if start:
            if start not in self.names():
                raise Abort(
                    f"unknown step: {start}\n"
                    f"known steps: {', '.join(self.names())}"
                )
            idx = self.names().index(start)
            chosen = chosen[idx:]
        only_set = set(self._resolve(only))
        if only_set:
            chosen = [s for s in chosen if s.name in only_set]
        skip_set = set(self._resolve(skip))
        if skip_set:
            chosen = [s for s in chosen if s.name not in skip_set]
        return chosen

    def run(self, args: argparse.Namespace) -> bool:
        """Execute the selected steps. Returns False if only listing."""
        if getattr(args, "list_steps", False):
            self.list_steps()
            return False

        chosen = self.select(
            only=getattr(args, "only", None),
            skip=getattr(args, "skip", None),
            start=getattr(args, "start_at", None),
        )
        if not chosen:
            raise Abort("no steps selected")

        self.partial = len(chosen) != len(self.steps)
        if self.partial:
            self.ctx.log(
                f"Partial run: {len(chosen)} of {len(self.steps)} step(s) -- "
                + ", ".join(s.name for s in chosen)
            )
        for step in chosen:
            self.ctx.log(f"--- step: {step.name} ({step.desc})")
            step.fn()
        return True


def add_step_args(parser: argparse.ArgumentParser) -> None:
    """Attach the step-selection flags to a subcommand parser."""
    group = parser.add_argument_group("step selection")
    group.add_argument("--list-steps", action="store_true",
                       help="list this command's steps and exit")
    group.add_argument("--only", metavar="NAME[,NAME...]",
                       help="run only these steps")
    group.add_argument("--skip", metavar="NAME[,NAME...]",
                       help="run everything except these steps")
    group.add_argument("--from", dest="start_at", metavar="NAME",
                       help="start at this step and run to the end")
