"""
Suite layout resolution.

Ports the ``_ovn_pick`` / ``_ovn_find_settings`` / ``_ovn_find_state`` logic
from ovn-common.sh, ovn-config.sh and ovn-state.sh.

Two layouts are supported, exactly as before:

  split   <root>/configs/  <root>/state/  <root>/libraries/
  flat    everything beside the executable

Environment overrides (highest precedence first):
  OVN_CONFIG_FILE   explicit path to ovn-settings.yaml
  OVN_CONF_DIR      directory holding ovn-settings.yaml
  OVN_STATE_DIR     directory holding ovn-deploy-state
  OVN_STATE_FILE    explicit path to the tracker
  OVN_ROOT          the suite root, if not inferable from __file__
"""

from __future__ import annotations

import os
from pathlib import Path

SETTINGS_NAME = "ovn-settings.yaml"
RANGES_NAME = "ovn-internal-ranges.conf"
STATE_NAME = "ovn-deploy-state"


def suite_root() -> Path:
    """The directory the suite is installed under.

    ``ovnsuite/`` lives one level below the root, so the parent of the
    package directory is the root unless OVN_ROOT says otherwise.
    """
    env = os.environ.get("OVN_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    return Path(__file__).resolve().parent.parent


def _pick(root: Path, name: str) -> Path:
    """<root>/<name> if it is a directory, else <root> itself (flat layout)."""
    candidate = root / name
    return candidate if candidate.is_dir() else root


def conf_dir() -> Path:
    env = os.environ.get("OVN_CONF_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return _pick(suite_root(), "configs")


def state_dir() -> Path:
    env = os.environ.get("OVN_STATE_DIR")
    if env:
        return Path(env).expanduser().resolve()
    root = suite_root()
    # A sibling configs/ means the split layout is in use, so state/ is the
    # right home even if it has not been created yet.
    if (root / "state").is_dir() or (root / "configs").is_dir():
        return root / "state"
    return root


def settings_file() -> Path:
    env = os.environ.get("OVN_CONFIG_FILE")
    if env:
        return Path(env).expanduser().resolve()
    return conf_dir() / SETTINGS_NAME


def ranges_file() -> Path:
    env = os.environ.get("INTERNAL_RANGES_CONF")
    if env:
        return Path(env).expanduser().resolve()
    return conf_dir() / RANGES_NAME


def state_file() -> Path:
    env = os.environ.get("OVN_STATE_FILE")
    if env:
        return Path(env).expanduser().resolve()
    return state_dir() / STATE_NAME
