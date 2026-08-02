"""
Loader for ovn-settings.yaml.

This is a faithful port of the awk parser in ovn-config.sh, NOT a general
YAML reader. It deliberately understands only the strict subset documented
at the top of the settings file:

  * two levels only: top-level section, then "  key: value"
  * lists: "  key:" on its own line, then '    - "item"' entries
  * scalar values may be quoted or bare
  * comments start with # (full-line, or after an UNQUOTED value)
  * no anchors, no deeper nesting, no multi-line values

Using PyYAML here would be a behaviour change, not a simplification: the
real file contains constructs the strict parser reads one way and a full
YAML parser reads another (bare values with '#' after them, "key: []" as a
list header that later "- item" lines still append to, duplicated keys in
the commented examples). Matching the original parser exactly means a
config that worked with the shell suite works here unchanged.

Every value lands under a (section, key) tuple, holding either a str
(scalar) or a list[str] (list).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from . import paths

# "name:" on a line of its own, optionally followed by a comment.
_SECTION_RE = re.compile(r"^[A-Za-z0-9_]+:[ \t]*(#.*)?$")
# "    - value"  (a space or tab is required after the dash)
_LIST_ITEM_RE = re.compile(r"^[ \t]+-[ \t]")
# "  key: ..." or "  key:"
_KEY_RE = re.compile(r"^[ \t]+[A-Za-z0-9_]+:")

_TRAILING_COMMENT_RE = re.compile(r"[ \t]+#.*$")


class ConfigError(Exception):
    """A missing or malformed required setting."""


def _strip_value(v: str) -> str:
    """Port of the awk strip() function.

    A quoted value ends at its CLOSING quote and the rest of the line is
    discarded -- without that, a trailing comment containing a quote gets
    swallowed into the value.
    """
    v = v.rstrip("\r")
    v = v.lstrip(" \t")
    if v.startswith('"'):
        rest = v[1:]
        idx = rest.find('"')
        return rest[:idx] if idx >= 0 else rest
    if v.startswith("'"):
        rest = v[1:]
        idx = rest.find("'")
        return rest[:idx] if idx >= 0 else rest
    v = _TRAILING_COMMENT_RE.sub("", v)
    return v.rstrip(" \t")


class Config:
    """Parsed ovn-settings.yaml with the accessors the shell suite used."""

    def __init__(self, path: Path | None = None):
        self.path: Path = Path(path) if path else paths.settings_file()
        self.values: dict[tuple[str, str], str | list[str]] = {}
        self.loaded = False

    # ------------------------------------------------------------------
    # loading
    # ------------------------------------------------------------------
    def load(self) -> "Config":
        if not self.path.is_file():
            raise ConfigError(
                f"settings file not found: {self.path}\n"
                "This is required -- there are no built-in defaults.\n"
                "Expected layout: <root>/configs/ovn-settings.yaml\n"
                "Override with OVN_CONFIG_FILE=/path/to/ovn-settings.yaml"
            )
        self.values = self._parse(self.path.read_text(encoding="utf-8", errors="replace"))
        self.loaded = True
        return self

    @staticmethod
    def _parse(text: str) -> dict[tuple[str, str], str | list[str]]:
        values: dict[tuple[str, str], str | list[str]] = {}
        section = ""
        listkey = ""

        for raw in text.splitlines():
            if not raw.strip():
                continue
            if raw.lstrip().startswith("#"):
                continue

            if _SECTION_RE.match(raw):
                section = raw.split(":", 1)[0]
                listkey = ""
                continue

            if _LIST_ITEM_RE.match(raw):
                if not section or not listkey:
                    continue
                val = re.sub(r"^[ \t]+-[ \t]*", "", raw)
                val = _strip_value(val)
                bucket = values.setdefault((section, listkey), [])
                if isinstance(bucket, list):
                    bucket.append(val)
                continue

            if _KEY_RE.match(raw):
                if not section:
                    continue
                line = raw.lstrip(" \t")
                key = line.split(":", 1)[0]
                val = re.sub(r"^[^:]*:[ \t]*", "", line).rstrip(" \t")

                # "key:" alone, "key: []", or "key: # comment" -> a LIST.
                # Keeping listkey set means later "- item" lines still
                # append correctly (e.g. after someone uncomments the
                # examples below the key).
                if val == "" or val.startswith("#") or val == "[]":
                    listkey = key
                    values.setdefault((section, key), [])
                    continue

                listkey = ""
                values[(section, key)] = _strip_value(val)
                continue

        return values

    # ------------------------------------------------------------------
    # accessors
    # ------------------------------------------------------------------
    def has(self, section: str, key: str) -> bool:
        return (section, key) in self.values

    def cfg(self, section: str, key: str) -> str:
        """A REQUIRED setting.

        A missing key is a configuration error, not something to paper over
        with a built-in default that silently disagrees with the yaml the
        operator is reading.
        """
        try:
            val = self.values[(section, key)]
        except KeyError:
            raise ConfigError(
                f"required setting [{section}].{key} is missing from {self.path}"
            ) from None
        if isinstance(val, list):
            # Mirrors bash "${!var}" on an array: the first element.
            return val[0] if val else ""
        return val

    def cfg_opt(self, section: str, key: str, default: str = "") -> str:
        """A genuinely OPTIONAL setting -- absent means 'not configured'."""
        val = self.values.get((section, key))
        if val is None:
            return default
        if isinstance(val, list):
            return val[0] if val else default
        return val

    def cfg_int(self, section: str, key: str) -> int:
        raw = self.cfg(section, key)
        try:
            return int(str(raw).strip())
        except ValueError:
            raise ConfigError(
                f"[{section}].{key} must be an integer, got {raw!r}"
            ) from None

    def cfg_int_opt(self, section: str, key: str, default: int) -> int:
        raw = self.cfg_opt(section, key, "")
        if raw == "":
            return default
        try:
            return int(str(raw).strip())
        except ValueError:
            return default

    def cfg_bool(self, section: str, key: str, default: bool = False) -> bool:
        raw = self.cfg_opt(section, key, "").strip().lower()
        if raw == "":
            return default
        return raw in ("true", "yes", "1", "on")

    def cfg_array(self, section: str, key: str) -> list[str] | None:
        """Return a configured list, or None if absent or empty.

        None (rather than []) lets callers keep their own defaults, exactly
        like the shell version's ``cfg_array DEST section key || true``.
        """
        val = self.values.get((section, key))
        if val is None:
            return None
        if isinstance(val, str):
            return [val] if val else None
        return list(val) if val else None

    def cfg_list(self, section: str, key: str) -> list[str]:
        """Same as cfg_array but always a list (possibly empty)."""
        return self.cfg_array(section, key) or []

    def require(self, *pairs: str) -> None:
        """Validate every required setting BEFORE anything is changed.

        Each argument is "section:key". Checking up front turns what would
        otherwise be a silent empty value into one clear failure listing
        every missing key.
        """
        missing: list[str] = []
        for pair in pairs:
            section, _, key = pair.partition(":")
            if not self.has(section, key):
                missing.append(f"[{section}].{key}")
        if missing:
            detail = "\n".join(f"         {m}" for m in missing)
            raise ConfigError(
                f"missing required setting(s) in {self.path}:\n{detail}"
            )

    # ------------------------------------------------------------------
    # in-place editors
    # ------------------------------------------------------------------
    # These let a command update ovn-settings.yaml at runtime (e.g. adding
    # an engagement's target subnet) without hand-editing. They operate on
    # the same strict subset the parser understands.
    #
    # NOTE: an emptied list is left as a bare "key:" rather than "key: []".
    # Both are read as an empty list by this parser.

    def _lines(self) -> list[str]:
        return self.path.read_text(encoding="utf-8").splitlines(keepends=True)

    def _write(self, lines: Iterable[str]) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text("".join(lines), encoding="utf-8")
        tmp.replace(self.path)

    def scalar_set(self, section: str, key: str, value: str) -> None:
        out: list[str] = []
        insec = False
        key_re = re.compile(rf"^([ \t]+){re.escape(key)}:")
        for line in self._lines():
            bare = line.rstrip("\n")
            if _SECTION_RE.match(bare):
                insec = bare.split(":", 1)[0] == section
            if insec:
                m = key_re.match(bare)
                if m:
                    out.append(f"{m.group(1)}{key}: {value}\n")
                    continue
            out.append(line)
        self._write(out)
        self.values[(section, key)] = value

    def list_add(self, section: str, key: str, value: str) -> bool:
        """Append an item to a list. No-op (returns False) if already present."""
        current = self.cfg_list(section, key)
        if value in current:
            return False

        out: list[str] = []
        insec = False
        done = False
        key_re = re.compile(rf"^[ \t]+{re.escape(key)}:")
        for line in self._lines():
            bare = line.rstrip("\n")
            if _SECTION_RE.match(bare):
                insec = bare.split(":", 1)[0] == section
            if insec and not done and key_re.match(bare):
                # "key: []" becomes "key:" so the item below is parsed.
                out.append(re.sub(r":[ \t]*\[\][ \t]*$", ":", bare) + "\n")
                out.append(f'    - "{value}"\n')
                done = True
                continue
            out.append(line)
        self._write(out)
        self.values.setdefault((section, key), [])
        bucket = self.values[(section, key)]
        if isinstance(bucket, list):
            bucket.append(value)
        return True

    def list_del(self, section: str, key: str, value: str) -> bool:
        out: list[str] = []
        insec = False
        inlist = False
        removed = False
        key_re = re.compile(rf"^[ \t]+{re.escape(key)}:")
        for line in self._lines():
            bare = line.rstrip("\n")
            if _SECTION_RE.match(bare):
                insec = bare.split(":", 1)[0] == section
                inlist = False
            if insec and key_re.match(bare):
                inlist = True
                out.append(line)
                continue
            if insec and inlist and _KEY_RE.match(bare):
                inlist = False
            if insec and inlist and _LIST_ITEM_RE.match(bare):
                v = re.sub(r"^[ \t]+-[ \t]*", "", bare)
                v = v.strip().strip('"').rstrip()
                if v == value:
                    removed = True
                    continue
            out.append(line)
        self._write(out)
        bucket = self.values.get((section, key))
        if isinstance(bucket, list) and value in bucket:
            bucket.remove(value)
        return removed


# ---------------------------------------------------------------------------
# legacy ovn-internal-ranges.conf
# ---------------------------------------------------------------------------
_ARRAY_ENTRY_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'|(\S+)')


def load_legacy_ranges(path: Path) -> list[str]:
    """Read OUR_INTERNAL_RANGES=( ... ) out of the legacy conf file.

    The original sourced this as shell. Parsing it instead means a stray
    command in that file cannot execute -- and the file only ever contains
    a single array.
    """
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"OUR_INTERNAL_RANGES=\((.*?)\)", text, re.S)
    if not m:
        return []
    body = m.group(1)
    ranges: list[str] = []
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for match in _ARRAY_ENTRY_RE.finditer(line):
            token = match.group(1) or match.group(2) or match.group(3)
            if token:
                ranges.append(token)
    return ranges
