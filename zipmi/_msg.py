"""
zipmi.cli._msg — leveled, colored diagnostic lines on stderr.

WHAT   `info/warn/error/ok(msg)` print a colored `[level]` tag + message to
       stderr. RESULTS (the data a user pipes/greps) stay on stdout; everything
       else — progress, warnings, errors, findings — goes here, to stderr.
WHY    One consistent channel + vocabulary for diagnostics across the CLI, so a
       user can `2>/dev/null` to silence chatter and keep clean results, and a
       tty user gets color-coded severity. Reuses the existing color policy in
       scapy_ipmi.colorize (NO_COLOR / FORCE_COLOR / -n / tty) — no second knob.

Home: package root so both the library (core) and CLI can use it.
Migration: new code should call these instead of `print(..., file=sys.stderr)`.
Existing commands are being moved over incrementally.
"""
from __future__ import annotations

import sys

from .scapy_ipmi.colorize import color_enabled, _ansi, _RESET

# level -> (tag, rgb). Colors chosen to read on dark terminals (the common case)
# and to match intuition: blue=info, yellow=warn, red=error, green=ok.
_LEVELS: dict[str, tuple[str, tuple[int, int, int]]] = {
    "info":  ("[info]",  (0x87, 0xAF, 0xFF)),   # blue
    "warn":  ("[warn]",  (0xFF, 0xD7, 0x5F)),   # yellow
    "error": ("[error]", (0xFF, 0x5F, 0x5F)),   # red
    "ok":    ("[ok]",    (0x87, 0xD7, 0x87)),   # green
}
_TAGW = max(len(tag) for tag, _ in _LEVELS.values())   # align messages in a column

# None = auto (color_enabled on the target stream); True/False = forced by the CLI
# from -n/--no-color. Set once in main() via configure().
_forced: bool | None = None


def configure(enabled: bool | None) -> None:
    """Force color on (True), off (False), or auto (None, the default policy)."""
    global _forced
    _forced = enabled


def _use_color(stream) -> bool:
    return color_enabled(stream) if _forced is None else _forced


def emit(level: str, msg: str, *, stream=None) -> None:
    tag, rgb = _LEVELS[level]
    stream = stream if stream is not None else sys.stderr
    shown = f"{_ansi(rgb)}{tag}{_RESET}" if _use_color(stream) else tag
    # Pad on the PLAIN tag length — the ANSI escapes have zero display width, so
    # ljust on the colored string would misalign. +1 for the gap before the text.
    pad = " " * (_TAGW - len(tag) + 1)
    print(f"{shown}{pad}{msg}", file=stream, flush=True)


def info(msg: str, *, stream=None) -> None:
    emit("info", msg, stream=stream)


def warn(msg: str, *, stream=None) -> None:
    emit("warn", msg, stream=stream)


def error(msg: str, *, stream=None) -> None:
    emit("error", msg, stream=stream)


def ok(msg: str, *, stream=None) -> None:
    emit("ok", msg, stream=stream)
