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


def ascii_or_none(data: bytes) -> str | None:
    """Return `data` decoded as ASCII if it is a printable string (allowing
    trailing NUL / 0xFF / whitespace padding), else None.

    Purpose: many IPMI/OEM responses are plain strings — firmware build tags
    (`BL_SUPERMICRO_X7SB3_2014-04-18_B`), version strings, asset/name fields —
    that the CLI otherwise surfaces only as a hex row. Decoding it next to the
    hex saves the manual `hex -> ascii` step. Conservative on purpose: decodes
    only when EVERY non-padding byte is printable ASCII, so binary/status
    responses (a lone 0x00, a bitmask, a struct) are left as hex, not mojibake.
    """
    if not data:
        return None
    trimmed = data.rstrip(b"\x00\xff \t\r\n")
    if len(trimmed) < 2:                       # a lone char is noise, not a string
        return None
    if all(0x20 <= b <= 0x7E for b in trimmed):
        return trimmed.decode("ascii")
    return None


def hex_dump_lines(data: bytes, *, width: int = 16, base: int = 0) -> list[str]:
    """hexdump-style two-line-per-row view: a hex row and, directly under it,
    an ASCII row (printable byte -> its char, non-printable -> '.'), aligned
    per byte. Returns a flat list [hex, ascii, hex, ascii, ...], `width` bytes
    per row, with a 4-hex offset column.

        0000  00 33 41 42 34
               .  3  A  B  4
    """
    lines: list[str] = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        # right-align each char to 2 cols so it sits under the byte's low nibble
        ascs = " ".join(f"{(chr(b) if 0x20 <= b <= 0x7E else '.'):>2}" for b in chunk)
        lines.append(f"{base + off:04x}  {hexs}")
        lines.append(f"{'':6}{ascs}")
    return lines


def ascii_hint(data: bytes, *, stream=None) -> str | None:
    """Surface a human-readable view of a raw response on stderr as `[info]`
    line(s), leaving the pipeable hex untouched on stdout. Decode ladder:

      * fully printable ASCII (trailing NUL/pad ignored) -> one decoded string
      * partly printable (mixed text+binary)             -> hexdump two-line view
      * pure binary (no printable byte) / <2 bytes       -> nothing (hex row suffices)

    Returns the decoded string when the first rung fired, else None.
    """
    s = ascii_or_none(data)
    if s is not None:
        info(s, stream=stream)
        return s
    if len(data) >= 2 and any(0x20 <= b <= 0x7E for b in data):
        for ln in hex_dump_lines(data):
            info(ln, stream=stream)
    return None


if __name__ == "__main__":  # self-check: python -m zipmi._msg
    assert ascii_or_none(bytes.fromhex(
        "424c5f53555045524d4943524f5f5837534233"
        "5f323031342d30342d31385f42")) == "BL_SUPERMICRO_X7SB3_2014-04-18_B"
    assert ascii_or_none(b"OK\x00\x00\x00") == "OK"          # trailing NUL pad stripped
    assert ascii_or_none(b"\x00") is None                     # lone binary byte
    assert ascii_or_none(b"\x01\x02\x03\x04") is None         # binary struct
    assert ascii_or_none(b"A") is None                        # single char = noise
    assert ascii_or_none(b"") is None                         # empty
    assert ascii_or_none(b"1.2.3") == "1.2.3"                 # version string
    # hexdump fallback: hex row + aligned ascii/dot row
    hd = hex_dump_lines(bytes([0x00, 0x33, 0x41, 0x42, 0x34]))
    assert hd == ["0000  00 33 41 42 34", "       .  3  A  B  4"], hd
    # ascii_hint on pure binary emits nothing (returns None, no dump)
    assert ascii_hint(b"\x00\x01") is None
    print("_msg self-check OK")
