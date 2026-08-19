"""
zipmi.scapy_ipmi.colorize — ANSI color the wire-trace hex output.

WHAT     `colorize_hex(buf, is_response)` returns the buffer's hex
         encoding with 24-bit ANSI color escapes wrapping the
         interesting byte ranges (RMCP header, session header, NetFn,
         cmd, data, completion code, etc.).

WHY      Naked hex is hard to scan. Coloring NetFn/cmd/data the same
         way every line lets a human eyeball "is this a Get SDR or a
         Get Sensor Reading?" and "did the BMC return CC=0 or 0xC1?"
         without parsing each line by hand.

PALETTE  ColorBrewer "Pastel1" qualitative scheme, n=8.
         https://colorbrewer2.org/#type=qualitative&scheme=Pastel1&n=8
         Eight distinguishable pastels chosen to be readable on dark
         terminals (the common case). On a light-background terminal
         they may wash out — use --no-color in that case.

SUCCESS  `zipmi lan print -v` shows the LAN-config Get/Response with
         RMCP in blue, NetFn in green, cmd in peach, data in cream,
         and the CC byte of the response in pink.

RELATED  cmd_names.py (the name column to the left of the hex),
         core.py:Transport._dump (the consumer), cli/zipmi.py
         (--no-color plumbing).
"""

from __future__ import annotations

import os
import sys


# =========================================================================
# >>> COLOR CONFIG — edit here to retune the wire-trace palette <<<
# =========================================================================
# Three palettes ship by name (CLI flag `-p / --palette`):
#
#   pastel  ColorBrewer "Pastel1" qualitative n=8 (default; dark terminals)
#   set     ColorBrewer "Set1"    qualitative n=8 (saturated; light terms)
#   dark    ColorBrewer "Dark2"   qualitative n=8 (muted; dark terminals)
#
# Each palette is a {role: (R,G,B)} dict so swapping palettes preserves
# semantic meaning (NetFn always green-ish, CC always red/pink-ish, etc.).
#
# To add a new palette, define a role-keyed dict and register it in
# PALETTES below. To remap which colour a role gets within an existing
# palette, just edit the dict literal.
# =========================================================================

# ColorBrewer Pastel1 qualitative, n=8 — pastel pink/blue/green/purple/...
# https://colorbrewer2.org/#type=qualitative&scheme=Pastel1&n=8
_PASTEL_ROLES: dict[str, tuple[int, int, int]] = {
    "rmcp":        (0xb3, 0xcd, 0xe3),  # blue
    "session":     (0xde, 0xcb, 0xe4),  # purple
    "auth":        (0xfd, 0xda, 0xec),  # magenta — auth_type byte + AuthCode
    "netfn":       (0xcc, 0xeb, 0xc5),  # green
    "cmd":         (0xfe, 0xd9, 0xa6),  # orange
    "data":        (0xff, 0xff, 0xcc),  # yellow
    "cc":          (0xfb, 0xb4, 0xae),  # pink
    # enc_payload / dec_payload are security-semantic; same across all palettes
    # so the red/green signal is consistent regardless of --palette choice.
    # Edit these two lines to remap for colorblindness or personal preference.
    "enc_payload": (220,  60,  60),     # bright red   — encrypted ciphertext bytes
    "dec_payload": ( 60, 210,  90),     # bright green — decrypted plaintext bytes
}

# ColorBrewer Set1 qualitative, n=8 — saturated red/blue/green/purple/...
# https://colorbrewer2.org/#type=qualitative&scheme=Set1&n=8
_SET_ROLES: dict[str, tuple[int, int, int]] = {
    "rmcp":        ( 55, 126, 184),     # blue
    "session":     (152,  78, 163),     # purple
    "auth":        (247, 129, 191),     # pink (Set1's 8th)
    "netfn":       ( 77, 175,  74),     # green
    "cmd":         (255, 127,   0),     # orange
    "data":        (255, 255,  51),     # yellow
    "cc":          (228,  26,  28),     # red (CC pops)
    "enc_payload": (220,  60,  60),     # bright red   — encrypted ciphertext bytes
    "dec_payload": ( 60, 210,  90),     # bright green — decrypted plaintext bytes
}

# ColorBrewer Dark2 qualitative, n=8 — muted teal/orange/purple/magenta/...
# https://colorbrewer2.org/#type=qualitative&scheme=Dark2&n=8
_DARK_ROLES: dict[str, tuple[int, int, int]] = {
    "rmcp":        ( 27, 158, 119),     # teal
    "session":     (117, 112, 179),     # purple
    "auth":        (166, 118,  29),     # brown
    "netfn":       (102, 166,  30),     # green
    "cmd":         (217,  95,   2),     # orange
    "data":        (230, 171,   2),     # mustard
    "cc":          (231,  41, 138),     # magenta (CC pops)
    "enc_payload": (220,  60,  60),     # bright red   — encrypted ciphertext bytes
    "dec_payload": ( 60, 210,  90),     # bright green — decrypted plaintext bytes
}

PALETTES: dict[str, dict[str, tuple[int, int, int]]] = {
    "pastel": _PASTEL_ROLES,
    "set":    _SET_ROLES,
    "dark":   _DARK_ROLES,
}

# Active role → colour map. Mutated by set_palette().
ROLE_COLORS: dict[str, tuple[int, int, int]] = dict(_PASTEL_ROLES)


def set_palette(name: str) -> None:
    """Switch the active palette. Raises KeyError on unknown name.

    Accepts canonical names: 'pastel', 'set', 'dark'. Single-letter
    aliases are normalised by `normalize_palette_name()` (CLI helper).
    """
    pal = PALETTES[name]
    ROLE_COLORS.clear()
    ROLE_COLORS.update(pal)


_PALETTE_ALIASES: dict[str, str] = {
    "p": "pastel", "pastel": "pastel", "pastel1": "pastel",
    "s": "set",    "set":    "set",    "set1":    "set",
    "d": "dark",   "dark":   "dark",   "dark2":   "dark",
    "a": "auto",   "auto":   "auto",
}

# When palette == "auto", map detected background luminance → palette name.
# pastel + dark2 read well on dark backgrounds; set1 is saturated enough
# to survive a white background.
_BACKGROUND_TO_PALETTE: dict[str, str] = {
    "dark":  "pastel",
    "light": "set",
}


def normalize_palette_name(s: str) -> str:
    """Map p|pastel|pastel1 → pastel (and friends). Raises on unknown."""
    key = s.lower()
    if key not in _PALETTE_ALIASES:
        raise ValueError(
            f"unknown palette {s!r}; pick one of: auto|pastel|set|dark "
            f"(or short forms a|p|s|d)")
    return _PALETTE_ALIASES[key]


def resolve_palette(name: str) -> str:
    """Resolve 'auto' to the best palette for the current terminal.

    Falls back to 'pastel' if background detection fails (no
    COLORFGBG, no OSC 11 reply, non-TTY).
    """
    if name != "auto":
        return name
    bg = detect_background()
    return _BACKGROUND_TO_PALETTE.get(bg, "pastel")

# =========================================================================
# >>> end of color config <<<
# =========================================================================


def _ansi(rgb: tuple[int, int, int]) -> str:
    r, g, b = rgb
    return f"\x1b[38;2;{r};{g};{b}m"


_RESET = "\x1b[0m"


def detect_background() -> str | None:
    """Return 'dark', 'light', or None if undetermined.

    Tries two probes in order:

    1. COLORFGBG env var (set by Konsole, rxvt, sometimes iTerm).
       Format: 'fg;bg' with bg being a 0..15 ANSI colour index;
       0..6 are dark, 7..15 are light by convention.

    2. OSC 11 query (xterm 'Get text background colour'). Sends
       \\x1b]11;?\\x07 to the controlling terminal and reads back
       \\x1b]11;rgb:RRRR/GGGG/BBBB\\x07. Computes Rec.709 luminance
       to decide. Times out at 100 ms so a non-responding terminal
       doesn't hang the CLI.

    Both probes are best-effort; never raises.
    """
    fgbg = os.environ.get("COLORFGBG")
    if fgbg and ";" in fgbg:
        try:
            bg = int(fgbg.rsplit(";", 1)[-1].split(",")[0])
            return "light" if bg >= 7 else "dark"
        except ValueError:
            pass
    return _osc11_detect()


def _osc11_detect(timeout: float = 0.1) -> str | None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    try:
        import termios
        import tty
        import select
        import re
    except ImportError:
        return None
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except (termios.error, OSError):
        return None
    try:
        tty.setcbreak(fd, termios.TCSANOW)
        sys.stdout.write("\x1b]11;?\x07")
        sys.stdout.flush()
        buf = b""
        while True:
            r, _, _ = select.select([fd], [], [], timeout)
            if not r:
                break
            try:
                chunk = os.read(fd, 64)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if b"\x07" in buf or b"\x1b\\" in buf:
                break
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except (termios.error, OSError):
            pass
    m = re.search(rb"rgb:([0-9a-fA-F]+)/([0-9a-fA-F]+)/([0-9a-fA-F]+)", buf)
    if not m:
        return None

    def _scale(s: bytes) -> int:
        v = int(s, 16)
        # OSC 11 returns 16-bit-per-channel by default ('RRRR'); some
        # terminals reply with 8-bit-per-channel ('RR'). Normalise to 0..255.
        return (v >> 8) if len(s) >= 4 else (v & 0xFF)

    r, g, b = _scale(m.group(1)), _scale(m.group(2)), _scale(m.group(3))
    # Rec.709 luminance, normalised to 0..1.
    lum = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0
    return "light" if lum > 0.5 else "dark"


def color_enabled(stream=None) -> bool:
    """Default policy: TTY out, NO_COLOR honoured (no-color.org).

    Callers that have an explicit user preference should override this.

    FORCE_COLOR / CLICOLOR_FORCE (CI and BSD conventions, the inverse of
    no-color.org's NO_COLOR) force colour on even off a TTY — needed to
    capture the -d wire trace into a pipe for the docs SVG.
    """
    if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    s = stream if stream is not None else sys.stdout
    try:
        return bool(s.isatty())
    except Exception:
        return False


# --------------------------------------------------------------------------
# Wire parsing → list of (start_byte, end_byte_excl, role_rgb).
# Ranges may be sparse and out of order; _wrap() sorts and skips gaps.
# --------------------------------------------------------------------------
def _ranges_for(buf: bytes, is_response: bool) -> list[tuple[int, int, tuple[int, int, int]]]:
    n = len(buf)
    if n < 4:
        return [(0, n, ROLE_COLORS["rmcp"])] if n else []

    out: list[tuple[int, int, tuple[int, int, int]]] = []
    out.append((0, 4, ROLE_COLORS["rmcp"]))
    msg_class = buf[3] & 0x1F

    # ASF (DSP0136), msg_class 0x06.
    if msg_class == 0x06:
        # IANA(4) | msg_type(1) | msg_tag(1) | reserved(1) | data_len(1) | data...
        if n >= 9:
            out.append((8, 9, ROLE_COLORS["cmd"]))       # msg_type behaves like cmd
        if n > 9:
            out.append((9, n, ROLE_COLORS["data"]))
        return out

    if msg_class != 0x07 or n < 5:
        return out

    auth_type = buf[4]

    # IPMI 2.0 RMCP+ (auth_type byte == 0x06).
    if auth_type == 0x06:
        # auth(1) ptype(1) sid(4) seq(4) len(2) = 12 bytes
        sess_end = min(4 + 12, n)
        # auth_type byte stands alone in the auth colour; rest of the
        # session header (ptype/sid/seq/len) is the session colour.
        out.append((4, 5, ROLE_COLORS["auth"]))
        out.append((5, sess_end, ROLE_COLORS["session"]))
        if n >= 6:
            # payload_type lives inside the session header but call it out
            # specifically — it's the closest analogue to "cmd" at this layer.
            out.append((5, 6, ROLE_COLORS["cmd"]))
        ptype_byte = buf[5] if n >= 6 else 0
        ptype = ptype_byte & 0x3F
        encrypted = bool(ptype_byte & 0x80)
        if ptype != 0x00 or encrypted:
            # RAKP/OpenSession or encrypted IPMI — payload is opaque.
            if sess_end < n:
                color = ROLE_COLORS["enc_payload"] if encrypted else ROLE_COLORS["data"]
                out.append((sess_end, n, color))
            return out
        # Embedded IPMI message — colour the IPMB layer.
        return out + _ipmb_ranges(buf, 4 + 12, is_response)

    # IPMI 1.5 session header.
    has_auth_code = auth_type not in (0x00,)
    # Layout: auth(1) seq(4) sid(4) [authcode(16)] msg_len(1) ipmb...
    # auth_type byte (offset 4) → auth colour. seq + sid → session colour.
    out.append((4, 5, ROLE_COLORS["auth"]))
    out.append((5, 4 + 1 + 4 + 4, ROLE_COLORS["session"]))
    cursor = 4 + 1 + 4 + 4
    if has_auth_code and n >= cursor + 16:
        out.append((cursor, cursor + 16, ROLE_COLORS["auth"]))
        cursor += 16
    if n >= cursor + 1:
        out.append((cursor, cursor + 1, ROLE_COLORS["session"]))  # msg_len
        cursor += 1
    return out + _ipmb_ranges(buf, cursor, is_response)


def _ipmb_ranges(
    buf: bytes,
    off: int,
    is_response: bool,
) -> list[tuple[int, int, tuple[int, int, int]]]:
    n = len(buf)
    # IPMB minimum: rs(1) netfn(1) chk1(1) rq(1) rqseq(1) cmd(1) chk2(1) = 7
    if n < off + 7:
        return [(off, n, ROLE_COLORS["data"])] if off < n else []
    # IPMB framing bytes (rs_addr, chk1, rq_addr, rq_seq, chk2) are left
    # in the default terminal colour — the eye-grabbing fields are
    # NetFn / cmd / data / CC.
    out: list[tuple[int, int, tuple[int, int, int]]] = []
    out.append((off + 1, off + 2, ROLE_COLORS["netfn"]))     # NetFn|LUN
    out.append((off + 5, off + 6, ROLE_COLORS["cmd"]))       # cmd
    data_start = off + 6
    data_end = n - 1                                # chk2 is the last byte
    if data_end > data_start:
        if is_response:
            out.append((data_start, data_start + 1, ROLE_COLORS["cc"]))
            if data_end > data_start + 1:
                out.append((data_start + 1, data_end, ROLE_COLORS["data"]))
        else:
            out.append((data_start, data_end, ROLE_COLORS["data"]))
    return out


def _wrap(hex_str: str, ranges: list[tuple[int, int, tuple[int, int, int]]]) -> str:
    """Insert ANSI escapes around byte ranges in a hex string.

    `ranges` are byte offsets; each byte is 2 hex chars in `hex_str`.
    Sorts by start offset and tolerates overlaps by preferring the
    earlier-listed range (caller should not rely on overlap behaviour).
    """
    if not ranges:
        return hex_str
    ranges = sorted(ranges, key=lambda t: (t[0], t[1]))
    parts: list[str] = []
    cursor = 0
    for s, e, rgb in ranges:
        if e <= s:
            continue
        if s > cursor:
            parts.append(hex_str[cursor * 2:s * 2])
        parts.append(_ansi(rgb))
        parts.append(hex_str[s * 2:e * 2])
        parts.append(_RESET)
        cursor = e
    if cursor * 2 < len(hex_str):
        parts.append(hex_str[cursor * 2:])
    return "".join(parts)


def colorize_hex(buf: bytes, *, is_response: bool, enabled: bool = True) -> str:
    """Return buf.hex() optionally wrapped with Pastel1 ANSI escapes."""
    plain = buf.hex()
    if not enabled:
        return plain
    _legend_arm()
    return _wrap(plain, _ranges_for(buf, is_response))


def colorize_hex_dec(buf: bytes, *, enabled: bool = True) -> str:
    """Return buf.hex() wrapped entirely in dec_payload (green).

    Used for the decrypted-plaintext second line that follows an encrypted
    wire dump. Colours all bytes uniformly so the green clearly signals
    "this is what the ciphertext above actually contains".
    """
    plain = buf.hex()
    if not enabled or not plain:
        return plain
    _legend_arm()
    return _ansi(ROLE_COLORS["dec_payload"]) + plain + _RESET


# --------------------------------------------------------------------------
# Legend — printed once at process exit if any coloured trace was emitted.
# Lists every role in byte-order (the order they appear on the wire) so the
# reader can map colour → meaning by scanning left-to-right.
# --------------------------------------------------------------------------
_LEGEND_ORDER = [
    ("rmcp",        "RMCP"),
    ("session",     "session"),
    ("auth",        "Auth"),
    ("netfn",       "NetFn"),
    ("cmd",         "cmd"),
    ("data",        "data"),
    ("cc",          "CC"),
    ("enc_payload", "encrypted"),
    ("dec_payload", "decrypted"),
]

_legend_pending = False
_legend_registered = False


def _legend_arm() -> None:
    """Mark that we emitted a coloured byte; hook atexit if not already."""
    global _legend_pending, _legend_registered
    _legend_pending = True
    if not _legend_registered:
        import atexit
        atexit.register(_print_legend)
        _legend_registered = True


def _print_legend() -> None:
    if not _legend_pending:
        return
    # 10-space indent matches the leading "  " + 8-char prefix on every
    # trace line, so the legend's first label lines up under the arrow.
    parts = [f"{_ansi(ROLE_COLORS[role])}{label}{_RESET}"
             for role, label in _LEGEND_ORDER]
    print("\n" + " " * 10 + "  ".join(parts), flush=True)


__all__ = [
    "PALETTES",
    "ROLE_COLORS",
    "color_enabled",
    "colorize_hex",
    "colorize_hex_dec",
    "detect_background",
    "normalize_palette_name",
    "resolve_palette",
    "set_palette",
]
