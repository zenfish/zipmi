"""
zipmi.parsers.idrac10_commands_json — build the iDRAC10 OEM command catalog.

WHAT     Reads the reverse-engineered iDRAC10 command catalog
         (idrac10-commands.json, 447 commands) and emits a Python module
         with a frozen `IDrac10Command` dataclass and the full list of
         entries. Sibling to `idrac10_dispatch_md.py`: the dispatch parser
         gives (NetFn, cmd) → handler-symbol from the ELF dispatch tables;
         THIS parser gives the rich per-command doc (purpose, request,
         response, privilege, security notes, backend deps, confidence).
WHY      The dispatch tables name the wire surface but say nothing about
         what a command *does*. The JSON catalog was RE'd + adversarially
         verified against the iDRAC10 libs and carries the human-facing
         documentation. Wiring it in turns `zipmi idrac10 <name> help` into
         a real per-command reference and lets callers look a command up by
         (NetFn, cmd[, subcmd]).
USAGE    python -m zipmi.parsers.idrac10_commands_json \
             [idrac10-commands.json] \
             > zipmi/scapy_ipmi/oem/idrac10_commands_generated.py
SUCCESS  Regeneration is idempotent (byte-for-byte identical output) and
         the emitted module imports with len(IDRAC10_COMMANDS) == 447.
TARGET   iDRAC10 firmware 1.30.10.50 (aarch64), Dell IANA 674.
RELATED  iDRAC10 firmware reverse-engineering notes (idrac10-commands.json),
         zipmi/scapy_ipmi/oem/idrac10.py (consumer),
         zipmi/parsers/idrac10_dispatch_md.py (dispatch-table sibling).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class IDrac10Command:
    name: str
    netfn: int | None       # None when RE could not pin the NetFn ("undetermined")
    cmd: int | None
    subcmd: int | None      # None when the command has no sub-command byte
    priv: str               # free-form as RE'd, e.g. "Admin", "User (0x02)"
    purpose: str
    request: str
    response: str
    in_band_only: bool
    backend_deps: str
    security: str
    confidence: str
    lib: str


def _hex_or_none(s: str) -> int | None:
    """Parse a hex string → int; '' or 'undetermined' → None.

    Most values are a single byte ('0x30'). A handful of subcmds are
    whitespace-separated multi-byte selectors ('0x06 0x00'); those fold
    big-endian into one int (0x0600). Single wide tokens ('0xfffffff0')
    pass through unchanged.
    """
    s = (s or "").strip()
    if not s or s == "undetermined":
        return None
    val = 0
    for tok in s.split():
        val = (val << 8) | int(tok, 16)
    return val


def parse_json(text: str) -> list[IDrac10Command]:
    data = json.loads(text)
    out: list[IDrac10Command] = []
    for c in data["commands"]:
        out.append(IDrac10Command(
            name=c["name"],
            netfn=_hex_or_none(c["netfn"]),
            cmd=_hex_or_none(c["cmd"]),
            subcmd=_hex_or_none(c["subcmd"]),
            priv=c["priv"],
            purpose=c["purpose"],
            request=c["request"],
            response=c["response"],
            in_band_only=bool(c["inBandOnly"]),
            backend_deps=c["backendDeps"],
            security=c["security"],
            confidence=c["confidence"],
            lib=c["lib"],
        ))
    return out


def _fmt_opt_hex(v: int | None) -> str:
    return "None" if v is None else f"0x{v:02x}"


def emit_module(entries: list[IDrac10Command], src: str) -> str:
    lines = [
        '"""',
        "zipmi.scapy_ipmi.oem.idrac10_commands_generated — auto-generated catalog.",
        "",
        "DO NOT EDIT BY HAND. Regenerate with:",
        "    python -m zipmi.parsers.idrac10_commands_json \\",
        "        > zipmi/scapy_ipmi/oem/idrac10_commands_generated.py",
        "",
        f"Source: {src}",
        f"Entries: {len(entries)}",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass",
        "",
        "",
        "@dataclass(frozen=True)",
        "class IDrac10Command:",
        "    name: str",
        "    netfn: int | None",
        "    cmd: int | None",
        "    subcmd: int | None",
        "    priv: str",
        "    purpose: str",
        "    request: str",
        "    response: str",
        "    in_band_only: bool",
        "    backend_deps: str",
        "    security: str",
        "    confidence: str",
        "    lib: str",
        "",
        "",
        "IDRAC10_COMMANDS: list[IDrac10Command] = [",
    ]
    for e in entries:
        lines.append(
            "    IDrac10Command("
            f"name={e.name!r}, "
            f"netfn={_fmt_opt_hex(e.netfn)}, "
            f"cmd={_fmt_opt_hex(e.cmd)}, "
            f"subcmd={_fmt_opt_hex(e.subcmd)}, "
            f"priv={e.priv!r}, "
            f"purpose={e.purpose!r}, "
            f"request={e.request!r}, "
            f"response={e.response!r}, "
            f"in_band_only={e.in_band_only!r}, "
            f"backend_deps={e.backend_deps!r}, "
            f"security={e.security!r}, "
            f"confidence={e.confidence!r}, "
            f"lib={e.lib!r}),"
        )
    lines.append("]")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    src = str(Path(__file__).resolve().parent.parent / "data" / "sources" / "idrac10-commands.json")
    if len(args) > 1:
        src = args[1]
    with open(src) as f:
        text = f.read()
    entries = parse_json(text)
    sys.stdout.write(emit_module(entries, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
