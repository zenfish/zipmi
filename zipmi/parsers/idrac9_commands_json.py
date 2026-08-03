"""
zipmi.parsers.idrac9_commands_json — build the iDRAC9 OEM command catalog.

WHAT     Reads the reverse-engineered iDRAC9 command catalog
         (idrac9-commands.json, 276 commands) and emits a Python module
         with a frozen `IDrac9Command` dataclass and the full list of
         entries. Sibling to `idrac9_dispatch_md.py`: the dispatch parser
         gives (NetFn, cmd) → handler-symbol from the ELF dispatch tables;
         THIS parser gives the rich per-command doc (purpose, request,
         response, privilege, security notes, backend deps, confidence).
WHY      The dispatch tables name the wire surface but say nothing about
         what a command *does*. The JSON catalog was RE'd + adversarially
         verified against the iDRAC9 libs and carries the human-facing
         documentation. 43 of the 276 entries are honestly incomplete —
         request/response="undetermined", confidence="unverified" — because
         they are PLT-shim handlers whose payload logic lives in delegate
         libs; that is intentional, correct data (a non-empty "undetermined"
         marker), not a hole. Wiring it in turns `zipmi idrac9 <name> help`
         into a real per-command reference and lets callers look a command
         up by (NetFn, cmd[, subcmd]).
USAGE    python -m zipmi.parsers.idrac9_commands_json \
             [idrac9-commands.json] \
             > zipmi/scapy_ipmi/oem/idrac9_commands_generated.py
SUCCESS  Regeneration is idempotent (byte-for-byte identical output) and
         the emitted module imports with len(IDRAC9_COMMANDS) == 276.
TARGET   iDRAC9 firmware (firmimgFIT.d9) v7.20.30.50, Dell IANA 674.
RELATED  iDRAC9 firmware reverse-engineering notes (idrac9-commands.json),
         zipmi/scapy_ipmi/oem/idrac9.py (consumer),
         zipmi/parsers/idrac9_dispatch_md.py (dispatch-table sibling).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class IDrac9Command:
    name: str
    netfn: int | None       # None when RE could not pin the NetFn ("undetermined")
    cmd: int | None
    subcmd: int | None      # None when the command has no sub-command byte
    priv: str               # free-form as RE'd, e.g. "Admin (4)", "User (0x02)", "2"
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


def parse_json(text: str) -> list[IDrac9Command]:
    data = json.loads(text)
    out: list[IDrac9Command] = []
    for c in data["commands"]:
        out.append(IDrac9Command(
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


def emit_module(entries: list[IDrac9Command], src: str) -> str:
    lines = [
        '"""',
        "zipmi.scapy_ipmi.oem.idrac9_commands_generated — auto-generated catalog.",
        "",
        "DO NOT EDIT BY HAND. Regenerate with:",
        "    python -m zipmi.parsers.idrac9_commands_json \\",
        "        > zipmi/scapy_ipmi/oem/idrac9_commands_generated.py",
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
        "class IDrac9Command:",
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
        "IDRAC9_COMMANDS: list[IDrac9Command] = [",
    ]
    for e in entries:
        lines.append(
            "    IDrac9Command("
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
    src = str(Path(__file__).resolve().parent.parent / "data" / "sources" / "idrac9-commands.json")
    if len(args) > 1:
        src = args[1]
    with open(src) as f:
        text = f.read()
    entries = parse_json(text)
    sys.stdout.write(emit_module(entries, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
