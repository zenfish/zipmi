"""
zipmi.parsers.idrac10_commands_json — build the iDRAC10 OEM command catalog.

WHAT     Reads the reverse-engineered iDRAC10 command catalog
         (idrac10-commands.json) and emits a Python module
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
SUCCESS  Regeneration is idempotent (byte-for-byte identical output).
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
    prefix: bytes
    selector_offset: int | None
    live: dict | None
    effect: str
    side_effects: str
    request_length: tuple[int | None, int | None]
    response_length_including_cc: tuple[int | None, int | None]
    completion_codes: str | list[dict]
    activation: str | dict
    request_fields: list[dict]
    response_fields: list[dict]
    codec_state: str
    evidence: str | dict


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


def _prefix(c: dict, subcmd: int | None) -> bytes:
    explicit = (c.get("prefix") or "").strip()
    if explicit:
        return bytes(int(token, 16) for token in explicit.split())
    if subcmd is None:
        return b""
    if "selectorOffset" in c and c["selectorOffset"] != 0:
        return b""
    return subcmd.to_bytes(max(1, (subcmd.bit_length() + 7) // 8), "big")


def _length_range(value) -> tuple[int | None, int | None]:
    if isinstance(value, int):
        return value, value
    if isinstance(value, dict):
        return value.get("min"), value.get("max")
    return None, None


def parse_json(text: str) -> list[IDrac10Command]:
    data = json.loads(text)
    out: list[IDrac10Command] = []
    for c in data["commands"]:
        subcmd = _hex_or_none(c["subcmd"])
        out.append(IDrac10Command(
            name=c["name"],
            netfn=_hex_or_none(c["netfn"]),
            cmd=_hex_or_none(c["cmd"]),
            subcmd=subcmd,
            priv=c["priv"],
            purpose=c["purpose"],
            request=c["request"],
            response=c["response"],
            in_band_only=bool(c["inBandOnly"]),
            backend_deps=c["backendDeps"],
            security=c["security"],
            confidence=c["confidence"],
            lib=c["lib"],
            prefix=_prefix(c, subcmd),
            selector_offset=c.get("selectorOffset", 0 if subcmd is not None else None),
            live=c.get("live"),
            effect=c.get("effect", "unknown"),
            side_effects=c.get("sideEffects", "not yet classified"),
            request_length=_length_range(c.get("requestLength")),
            response_length_including_cc=_length_range(c.get("responseLengthIncludingCc")),
            completion_codes=c.get("completionCodes", "not yet normalized"),
            activation=c.get("activation", "not yet classified"),
            request_fields=c.get("requestFields", []),
            response_fields=c.get("responseFields", []),
            codec_state=c.get("codecState", "raw-exact"),
            evidence=c.get("evidence", ""),
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
        "    prefix: bytes",
        "    selector_offset: int | None",
        "    live: dict | None",
        "    effect: str",
        "    side_effects: str",
        "    request_length: tuple[int | None, int | None]",
        "    response_length_including_cc: tuple[int | None, int | None]",
        "    completion_codes: str | list[dict]",
        "    activation: str | dict",
        "    request_fields: list[dict]",
        "    response_fields: list[dict]",
        "    codec_state: str",
        "    evidence: str | dict",
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
            f"lib={e.lib!r}, "
            f"prefix={e.prefix!r}, "
            f"selector_offset={e.selector_offset!r}, "
            f"live={e.live!r}, "
            f"effect={e.effect!r}, "
            f"side_effects={e.side_effects!r}, "
            f"request_length={e.request_length!r}, "
            f"response_length_including_cc={e.response_length_including_cc!r}, "
            f"completion_codes={e.completion_codes!r}, "
            f"activation={e.activation!r}, "
            f"request_fields={e.request_fields!r}, "
            f"response_fields={e.response_fields!r}, "
            f"codec_state={e.codec_state!r}, "
            f"evidence={e.evidence!r}),"
        )
    lines.append("]")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    src_path = Path(__file__).resolve().parent.parent / "data" / "sources" / "idrac10-commands.json"
    src = "iDRAC10 command catalog JSON (bundled: zipmi/data/sources/)"
    if len(args) > 1:
        src_path = Path(args[1])
        src = str(src_path)
    with open(src_path) as f:
        text = f.read()
    entries = parse_json(text)
    sys.stdout.write(emit_module(entries, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
