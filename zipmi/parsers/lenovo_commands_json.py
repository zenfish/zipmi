"""Build the generated Lenovo XCC OEM command catalog from normalized JSON."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LenovoCommand:
    name: str
    netfn: int
    cmd: int
    prefix: bytes
    iana: int | None
    runnable: bool
    dispatch: str
    privilege: int | None
    request_length_rules: tuple[tuple[str, int], ...]
    handler: str
    registrations: tuple[tuple[str, str], ...]
    purpose: str
    request: str
    response: str
    side_effect: str
    remote_restriction: str
    evidence_state: str
    confidence: str
    source: str
    notes: str


def parse_json(text: str) -> list[LenovoCommand]:
    data = json.loads(text)
    out = []
    for c in data["commands"]:
        out.append(LenovoCommand(
            name=c["name"], netfn=c["netfn"], cmd=c["cmd"],
            prefix=bytes(c["prefix"]), iana=c["iana"], runnable=c["runnable"],
            dispatch=c["dispatch"], privilege=c["privilege"],
            request_length_rules=tuple((r["length_kind"], r["request_length"])
                                       for r in c["requestLengthRules"]),
            handler=c["handler"],
            registrations=tuple((r["module"], r["owner"])
                                for r in c["registrations"]),
            purpose=c["purpose"], request=c["request"], response=c["response"],
            side_effect=c["sideEffect"], remote_restriction=c["remoteRestriction"],
            evidence_state=c["evidenceState"], confidence=c["confidence"],
            source=c["source"], notes=c["notes"],
        ))
    return out


def emit_module(entries: list[LenovoCommand], source: str) -> str:
    lines = [
        '"""Auto-generated Lenovo XCC OEM command catalog; do not edit."""',
        "from __future__ import annotations", "", "from dataclasses import dataclass", "", "",
        "@dataclass(frozen=True)", "class LenovoCommand:",
        "    name: str", "    netfn: int", "    cmd: int", "    prefix: bytes",
        "    iana: int | None", "    runnable: bool", "    dispatch: str",
        "    privilege: int | None", "    request_length_rules: tuple[tuple[str, int], ...]",
        "    handler: str", "    registrations: tuple[tuple[str, str], ...]",
        "    purpose: str", "    request: str", "    response: str",
        "    side_effect: str", "    remote_restriction: str", "    evidence_state: str",
        "    confidence: str", "    source: str", "    notes: str", "", "",
        f"# Source: {source}", f"# Entries: {len(entries)}",
        "LENOVO_COMMANDS: list[LenovoCommand] = [",
    ]
    for e in entries:
        lines.append(
            "    LenovoCommand("
            f"name={e.name!r}, netfn=0x{e.netfn:02x}, cmd=0x{e.cmd:02x}, "
            f"prefix={e.prefix!r}, iana={e.iana!r}, runnable={e.runnable!r}, "
            f"dispatch={e.dispatch!r}, privilege={e.privilege!r}, "
            f"request_length_rules={e.request_length_rules!r}, handler={e.handler!r}, "
            f"registrations={e.registrations!r}, purpose={e.purpose!r}, "
            f"request={e.request!r}, response={e.response!r}, "
            f"side_effect={e.side_effect!r}, remote_restriction={e.remote_restriction!r}, "
            f"evidence_state={e.evidence_state!r}, confidence={e.confidence!r}, "
            f"source={e.source!r}, notes={e.notes!r}),"
        )
    lines += ["]", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    source = Path(__file__).resolve().parent.parent / "data" / "sources" / "lenovo-xcc-commands.json"
    if len(args) > 1:
        source = Path(args[1])
    entries = parse_json(source.read_text())
    sys.stdout.write(emit_module(entries, "lenovo-xcc-commands.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
