"""Build the generated Lenovo XCC OEM command catalog from normalized JSON."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LenovoOperation:
    selector: str
    operation: str
    request: str
    response: str
    completion_codes: str
    effect: str
    evidence: str
    source: str


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
    operations: tuple[LenovoOperation, ...]
    live_evidence: dict[str, object] | None


@dataclass(frozen=True)
class LenovoContract:
    name: str
    netfn: int
    cmd: int
    selector: bytes
    selector_offset: int | None
    prefix: bytes
    privilege: int
    purpose: str
    request: str
    response: str
    request_length: tuple[int | None, int | None]
    response_length: tuple[int | None, int | None]
    request_fields: list[dict]
    response_fields: list[dict]
    effect: str
    side_effects: str
    completion_codes: list[dict]
    channel: str
    activation: str
    codec_state: str
    request_codec: bool
    response_codec: bool
    evidence: str
    source: str


def _length_range(value) -> tuple[int | None, int | None]:
    if isinstance(value, int):
        return value, value
    if isinstance(value, dict):
        return value.get("min"), value.get("max")
    return None, None


def parse_json(text: str) -> list[LenovoCommand]:
    data = json.loads(text)
    out = []
    for c in data["commands"]:
        operations = tuple(LenovoOperation(
            selector=o["selector"], operation=o["operation"],
            request=o["request"], response=o["response"],
            completion_codes=o["completionCodes"], effect=o["effect"],
            evidence=o["evidence"], source=o["source"],
        ) for o in c.get("operations", []))
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
            source=c["source"], notes=c["notes"], operations=operations,
            live_evidence=c.get("liveEvidence"),
        ))
    return out


def parse_contract_json(text: str) -> list[LenovoContract]:
    data = json.loads(text)
    out = []
    for c in data["contracts"]:
        lan_parameter = c.get("lanParameter")
        selector = bytes(c.get("selector", [lan_parameter] if lan_parameter is not None else []))
        selector_offset = c.get("selectorOffset", 1 if lan_parameter is not None else None)
        request_fields = c.get("requestFields", [])
        if lan_parameter is not None:
            request_fields = [
                {"name": "channel", "kind": "u8"},
                {"name": "parameter", "kind": "u8", "constant": lan_parameter},
            ]
            if c["cmd"] == 0x02:
                request_fields += [
                    {"name": "set_selector", "kind": "u8", "constant": 0},
                    {"name": "block_selector", "kind": "u8", "constant": 0},
                ]
            else:
                request_fields += c.get("bodyFields", [])
        lan_completion_codes = (
            [{"code": 0x80, "meaning": "parameter unsupported"}]
            if c["cmd"] == 0x02 else [
                {"code": 0x80, "meaning": "parameter unsupported"},
                {"code": 0x81, "meaning": "set-in-progress conflict"},
                {"code": 0x82, "meaning": "parameter read-only"},
                {"code": 0x83, "meaning": "parameter write-only"},
            ]
        ) if lan_parameter is not None else []
        out.append(LenovoContract(
            name=c["name"], netfn=c["netfn"], cmd=c["cmd"],
            selector=selector, selector_offset=selector_offset,
            prefix=selector if selector and selector_offset == 0 else b"",
            privilege=c.get("privilege", 4 if c["cmd"] == 0x01 else 2),
            purpose=c["purpose"],
            request=c["request"], response=c["response"],
            request_length=_length_range(c.get("requestLength")),
            response_length=_length_range(c.get("responseLength")),
            request_fields=request_fields,
            response_fields=c.get("responseFields", []),
            effect=c["effect"], side_effects=c["sideEffects"],
            completion_codes=c.get("completionCodes", lan_completion_codes),
            channel=c.get("channel", "standard LAN configuration channel"),
            activation=c.get("activation", "XCC 6.92 OEMLANInit channel-data handler"),
            codec_state=c.get("codecState", "raw-exact"),
            request_codec=bool(c.get("requestCodec", False)),
            response_codec=bool(c.get("responseCodec", False)),
            evidence=c.get("evidence", "Lenovo public parameter contract and XCC 6.92 OEMLANDataAccess activation"),
            source=c.get("source", "https://pubs.lenovo.com/xcc/get_set_lan_config_parameter"),
        ))
    return out


def emit_module(entries: list[LenovoCommand], source: str,
                contracts: list[LenovoContract] | None = None) -> str:
    contracts = contracts or []
    lines = [
        '"""Auto-generated Lenovo XCC OEM command catalog; do not edit."""',
        "from __future__ import annotations", "", "from dataclasses import dataclass", "", "",
        "@dataclass(frozen=True)", "class LenovoOperation:",
        "    selector: str", "    operation: str", "    request: str",
        "    response: str", "    completion_codes: str", "    effect: str",
        "    evidence: str", "    source: str", "", "",
        "@dataclass(frozen=True)", "class LenovoCommand:",
        "    name: str", "    netfn: int", "    cmd: int", "    prefix: bytes",
        "    iana: int | None", "    runnable: bool", "    dispatch: str",
        "    privilege: int | None", "    request_length_rules: tuple[tuple[str, int], ...]",
        "    handler: str", "    registrations: tuple[tuple[str, str], ...]",
        "    purpose: str", "    request: str", "    response: str",
        "    side_effect: str", "    remote_restriction: str", "    evidence_state: str",
        "    confidence: str", "    source: str", "    notes: str",
        "    operations: tuple[LenovoOperation, ...]",
        "    live_evidence: dict[str, object] | None", "", "",
        "@dataclass(frozen=True)", "class LenovoContract:",
        "    name: str", "    netfn: int", "    cmd: int", "    selector: bytes",
        "    selector_offset: int | None", "    prefix: bytes", "    privilege: int",
        "    purpose: str", "    request: str", "    response: str",
        "    request_length: tuple[int | None, int | None]",
        "    response_length: tuple[int | None, int | None]",
        "    request_fields: list[dict]", "    response_fields: list[dict]",
        "    effect: str", "    side_effects: str",
        "    completion_codes: list[dict]", "    channel: str",
        "    activation: str", "    codec_state: str", "    request_codec: bool",
        "    response_codec: bool", "    evidence: str", "    source: str", "", "",
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
            f"source={e.source!r}, notes={e.notes!r}, operations={e.operations!r}, "
            f"live_evidence={e.live_evidence!r}),"
        )
    lines += ["]", ""]
    lines += [f"# Operation contracts: {len(contracts)}",
              "LENOVO_CONTRACTS: list[LenovoContract] = ["]
    for c in contracts:
        lines.append(
            "    LenovoContract("
            f"name={c.name!r}, netfn=0x{c.netfn:02x}, cmd=0x{c.cmd:02x}, "
            f"selector={c.selector!r}, selector_offset={c.selector_offset!r}, "
            f"prefix={c.prefix!r}, privilege={c.privilege!r}, purpose={c.purpose!r}, "
            f"request={c.request!r}, response={c.response!r}, "
            f"request_length={c.request_length!r}, response_length={c.response_length!r}, "
            f"request_fields={c.request_fields!r}, response_fields={c.response_fields!r}, "
            f"effect={c.effect!r}, side_effects={c.side_effects!r}, "
            f"completion_codes={c.completion_codes!r}, channel={c.channel!r}, "
            f"activation={c.activation!r}, codec_state={c.codec_state!r}, "
            f"request_codec={c.request_codec!r}, response_codec={c.response_codec!r}, "
            f"evidence={c.evidence!r}, source={c.source!r}),"
        )
    lines += ["]", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    source = Path(__file__).resolve().parent.parent / "data" / "sources" / "lenovo-xcc-commands.json"
    contract_source = (Path(__file__).resolve().parent.parent / "data" / "sources" /
                       "lenovo-xcc-operation-contracts.json")
    if len(args) > 1:
        source = Path(args[1])
    entries = parse_json(source.read_text())
    contracts = parse_contract_json(contract_source.read_text())
    sys.stdout.write(emit_module(entries, "lenovo-xcc-commands.json", contracts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
