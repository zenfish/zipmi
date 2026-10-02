#!/usr/bin/env python3
# z-artifact: 23e5503a-4790-4695-bba8-53839f0e412d
"""Generate the Dell iDRAC10 command reference through the shared renderer."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from oem_reference import render_reference

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "zipmi/data/sources/idrac10-commands.json"
OUTPUT = ROOT / "docs/idrac10-command-reference.html"
ARTIFACT_MARKER = "2c8c7d99-ac5f-457d-a2cb-30a659cb2a21 generated"

SAFETY_BY_EFFECT = {
    "safe": "read-only",
    "security-sensitive": "sensitive",
    "mutates": "state-changing",
    "destructive": "destructive",
    "unknown": "unknown",
}
DISRUPTIVE_OPERATIONS = {"DellCmdBladeACPowerCycle"}
DESTRUCTIVE_OVERRIDES = {"DellRollbackFW", "SubCmdHandler/DellBpFwUpdateInterface"}
WIDTHS = {"u8": 1, "u16": 2, "u16le": 2, "u32": 4, "u32le": 4, "u64": 8}


def _load_commands():
    """Use the runtime objects so documentation and named execution cannot drift."""
    sys.path.insert(0, str(ROOT))
    from zipmi.scapy_ipmi.oem.idrac10 import IDRAC10_COMMANDS
    from zipmi.cli.oem_cmds import _vendor_listing

    return IDRAC10_COMMANDS, _vendor_listing("idrac10")


def safety(command) -> str:
    if command.name in DESTRUCTIVE_OVERRIDES:
        return "destructive"
    if command.name in DISRUPTIVE_OPERATIONS:
        return "disruptive"
    return SAFETY_BY_EFFECT[command.effect]


def response_length(command) -> tuple[int | None, int | None]:
    """Return response data length after the completion-code byte."""
    return tuple(None if value is None else value - 1
                 for value in command.response_length_including_cc)


def response_fields(command) -> list[dict]:
    """Remove the runtime decoder's synthetic completion-code field."""
    items = command.response_fields
    if items and items[0].get("name") == "completion_code":
        return items[1:]
    return items


def layout_status(command, *, response: bool) -> str:
    codec = command.response_codec if response else command.request_codec
    low, high = response_length(command) if response else command.request_length
    prose = command.response if response else command.request
    if codec or low == high == 0:
        return "Complete"
    if low is None and high is None and "undetermined" in prose.lower():
        return "Unknown"
    return "Partial"


def length_text(bounds: tuple[int | None, int | None], *, response: bool) -> str:
    low, high = bounds
    unit = "data bytes after completion code" if response else "payload bytes"
    if low is None and high is None:
        return "Unknown"
    if low == high:
        return f"{low} {unit}"
    if high is None:
        return f"At least {low} {unit}"
    if low is None:
        return f"At most {high} {unit}"
    return f"{low}–{high} {unit}"


def _field_width(field: dict) -> int | str:
    if field.get("length") is not None:
        return field["length"]
    if field.get("size") is not None:
        return field["size"]
    return WIDTHS.get(field.get("kind") or field.get("type"), "?")


def fields(items: list[dict], *, complete: bool) -> list[dict] | None:
    if not items:
        return [] if complete else None
    result = []
    next_offset = 0
    for item in items:
        width = _field_width(item)
        offset = item.get("offset", next_offset)
        if isinstance(offset, int) and isinstance(width, int):
            shown_offset = str(offset) if width == 1 else f"{offset}–{offset + width - 1}"
            next_offset = offset + width
        else:
            shown_offset = str(offset)
        field_type = item.get("kind") or item.get("type") or "bytes"
        if field_type == "bytes" and width != "?":
            field_type = f"bytes[{width}]"
        if "constant" in item:
            constant = item["constant"]
            meaning = f"Must be 0x{constant:02x}" if isinstance(constant, int) else f"Must be {constant}"
        else:
            meaning = (item.get("description") or item.get("meaning")
                       or item.get("constraint") or item.get("encoding")
                       or (json.dumps(item["values"], sort_keys=True)
                           if "values" in item else "See operation semantics"))
        result.append({
            "offset": shown_offset,
            "name": item.get("name", "unnamed"),
            "type": field_type,
            "meaning": meaning,
        })
    return result


def identity_bytes(command) -> bytes:
    if command.subcmd is None:
        return command.prefix
    return command.subcmd.to_bytes(max(1, (command.subcmd.bit_length() + 7) // 8), "big")


def operation_id(command) -> str:
    base = f"{command.netfn:02x}/{command.cmd:02x}"
    identity = identity_bytes(command)
    if not identity:
        return base
    encoded = " ".join(f"{byte:02x}" for byte in identity)
    if command.prefix:
        return f"{base} data {encoded}"
    return f"{base} selector@{command.selector_offset} {encoded}"


def named_command(command, listing_row: dict) -> str:
    tokens = ["zipmi", "oem", "idrac10"]
    if listing_row["requires_unsafe"]:
        tokens.append("--unsafe")
    tokens.append(shlex.quote(listing_row["name"]))
    low, high = command.request_length
    fixed = len(command.prefix)
    low = None if low is None else max(0, low - fixed)
    high = None if high is None else max(0, high - fixed)
    if low is None and high is None:
        tokens.append("<payload bytes>")
    elif low == high:
        if low:
            tokens.append(f"<{low} payload bytes>")
    elif high is None:
        tokens.append(f"<at least {low or 0} payload bytes>")
    elif low is None:
        tokens.append(f"<up to {high} payload bytes>")
    else:
        tokens.append(f"<{low}–{high} payload bytes>")
    return " ".join(tokens)


def completion_codes(value: str | dict | list[dict]) -> str:
    if isinstance(value, str):
        return value or "Not separately documented"
    if isinstance(value, dict):
        return ", ".join(value) or "Not separately documented"
    codes = []
    for item in value:
        code = str(item.get("code", "")).lower()
        if code and code not in codes:
            codes.append(code)
    return ", ".join(codes) or "Not separately documented"


def evidence_text(command) -> str:
    parts = [f"Library: {command.lib}"]
    if command.evidence:
        parts.append("Evidence: " + (command.evidence if isinstance(command.evidence, str)
                                     else json.dumps(command.evidence, sort_keys=True,
                                                     separators=(",", ":"))))
    if command.activation:
        parts.append("Activation: " + (command.activation if isinstance(command.activation, str)
                                       else json.dumps(command.activation, sort_keys=True,
                                                       separators=(",", ":"))))
    if command.security:
        parts.append("Security: " + command.security)
    if command.backend_deps:
        parts.append("Backend dependencies: " + command.backend_deps)
    return "; ".join(parts)


def live_text(value: dict | None) -> str:
    if not value:
        return "Not live-tested"
    cc = value.get("cc")
    cc_text = f"0x{cc:02x}" if isinstance(cc, int) else "not parsed"
    return (f'{value.get("verdict", "observed")}; host {value.get("host", "unspecified")}; '
            f'CC {cc_text}; data {value.get("resp") or "(empty)"}')


def operation(command, listing_row: dict) -> dict:
    request_status = layout_status(command, response=False)
    response_status = layout_status(command, response=True)
    execution = "Requires --unsafe" if listing_row["requires_unsafe"] else "Allowed by default"
    note = command.side_effects if command.side_effects and command.side_effects != "none" else ""
    return {
        "id": operation_id(command),
        "send": named_command(command, listing_row),
        "name": command.name,
        "purpose": command.purpose,
        "safety": safety(command),
        "safety_note": note,
        "execution": execution,
        "request": {
            "status": request_status,
            "length": length_text(command.request_length, response=False),
            "summary": command.request,
            "fields": fields(command.request_fields, complete=request_status == "Complete"),
        },
        "response": {
            "status": response_status,
            "length": length_text(response_length(command), response=True),
            "summary": command.response,
            "fields": fields(response_fields(command), complete=response_status == "Complete"),
        },
        "privilege": command.priv,
        "interface": ("System interface only (KCS/in-band)" if command.in_band_only
                      else "Out-of-band or system interface, subject to operation gates"),
        "availability": "Registered in this firmware; conditional gates are listed in evidence",
        "completion_codes": completion_codes(command.completion_codes),
        "live": command.live is not None,
        "live_text": live_text(command.live),
        "evidence": evidence_text(command),
        "confidence": command.confidence,
    }


def reference_page() -> dict:
    commands, listing = _load_commands()
    if len(commands) != 581 or len(listing) != 581:
        raise SystemExit("expected 581 iDRAC10 operation contracts and named CLI routes")
    operations = []
    for command in commands:
        identity = identity_bytes(command)
        key = (command.netfn, command.cmd, *identity)
        operations.append(operation(command, listing[key]))
    pairs = sorted({(command.netfn, command.cmd) for command in commands})
    source = json.loads(SOURCE.read_text())
    target = source["target"]
    return {
        "artifact_marker": ARTIFACT_MARKER,
        "title": "Dell iDRAC10 OEM IPMI command reference",
        "scope": ("Firmware-bound reference for all 581 recovered operations across 255 "
                  "NetFn/Cmd addresses in Dell iDRAC10 firmware 1.30.10.50."),
        "provenance": [
            ("Controller", target["model"]),
            ("Firmware", f'{target["version"]}; internal {target["internalVersion"]}; released {target["releaseDate"]}'),
            ("Firmware DUP SHA-256", f'<code>{target["dupSha256"]}</code>'),
            ("Catalog", "581 operation records; generated 2026-07-05 and subsequently contract-audited"),
        ],
        "links": [{
            "label": "zBMC iDRAC10 firmware analysis",
            "href": "https://github.com/zenfish/zbmc/tree/main/boxes/idrac10",
        }],
        "operations": operations,
        "commands": [{"netfn": netfn, "cmd": cmd} for netfn, cmd in pairs],
        "gaps": ("All 581 catalog records have a recovered NetFn/Cmd identity and a distinct named "
                 "zipmi route. Partial and Unknown layout labels are intentional: exact operation "
                 "identity does not imply that every payload field is decoded. Selector-at-offset-one "
                 "operations require the caller to provide the full payload because zipmi does not "
                 "silently move or inject that selector. Firmware gates and delegated backends can "
                 "still reject a registered command."),
        "live_evidence": ("445 operations carry responses from the catalog's iDRAC10 live sweep. "
                          "These observations prove only the recorded operation and payload; they do "
                          "not make related state-changing operations safe to exercise. Cross-target "
                          "operator note (Supermicro X14 only; not evidence of Dell policy): X14's "
                          "shipped validator requires 8–20 characters, at least three of lowercase, "
                          "uppercase, digit, and supported ASCII punctuation, no leading or trailing "
                          "ASCII space, and a value unequal to the username or its reverse. A 13-byte "
                          "four-class password succeeded live through standard command 0x06/0x47 in "
                          "16-byte mode; a rejected policy candidate returned misleading completion "
                          "code 0xC8. The 16/20-byte selector controls IPMI field width, not complexity "
                          "policy."),
        "sources": [
            '<a href="../zipmi/data/sources/idrac10-commands.json">Reviewed operation-contract JSON</a>',
            '<a href="../zipmi/data/sources/idrac10-dispatch-tables.md">Firmware dispatch-table extraction</a>',
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = render_reference(reference_page())
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != document:
            print("iDRAC10 generated reference is stale", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(document)
    print("wrote iDRAC10 reference: 581 operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
