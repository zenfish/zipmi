#!/usr/bin/env python3
# z-artifact: 7e864e5f-ce89-4c62-9faf-7b2fac512cf7
"""Generate the Lenovo XCC OEM reference through the shared renderer."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

from oem_reference import render_reference
from zipmi.parsers.lenovo_commands_json import parse_contract_json

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "zipmi/data/sources"
CATALOG = SOURCES / "lenovo-xcc-commands.json"
CONTRACTS = SOURCES / "lenovo-xcc-operation-contracts.json"
LIVE = ROOT / "docs/evidence/20260926T180101Z-lenovo-xcc-safe-live.json"
OUTPUT = ROOT / "docs/lenovo-xcc-command-reference.html"
ARTIFACT_MARKER = "80a0113f-275b-40ea-9f28-089ba1ac988e generated"

DESTRUCTIVE = {"Reset XCC to Default", "OSA Reset to Default"}
DISRUPTIVE = {
    "NMI and Reset", "OSA Graceful Reset", "OSA Memory Check", "Terminal SYS",
    "LAN Ethernet Interface Set", "Active Session Delete",
}
SENSITIVE = {"Push File", "Sessionless Privilege Set", "OEM I2C Master Write Read"}
UNKNOWN = {"Data Collection Status", "OSA Sensor Test"}
WIDTHS = {"u8": 1, "u16le": 2, "u32le": 4}
CATALOG_DESTRUCTIVE = {"datastore delete", "secured datastore delete"}
CATALOG_SENSITIVE = {"BMU credentials get"}


def bounds(value: object) -> tuple[int | None, int | None]:
    if isinstance(value, int):
        return value, value
    if isinstance(value, dict):
        return value.get("min"), value.get("max")
    return None, None


def normalized_contracts(text: str) -> list[dict]:
    """Reuse zipmi's runtime parser so LAN defaults and selectors cannot drift."""
    return [{
        "name": item.name, "netfn": item.netfn, "cmd": item.cmd,
        "selector": item.selector, "selectorOffset": item.selector_offset,
        "prefix": item.prefix, "privilege": item.privilege, "purpose": item.purpose,
        "request": item.request, "response": item.response,
        "requestLength": {"min": item.request_length[0], "max": item.request_length[1]},
        "responseLength": {"min": item.response_length[0], "max": item.response_length[1]},
        "requestFields": item.request_fields, "responseFields": item.response_fields,
        "effect": item.effect, "sideEffects": item.side_effects,
        "completionCodes": item.completion_codes, "channel": item.channel,
        "activation": item.activation, "codecState": item.codec_state,
        "requestCodec": item.request_codec, "responseCodec": item.response_codec,
        "evidence": item.evidence, "source": item.source,
    } for item in parse_contract_json(text)]


def length_text(value: object, *, response: bool = False) -> str:
    low, high = bounds(value)
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


def normalized_fields(items: list[dict], *, complete: bool) -> list[dict] | None:
    if not items:
        return [] if complete else None
    result = []
    offset = 0
    for item in items:
        width = item["length"] if "length" in item else WIDTHS[item["kind"]]
        meaning = (f"Must be 0x{item['constant']:02x}" if "constant" in item
                   else item.get("meaning", "See operation semantics"))
        result.append({
            "offset": str(offset) if width == 1 else f"{offset}–{offset + width - 1}",
            "name": item["name"],
            "type": f"bytes[{width}]" if item["kind"] == "bytes" else item["kind"],
            "meaning": meaning,
        })
        offset += width
    return result


def layout_status(codec: bool, state: str) -> str:
    if codec:
        return "Complete"
    if state == "conflicting-evidence":
        return "Conflicting"
    if state == "unresolved":
        return "Unknown"
    return "Partial"


def contract_safety(item: dict) -> str:
    if item["effect"] == "safe":
        return "read-only"
    name = item["name"]
    if name in DESTRUCTIVE:
        return "destructive"
    if name in DISRUPTIVE:
        return "disruptive"
    if name in SENSITIVE:
        return "sensitive"
    if name in UNKNOWN:
        return "unknown"
    return "state-changing"


def catalog_safety(operation: str, effect: str) -> str:
    if operation in CATALOG_DESTRUCTIVE:
        return "destructive"
    if operation in CATALOG_SENSITIVE:
        return "sensitive"
    text = effect.lower()
    destructive = ("secure-erase", "persistent delete", "reset to default", "firmware-update",
                   "firmware update")
    sensitive = ("credential", "token", "key-lifecycle", "account", "secured",
                 "security state", "lockdown", "physical-presence", "raw i2c", "i2c read/write")
    disruptive = ("reset", "shutdown", "power control", "start/stop", "mount/unmount",
                  "virtual reseat", "service control")
    changing = ("change", "set", "write", "persist", "control", "allocate", "close",
                "append", "trim", "publish", "start", "disable", "enable", "clear",
                "update", "remove", "create", "acquire", "release", "assert", "store",
                "refresh", "consume", "post")
    if any(word in text for word in destructive):
        return "destructive"
    if any(word in text for word in sensitive):
        return "sensitive"
    if any(word in text for word in disruptive):
        return "disruptive"
    if "possible discovery side effect" in text:
        return "unknown"
    if text == "read" or (text.startswith("read") and not any(word in text for word in changing)):
        return "read-only"
    if any(word in text for word in changing):
        return "state-changing"
    return "unknown"


def availability(value: str) -> str:
    replacements = (
        ("admitted but inactive on XCC 6.92 Newyork; dispatch returns c1",
         "Admitted by the dispatcher but inactive on this firmware; returns 0xc1"),
        ("active libipmi outer and inner tables", "Registered in both libipmi dispatch layers"),
        ("active libipmi core table CmdTerminalSYS",
         "Registered in the libipmi core table for serial-terminal operations"),
        ("active libipmi core row", "Registered in the libipmi core table"),
        ("legacy OEM admission route", "Available through the legacy OEM dispatcher"),
        ("legacy direct handler", "Available through a legacy direct handler"),
        ("platform-dependent front USB", "Registered on platforms with front USB support"),
        ("rack-server platforms", "Registered on rack-server platforms"),
    )
    for old, new in replacements:
        if value == old:
            return new
    if value.startswith("registered by "):
        return f"Registered automatically when the IPMI service starts ({value[14:]})"
    if value.startswith("XCC 6.92 firmware-only"):
        return "Available in this firmware; not described by Lenovo's public command reference"
    if value.startswith("active core row;"):
        return "Registered in the core table; usable only when Node Manager pass-through is enabled"
    if value.startswith("active libipmi core request-table row"):
        return "Registered in the core table; successful bridging depends on the platform's Node Manager"
    return value[0].upper() + value[1:]


def confidence(value: str) -> str:
    return {
        "verified": "Complete fixed request and response layouts",
        "raw-exact": "Exact operation identity; one or both layouts remain partial",
        "partial": "Some request or response details remain unresolved",
        "unresolved": "Operation identity is known; payload layout is unknown",
        "conflicting-evidence": "Public documentation and this firmware disagree",
    }[value]


def completion_codes(items: list[dict]) -> str:
    if not items:
        return "Not separately documented"
    return ", ".join(f"0x{item['code']:02x} {item['meaning']}" for item in items)


def request_tokens(fields: list[dict], skip: int = 0) -> tuple[list[str], int]:
    tokens = []
    represented = 0
    for field in fields:
        width = field["length"] if "length" in field else WIDTHS[field["kind"]]
        represented += width
        if skip >= width:
            skip -= width
            continue
        if "constant" in field:
            tokens.append(f"0x{field['constant']:02x}")
        elif field["kind"] == "bytes":
            tokens.append(f"<{field['name']}:{width} bytes>")
        else:
            tokens.append(f"<{field['name']}:{field['kind']}>")
    return tokens, represented


def contract_send(item: dict, execution: str) -> str:
    tokens = ["zipmi", "oem", "lenovo"]
    if execution == "Requires --unsafe":
        tokens.append("--unsafe")
    tokens.append(shlex.quote(item["name"]))
    fields = item.get("requestFields", [])
    field_tokens, represented = request_tokens(fields, len(item.get("prefix", [])))
    tokens.extend(field_tokens)
    low, high = bounds(item.get("requestLength"))
    represented = max(represented, len(item.get("prefix", [])))
    remaining_low = max(0, (low or 0) - represented)
    remaining_high = None if high is None else max(0, high - represented)
    if remaining_high is None:
        if remaining_low:
            tokens.append(f"<at least {remaining_low} data bytes>")
        else:
            tokens.append("<additional data bytes>")
    elif remaining_high:
        tokens.append(f"<{remaining_high} data bytes>" if remaining_low == remaining_high
                      else f"<{remaining_low}–{remaining_high} data bytes>")
    return " ".join(tokens)


def catalog_request_length(item: dict) -> str:
    exact = sorted(rule["request_length"] for rule in item["requestLengthRules"]
                   if rule["length_kind"] == "exact")
    minimum = sorted(rule["request_length"] for rule in item["requestLengthRules"]
                     if rule["length_kind"] == "minimum")
    if exact:
        return f'{", ".join(str(value) for value in exact)} body bytes after the fixed prefix'
    if minimum:
        return f"At least {minimum[0]} body bytes after the fixed prefix"
    return "Unknown"


def exact_selector_tokens(selector: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*", selector):
        return []
    return [f"0x{value.lower()}" for value in selector.split()]


def catalog_send(item: dict, operation: dict, *, distinct: bool, execution: str) -> str:
    if not item["runnable"]:
        return "Not available through zipmi over LAN"
    if not distinct:
        prefix = " ".join(f"0x{byte:02x}" for byte in item["prefix"])
        selector = " ".join(exact_selector_tokens(operation.get("selector", "")))
        return " ".join(part for part in (
            "zipmi raw", f"0x{item['netfn']:02x}", f"0x{item['cmd']:02x}", prefix,
            selector, "<remaining operation payload bytes>",
        ) if part)
    tokens = ["zipmi", "oem", "lenovo"]
    if execution == "Requires --unsafe":
        tokens.append("--unsafe")
    tokens.append(item["name"])
    exact = [rule["request_length"] for rule in item["requestLengthRules"]
             if rule["length_kind"] == "exact"]
    if len(exact) == 1 and exact[0]:
        tokens.append(f"<{exact[0]} body bytes>")
    elif not exact:
        tokens.append("<body bytes>")
    return " ".join(tokens)


def privilege(value: int | None) -> str:
    return {2: "User", 4: "Administrator"}.get(value, "Not established")


def contract_operations(
    contracts: list[dict], live_by_name: dict[str, dict],
    catalog_by_pair: dict[tuple[int, int], list[dict]],
) -> list[dict]:
    rows = []
    for item in contracts:
        request_complete = bool(item.get("requestCodec"))
        response_complete = bool(item.get("responseCodec"))
        low, high = bounds(item.get("requestLength"))
        execution = ("Requires --unsafe" if item["effect"] != "safe" or low is None or high is None
                     else "Allowed by default")
        live = live_by_name.get(item["name"])
        note = item["sideEffects"]
        if item["name"] == "Reset XCC to Default":
            note += "; this firmware accepted the reset from a User-privilege LAN session"
        if "outer route is User despite inner Admin metadata" in item.get("channel", ""):
            note += "; outer dispatcher accepts User privilege despite inner Admin metadata"
        identities = catalog_by_pair.get((item["netfn"], item["cmd"]), [])
        identity_evidence = "; ".join(
            f'firmware identity {identity["name"]}: {identity["handler"]}; {identity["source"]}'
            for identity in identities
        )
        rows.append({
            "id": item["name"], "name": item["name"], "purpose": item["purpose"],
            "send": contract_send(item, execution), "safety": contract_safety(item),
            "safety_note": note, "execution": execution,
            "request": {
                "status": layout_status(request_complete, item["codecState"]),
                "length": length_text(item.get("requestLength")), "summary": item["request"],
                "fields": normalized_fields(item.get("requestFields", []), complete=request_complete),
            },
            "response": {
                "status": layout_status(response_complete, item["codecState"]),
                "length": length_text(item.get("responseLength"), response=True),
                "summary": item["response"],
                "fields": normalized_fields(item.get("responseFields", []), complete=response_complete),
            },
            "privilege": privilege(item.get("privilege")), "interface": item.get("channel", "Not established"),
            "availability": availability(item.get("activation", "availability not established")),
            "completion_codes": completion_codes(item.get("completionCodes", [])),
            "live": live is not None,
            "live_text": (f'{live["zbmcRun"]}; CC {live["completionCode"]}; data '
                          f'{live["responseHex"] or "(empty)"}' if live else "Not live-tested"),
            "evidence": "; ".join(part for part in (
                item["evidence"], item["source"], identity_evidence,
            ) if part),
            "confidence": confidence(item["codecState"]),
        })
    return rows


def catalog_operations(catalog: list[dict], contract_pairs: set[tuple[int, int]]) -> list[dict]:
    rows = []
    for item in catalog:
        if (item["netfn"], item["cmd"]) in contract_pairs:
            continue
        decoded = item.get("operations", [])
        operations = decoded or [{
            "operation": "Firmware identity without a decoded leaf contract", "selector": "",
            "request": item["request"], "response": item["response"],
            "completionCodes": "", "effect": item["sideEffect"],
            "evidence": item["evidenceState"], "source": item["source"],
        }]
        distinct = len(operations) == 1
        cli_safe = (item["sideEffect"] == "likely-read-only"
                    and len(item["requestLengthRules"]) == 1
                    and item["requestLengthRules"][0]["length_kind"] == "exact")
        for operation in operations:
            execution = ("Allowed by default" if distinct and item["runnable"] and cli_safe
                         else "Requires --unsafe" if distinct and item["runnable"]
                         else "No distinct named route")
            effect = operation["effect"]
            request_summary = operation["request"] or item["request"]
            response_summary = operation["response"] or item["response"]
            unknown_request = "undecoded" in request_summary.lower() or "unknown" in request_summary.lower()
            unknown_response = "undecoded" in response_summary.lower() or "unknown" in response_summary.lower()
            selector = operation.get("selector") or "base"
            live = (item.get("liveEvidence") if operation["request"] == "empty"
                    and operation.get("selector", "") == "" else None)
            rows.append({
                "id": f'{item["name"]} [{selector}]',
                "name": operation["operation"], "purpose": item["purpose"],
                "send": catalog_send(item, operation, distinct=distinct, execution=execution),
                "safety": catalog_safety(operation["operation"], effect),
                "safety_note": f"Recovered effect: {effect}",
                "execution": execution,
                "request": {"status": "Unknown" if unknown_request else "Partial",
                            "length": catalog_request_length(item), "summary": request_summary,
                            "fields": None},
                "response": {"status": "Unknown" if unknown_response else "Partial",
                             "length": "Unknown", "summary": response_summary, "fields": None},
                "privilege": privilege(item.get("privilege")), "interface": item["remoteRestriction"],
                "availability": ("Not exposed as a runnable LAN route" if not item["runnable"]
                                 else "Registered in this firmware through " + item["dispatch"].replace("_", " ")),
                "completion_codes": operation.get("completionCodes") or "Not separately documented",
                "live": live is not None,
                "live_text": (f'{live["observed"]}; CC 0x{live["completionCode"]:02x}; data '
                              f'{live["responseHex"] or "(empty)"}' if live
                              else "Not live-tested as this distinct operation"),
                "evidence": f'{item["handler"]}; {operation["evidence"]}; {operation["source"]}',
                "confidence": item["confidence"],
            })
    return rows


def reference_page() -> dict:
    catalog_doc = json.loads(CATALOG.read_text())
    live_doc = json.loads(LIVE.read_text())
    catalog = catalog_doc["commands"]
    contracts = normalized_contracts(CONTRACTS.read_text())
    live_by_name = {item["name"]: {**item, "zbmcRun": live_doc["zbmcRun"]}
                    for item in live_doc["observations"]}
    contract_pairs = {(item["netfn"], item["cmd"]) for item in contracts}
    catalog_by_pair: dict[tuple[int, int], list[dict]] = {}
    for item in catalog:
        catalog_by_pair.setdefault((item["netfn"], item["cmd"]), []).append(item)
    operations = contract_operations(contracts, live_by_name, catalog_by_pair)
    operations += catalog_operations(catalog, contract_pairs)
    unique_pairs = {(item["netfn"], item["cmd"]) for item in catalog}
    if len(catalog) != 225 or len(unique_pairs) != 210 or len(contracts) != 107:
        raise SystemExit("unexpected Lenovo XCC inventory denominator")
    if len(operations) != 335 or len(live_by_name) != 32:
        raise SystemExit("unexpected Lenovo XCC normalized operation count")
    return {
        "artifact_marker": ARTIFACT_MARKER,
        "title": "Lenovo XCC 6.92 OEM IPMI command reference",
        "scope": ("Firmware-bound reference for the complete Lenovo XCC 6.92 Newyork-pass1 "
                  "OEM IPMI inventory and its recovered operations."),
        "provenance": [
            ("Controller", "Lenovo XClarity Controller (XCC)"),
            ("Firmware", "XCC 6.92 Newyork-pass1"),
            ("Firmware evidence artifact", "Preserved signed SquashFS root filesystem"),
            ("Rootfs SHA-256", "<code>2aaedcb6c5939efabd49ac4da0a8066e17c5c3dea356ad33ad0d9246c4b192c2</code>"),
            ("IPMI dispatcher library", "<code>libipmi.so</code>"),
            ("libipmi.so SHA-256", "<code>b72294cd8a10699e2cd3827dd1b4aa0a13943c483332af0ceae8ba603cf17485</code>"),
            ("Research artifact IDs", "Rootfs <code>7c5a00bf-e31e-5c7e-8a91-0f93c30ce5f9</code>; libipmi <code>3eecaf45-6ee5-515d-8e48-a77d5099869d</code>. These stable registry identities remain attached when research metadata changes."),
        ],
        "links": [
            {"label": "zBMC firmware analysis and emulation notes",
             "href": "https://github.com/zenfish/zbmc/blob/main/boxes/lenovo-xcc/index.html"},
            {"label": "zBMC authorization audit",
             "href": "https://github.com/zenfish/zbmc/blob/main/boxes/lenovo-xcc/lenovo-xcc-oem-authorization.html"},
        ],
        "operations": operations,
        "commands": sorted(unique_pairs),
        "gaps": ("The firmware inventory is closed at 225 prefix-qualified identities across 210 "
                 "NetFn/Cmd addresses. The table combines 107 promoted wire contracts with 185 "
                 "catalog-only decoded operations and 43 identities whose leaf payload is not yet "
                 "decoded. Fifty-eight promoted contracts retain partial, unresolved, raw, or "
                 "conflicting layouts. The original update-package-to-rootfs hash chain is unavailable."),
        "live_evidence": ("32 of the 107 promoted contracts have captured requests and responses from "
                          "the emulated firmware. The target reached READY after 382 seconds, including "
                          "an 83-second stable interval. Twenty-nine returned CC 0x00; Board Hardware "
                          "Revision returned 0xce, Front USB Enable Get returned 0xd5, and LAN Unnamed "
                          "OEM Value Get returned 0xcc. Three additional catalog-only reads have older "
                          "live captures, for 35 displayed operations with live evidence. No unsafe "
                          "operation was sent. Separately, the "
                          "authorization audit proved that this firmware accepts the destructive reset "
                          "contract at User privilege; zipmi still requires --unsafe."),
        "sources": [
            '<a href="../zipmi/data/sources/lenovo-xcc-commands.json">Complete firmware identity catalog</a>',
            '<a href="../zipmi/data/sources/lenovo-xcc-operation-contracts.json">Promoted operation contracts</a>',
            '<a href="evidence/20260926T180101Z-lenovo-xcc-safe-live.json">Captured safe live requests</a>',
            '<a href="https://pubs.lenovo.com/xcc/oem_ipmi_commands">Lenovo XCC OEM IPMI commands</a>',
            '<a href="https://pubs.lenovo.com/xcc/get_set_lan_config_parameter">Lenovo XCC LAN parameters</a>',
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = render_reference(reference_page())
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != document:
            print("Lenovo XCC generated reference is stale", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(document)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
