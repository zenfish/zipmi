#!/usr/bin/env python3
# z-artifact: f841be9f-21fc-4232-8511-70afdb652f85
"""Generate the Fujitsu iRMC S6 reference through the shared renderer."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from oem_reference import render_reference
from zipmi.cli.oem_cmds import _vendor_listing
from zipmi.scapy_ipmi.oem.fujitsu import (
    FUJITSU_OPERATIONS,
    FUJITSU_SELECTOR_PAYLOADS,
)


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs/fujitsu-irmc-s6-command-reference.html"
LIVE = ROOT / "docs/evidence/20260926T204500Z-fujitsu-irmc-safe-live-22.json"
ARTIFACT_MARKER = "a20b2e58-7cbf-4f25-9c6e-1b332e4d102d generated"


def summary(value: object) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return str(value)


def layout_status(text: str, *, complete: bool = False) -> str:
    if complete:
        return "Complete"
    lowered = text.lower()
    if any(word in lowered for word in ("unknown", "unresolved", "not fully resolved",
                                         "handler-specific")):
        return "Unknown"
    return "Partial"


def request_length(value: object) -> str:
    if not isinstance(value, dict):
        return "See request summary"
    if value.get("accepted_total_bytes") is not None:
        return f'Total request bytes: {value["accepted_total_bytes"]}'
    if value.get("selector_specific_length") is not None:
        return f'Total request bytes: {value["selector_specific_length"]}'
    if value.get("length_check_at_entry"):
        return f'Entry length check: {value["length_check_at_entry"]}'
    if value.get("shared_minimum_total_bytes") is not None:
        return f'At least {value["shared_minimum_total_bytes"]} total request bytes'
    return "Unknown"


def response_length(value: object) -> str:
    if not isinstance(value, dict):
        return "See response summary"
    if value.get("success_total_bytes") is not None:
        total = value["success_total_bytes"]
        if isinstance(total, int):
            return f"{max(0, total - 1)} data bytes after completion code"
        return f"Recovered total including completion code: {total}"
    return "Unknown"


def prefix_fields(prefix: bytes) -> list[dict]:
    if len(prefix) == 4 and prefix[:3] == bytes.fromhex("80 28 00"):
        names = ("iana_0", "iana_1", "iana_2", "selector")
    elif prefix and prefix[0] in (0x52, 0xDC):
        names = ("group", "selector")[:len(prefix)]
    else:
        names = tuple(f"prefix_{index}" for index in range(len(prefix)))
    return [
        {"offset": str(index), "name": name, "type": "u8",
         "meaning": f"Must be 0x{byte:02x}"}
        for index, (name, byte) in enumerate(zip(names, prefix, strict=True))
    ]


def response_fields(operation) -> list[dict] | None:
    if operation.netfn != 0x2E or operation.cmd != 0x01:
        return None
    selector = operation.prefix[-1]
    value = {
        0x15: ("reason", "u8", "Last power-on reason"),
        0x16: ("reason", "u8", "Next or last power-off reason"),
        0x18: ("runtime_power_field", "u32le", "Runtime power field"),
        0x1D: ("inhibit", "u8", "Power-off inhibit state"),
    }.get(selector)
    if value is None:
        return None
    name, kind, meaning = value
    width = 4 if kind == "u32le" else 1
    return [
        {"offset": "0", "name": "iana_0", "type": "u8", "meaning": "Must be 0x80"},
        {"offset": "1", "name": "iana_1", "type": "u8", "meaning": "Must be 0x28"},
        {"offset": "2", "name": "iana_2", "type": "u8", "meaning": "Must be 0x00"},
        {"offset": "3", "name": "length", "type": "u8", "meaning": f"Must be {width}"},
        {"offset": "4" if width == 1 else "4–7", "name": name, "type": kind,
         "meaning": meaning},
    ]


def safety(effect: str, *, proven_read: bool = False) -> str:
    """Map free-form recovery notes conservatively onto the shared vocabulary."""
    text = effect.lower()
    if any(term in text for term in (
        "firmware flash", "firmware-flash", "firmware update", "firmware upload",
        "image flashing", "tftp flash worker", "flash/dual-image", "secure erase",
        "delete user", "deletes selected", "creates/deletes user", "clear-all",
        "destructive reset", "reset of memory pda", "restore nvram", "clear idprom",
        "clear fru", "clear battery-backed", "restores variable default",
    )):
        return "destructive"
    if any(term in text for term in (
        "credential", "password", "private key", "certificate", "licensing key",
        "raw test", "raw peci", "peci multi", "i2c write/read", "account",
        "user privilege", "user identity", "sso session", "sensitive fingerprint",
    )):
        return "sensitive"
    pure_read = (proven_read or text == "read"
                 or text.startswith(("read ", "reads ", "none; reads", "none; returns",
                                     "read/compute")))
    if pure_read and not any(term in text for term in (
        "side effect", "advances", "refreshes", "delete", "clear", "write", "set ",
        "mutat", "consume",
    )):
        return "read-only"
    if any(term in text for term in (
        "host power/reset", "request host power-off", "role change", "start/stop",
        "service interruption", "network side effect", "calls onrequestasrrshutdown",
        "shutdown state",
    )):
        return "disruptive"
    if any(term in text for term in (
        "mutation", "mutating", "writes", "write ", "sets ", "set ", "stores ",
        "clears ", "clear ", "changes ", "change ", "persists ", "persistent iel add",
        "allocates ", "initiates ", "trigger ", "force ", "updates ", "update ",
    )):
        return "state-changing"
    if any(term in text for term in ("unknown", "unresolved", "undetermined", "backend-dependent",
                                     "mixed/unknown", "side effects depend")):
        return "unknown"
    return "unknown"


def execution(operation) -> str:
    if not operation.runnable:
        return "No distinct named route"
    return "Requires --unsafe" if operation.requires_unsafe else "Allowed by default"


def operation_send(operation, policy: str) -> str:
    if policy == "No distinct named route":
        return "Not available through zipmi over LAN"
    tokens = ["zipmi", "oem", "fujitsu"]
    if policy == "Requires --unsafe":
        tokens.append("--unsafe")
    tokens.append(shlex.quote(operation.name))
    total = None
    if operation.exact_safe_length is not None:
        total = operation.exact_safe_length
    elif isinstance(operation.request, dict):
        accepted = operation.request.get("accepted_total_bytes")
        selector_length = operation.request.get("selector_specific_length")
        total = accepted if isinstance(accepted, int) else selector_length
        total = total if isinstance(total, int) else None
    elif summary(operation.request).replace(" ", "") in {
        "[52,01]", "[52,a5]", "[dc]",
    }:
        total = len(operation.prefix)
    if total is None:
        tokens.append("<remaining payload bytes>")
    elif total > len(operation.prefix):
        tokens.append(f"<{total - len(operation.prefix)} payload bytes>")
    return " ".join(tokens)


def direct_send(info: dict) -> str:
    tokens = ["zipmi", "oem", "fujitsu", "--unsafe", shlex.quote(info["name"])]
    exact = info.get("request_min")
    if exact is None:
        tokens.append("<payload bytes>")
    elif exact:
        tokens.append(f"<{exact} payload bytes>")
    return " ".join(tokens)


def availability(value: str) -> str:
    if value == "registered; platform-dependent":
        return "Registered; availability depends on platform hardware and enabled features"
    if value == "0f only":
        return "Registered only on host-interface channel 0x0f"
    if value == "standard DCMI branch":
        return "Registered through the standard DCMI group-extension branch"
    return f"Registered when: {value}"


def reference_page() -> dict:
    listing = _vendor_listing("fujitsu")
    top = {key: info for key, info in listing.items() if len(key) == 2}
    operation_pairs = {(item.netfn, item.cmd) for item in FUJITSU_OPERATIONS}
    live_doc = json.loads(LIVE.read_text())
    live_by_wire = {
        (int(item["netfn"], 16), int(item["cmd"], 16), bytes.fromhex(item["request"])): item
        for item in live_doc["results"]
    }
    response_codecs = {
        (netfn, cmd, bytes(request()))
        for netfn, cmd, _offset, _selectors, (request, response) in FUJITSU_SELECTOR_PAYLOADS
        if request is not None and response is not None
    }
    rows = []

    for key, info in sorted(top.items()):
        if key in operation_pairs:
            continue
        effect = info["security"]
        request = info["request"]
        response = info["response"]
        rows.append({
            "id": f"{key[0]:02x}/{key[1]:02x}", "name": info["name"],
            "purpose": effect, "send": direct_send(info),
            "safety": safety(effect), "safety_note": f"Recovered effect: {effect}",
            "execution": "Requires --unsafe",
            "request": {"status": layout_status(request), "length": request,
                        "summary": request, "fields": None},
            "response": {"status": layout_status(response), "length": response,
                         "summary": response, "fields": None},
            "privilege": info["priv"], "interface": "IPMI LAN/session transport; LUN 0",
            "availability": availability(info["activation"]),
            "completion_codes": "Not separately documented", "live": False,
            "live_text": "Not live-tested as this distinct operation",
            "evidence": "; ".join(part for part in (info["lib"], info.get("src"),
                                                     info["confidence"]) if part),
            "confidence": info["confidence"],
        })

    for item in FUJITSU_OPERATIONS:
        key = (item.netfn, item.cmd)
        parent = top[key]
        policy = execution(item)
        request_summary = summary(item.request)
        response_summary = summary(item.response)
        live = live_by_wire.get((item.netfn, item.cmd, item.prefix))
        complete_response = (item.netfn, item.cmd, item.prefix) in response_codecs
        rows.append({
            "id": f'{item.netfn:02x}/{item.cmd:02x} ' + " ".join(f"{byte:02x}" for byte in item.prefix),
            "name": item.name, "purpose": item.effect,
            "send": operation_send(item, policy),
            "safety": safety(item.effect, proven_read=not item.requires_unsafe),
            "safety_note": f"Recovered effect: {item.effect}", "execution": policy,
            "request": {
                "status": layout_status(request_summary, complete=item.exact_safe_length == 4),
                "length": ("4 payload bytes on the named route; firmware may accept trailing bytes"
                           if item.exact_safe_length == 4 else request_length(item.request)),
                "summary": request_summary,
                "fields": prefix_fields(item.prefix),
            },
            "response": {
                "status": layout_status(response_summary, complete=complete_response),
                "length": response_length(item.response), "summary": response_summary,
                "fields": response_fields(item) if complete_response else None,
            },
            "privilege": {2: "User", 3: "Operator", 4: "Administrator"}.get(
                item.privilege, f"Raw privilege {item.privilege}"),
            "interface": ("Host interface, channel 0x0f" if not item.runnable
                          else "IPMI LAN/session transport; LUN 0"),
            "availability": availability(item.activation),
            "completion_codes": "Not separately documented",
            "live": live is not None,
            "live_text": (f'{live_doc["runId"]}; CC 0x{live["completionCode"]:02x}; data '
                          f'{live["response"] or "(empty)"}' if live else "Not live-tested"),
            "evidence": "; ".join(part for part in (
                item.source, f'parent handler {parent["name"]}', parent["lib"],
                parent.get("src"), item.status,
            ) if part),
            "confidence": ("Decoded leaf contract; field descriptions may remain prose"
                           if item.status == "decoded" else "Partial leaf contract"),
        })

    command_pairs = sorted(top)
    if (len(command_pairs), len(rows), len(live_by_wire)) != (135, 355, 22):
        raise SystemExit("unexpected Fujitsu iRMC reference denominator")
    expected_execution = {
        "Allowed by default": 22,
        "Requires --unsafe": 331,
        "No distinct named route": 2,
    }
    if {name: sum(row["execution"] == name for row in rows)
            for name in expected_execution} != expected_execution:
        raise SystemExit("unexpected Fujitsu execution counts")
    return {
        "artifact_marker": ARTIFACT_MARKER,
        "title": "Fujitsu iRMC S6 02.63S OEM IPMI command reference",
        "scope": ("Firmware-bound reference for the PRIMERGY RX2540 M7 iRMC S6 02.63S "
                  "dispatcher and its recovered selector operations."),
        "provenance": [
            ("Controller", "Fujitsu iRMC S6"),
            ("Firmware", "02.63S; SDR 03.67"),
            ("Platform", "PRIMERGY RX2540 M7"),
            ("IPMI dispatcher library", "<code>libipmipdkcmds.so.1.53.20</code>"),
            ("Dispatcher library SHA-256", "<code>35839f7ab40993898666425d50e18654d68791c7dfe3bb5a3c3496e4daa23804</code>"),
            ("Packaged command table SHA-256", "<code>6c25538d508e398135855d59550148b3fd93cdcc045bc9556e4f79c335f72dfa</code>"),
        ],
        "links": [
            {"label": "zBMC firmware analysis and emulation notes",
             "href": "https://github.com/zenfish/zbmc/blob/main/boxes/irmc-fujitsu/index.html"},
            {"label": "zBMC firmware-bound handler reference",
             "href": "https://github.com/zenfish/zbmc/blob/main/boxes/irmc-fujitsu/irmc-s6-oem-reference.html"},
        ],
        "operations": rows,
        "commands": command_pairs,
        "gaps": ("The firmware dispatcher inventory is closed at 148 registration records, 138 "
                 "LUN-aware identities, and 135 NetFn/Cmd addresses. This table folds 12 parent "
                 "dispatch names into their 232 selector/group leaves and retains 123 direct "
                 "commands, for 355 operation rows. Three distinct LUN-3 FRU handlers are not "
                 "exposed as LAN names after the target returned 0xc0 on LUN 3. The 232 leaf count "
                 "does not expand F5/A4's 40 inner selectors, E0/04's 50 maintenance subcommands, "
                 "or the 92 backup/restore parameter records; those nested inventories remain in "
                 "the linked firmware evidence."),
        "live_evidence": (f'The emulated iRMC run {live_doc["runId"]} captured all 22 reviewed '
                          "fixed four-byte read requests. Twenty-one returned completion code 0x00; "
                          "2e/e0 selector 00 returned 0x01. No state-changing request was sent."),
        "sources": [
            '<a href="../zipmi/data/sources/fujitsu-irmc-s6-command-tables.tsv">Packaged dispatcher table</a>',
            '<a href="../zipmi/data/sources/fujitsu-irmc-s6-operations.json">Recovered operation catalog</a>',
            '<a href="evidence/20260926T204500Z-fujitsu-irmc-safe-live-22.json">Captured safe live requests</a>',
            '<a href="https://support.ts.fujitsu.com/Search/SWP1267156.asp">Fujitsu iRMC S6 Concepts &amp; Interfaces</a>',
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = render_reference(reference_page())
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != document:
            print("Fujitsu iRMC generated reference is stale", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(document)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
