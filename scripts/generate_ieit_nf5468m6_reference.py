#!/usr/bin/env python3
# z-artifact: eec67aae-fbe3-4e41-b81a-68bd4f71d130
"""Generate the firmware-bound IEIT NF5468M6 OEM reference and table."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oem_command_table import render_command_table
from oem_reference import render_reference
from zipmi.scapy_ipmi.oem.ieit import (
    IEIT_COMMANDS,
    IEIT_FIRMWARE_SHA256,
    IEIT_PDK_SHA256,
    IEIT_REGISTRATIONS,
)


REFERENCE = ROOT / "docs/ieit-nf5468m6-command-reference.html"
TABLE = ROOT / "docs/ieit-nf5468m6-command-table.html"
LIVE = ROOT / "zipmi/data/sources/ieit-nf5468m6-live-evidence.json"
REFERENCE_ARTIFACT = "b4b9bfcd-01a6-4e68-b51b-8cd09f6e6c5e generated"
TABLE_ARTIFACT = "b7c7e7f8-6c01-44ec-a25e-7324d1b5cdcc generated"


def _length(bounds: tuple[int | None, int | None]) -> str:
    low, high = bounds
    if low == high and low is not None:
        return f"Exactly {low} payload bytes"
    if low is None and high is None:
        return "Variable length; see the operation contract"
    if high is None:
        return f"At least {low} payload bytes"
    return f"{low if low is not None else 0}–{high} payload bytes"


def _status(command: dict, direction: str) -> str:
    explicit = command.get(f"{direction}_status")
    if explicit:
        return explicit
    placeholder = (
        "Variable-length payload; handler contract required."
        if direction == "request" else "Handler-specific response."
    )
    if command[direction] == placeholder:
        return "Unknown"
    return "Complete" if command["confidence"].startswith("high") else "Partial"


def _prefix(key: tuple[int, ...], command: dict) -> bytes:
    return command["prefix"] if "prefix" in command else bytes(key[2:])


def _identity(key: tuple[int, ...], command: dict) -> bytes:
    return command.get("route_identity", _prefix(key, command))


def _send(key: tuple[int, ...], command: dict) -> str:
    words = ["zipmi", "oem", "ieit"]
    if command["safety"] != "read-only":
        words.append("--unsafe")
    words.append(shlex.quote(command["name"]))
    low, high = command["request_length"]
    fixed = len(_prefix(key, command))
    remaining_low = None if low is None else max(0, low - fixed)
    remaining_high = None if high is None else max(0, high - fixed)
    if remaining_low or remaining_high:
        if remaining_low == remaining_high:
            words.append(f"<{remaining_low} payload bytes>")
        else:
            words.append("<payload bytes>")
    return " ".join(words)


def _live_results() -> dict[tuple[int, int, bytes], dict]:
    evidence = json.loads(LIVE.read_text())
    results = {}
    for probe in evidence["probes"]:
        if "netfn" not in probe or "cmd" not in probe:
            continue
        results[(
            int(probe["netfn"], 0), int(probe["cmd"], 0),
            bytes.fromhex(probe.get("request_hex", "")),
        )] = probe
    return results


def _live(key: tuple[int, ...], command: dict, results: dict) -> tuple[bool, str]:
    probe = results.get((key[0], key[1], _prefix(key, command)))
    if probe is None:
        return False, "No retained live request for this exact operation"
    detail = probe["result"]
    if probe.get("retained_response"):
        detail += f"; retained response {probe['retained_response']}"
    if probe.get("note"):
        detail += f"; {probe['note']}"
    return True, detail


def _evidence(command: dict) -> str:
    registrations = command["registrations"]
    evidence = [
        f"{registration['binary']}:{registration['table']}[{registration['table_index']}] "
        f"→ {registration['handler']}"
        for registration in registrations
    ]
    source = command.get("source_contract", {})
    if command.get("operation_id"):
        evidence.append(command["operation_id"])
    if source.get("target_evidence_ref"):
        evidence.append(source["target_evidence_ref"])
    evidence.extend(source.get("evidence", ()))
    return "; ".join(evidence)


def operation_rows() -> list[dict]:
    results = _live_results()
    rows = []
    for key, command in IEIT_COMMANDS.items():
        live, live_text = _live(key, command, results)
        identity = _identity(key, command)
        source_id = command.get("operation_id") or command.get("source_contract", {}).get("id")
        rows.append({
            "id": (source_id or f"{key[0]:02x}/{key[1]:02x}") + (
                " selector " + " ".join(f"{byte:02x}" for byte in identity)
                if identity and not source_id else ""
            ),
            "name": command["name"],
            "purpose": command["purpose"],
            "send": _send(key, command),
            "safety": command["safety"],
            "safety_note": command["side_effects"],
            "execution": (
                "Allowed by default" if command["safety"] == "read-only"
                else "Requires --unsafe"
            ),
            "request": {
                "status": _status(command, "request"),
                "length": _length(command["request_length"]),
                "summary": command["request"],
                "fields": command["request_fields"],
            },
            "response": {
                "status": _status(command, "response"),
                "length": command.get("response_length_text", "See response contract"),
                "summary": command["response"],
                "fields": command["response_fields"],
            },
            "privilege": command["privilege"],
            "interface": "Raw OEM NetFn over authenticated IPMI; no IANA prefix",
            "availability": command["activation"],
            "completion_codes": command["completion_codes"] or "Not separately recovered",
            "live": live,
            "live_text": live_text,
            "evidence": _evidence(command),
            "confidence": command["confidence"],
        })
    return rows


def reference_page() -> dict:
    operations = operation_rows()
    selector_routes = sum(bool(_identity(key, command))
                          for key, command in IEIT_COMMANDS.items())
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "IEIT NF5468M6 OEM IPMI command reference",
        "scope": (
            f"Firmware-bound contracts for {len(IEIT_REGISTRATIONS)} OEM registration rows "
            f"({len({(r['netfn'], r['cmd']) for r in IEIT_REGISTRATIONS})} unique addresses) "
            "and their statically recoverable selector operations."
        ),
        "provenance": [
            ("Target", "IEIT NF5468M6; AMI MegaRAC SP-X 12.1 / WolfPass / AST2500"),
            ("BMC firmware", "7.26.05; generated 2026-07-07 09:24:15 +0800"),
            ("Firmware SHA-256", f"<code>{IEIT_FIRMWARE_SHA256}</code>"),
            ("IEIT PDK provider", "<code>/usr/local/lib/libipmipdkcmds.so.6.1.0</code>"),
            ("IEIT PDK SHA-256", f"<code>{IEIT_PDK_SHA256}</code>"),
            ("Registration closure", "324 rows / 323 unique NetFn/Cmd addresses"),
            ("AMI NetFn 0x32", "183 registrations / 470 target-decompiled operations"),
            ("IEIT PDK NetFn 0x3c", "129 registrations / 282 normalized operations"),
            ("Selector routes", str(selector_routes)),
            ("Known collision", "NetFn 0x30 / Cmd 0xe2 has IEIT common-interface and Intel PNM providers"),
        ],
        "links": [{"label": "Compact IEIT NF5468M6 command table", "href": "ieit-nf5468m6-command-table.html"}],
        "operations": operations,
        "commands": sorted({(key[0], key[1]) for key in IEIT_COMMANDS}),
        "gaps": (
            "External or indirect handler boundaries are labeled explicitly. Runtime data can replace "
            "the embedded BIOS translation table, and framework registration order does not statically "
            "resolve the 0x30/0xe2 provider collision."
        ),
        "live_evidence": (
            "Only read-only requests were attempted. NetFn 0x30/Cmd 0xe2 timed out and left the "
            "emulated IPMI service unhealthy, so the route is classified disruptive and gated. "
            "No credential-bearing or mutating command was sent."
        ),
        "sources": [
            '<a href="../zipmi/data/sources/ieit-nf5468m6-dispatch.json">Extracted dispatch ledger</a>',
            '<a href="../zipmi/data/sources/ieit-nf5468m6-netfn30-34-38.json">Platform/BIOS selector analysis</a>',
            '<a href="../zipmi/data/sources/ieit-nf5468m6-pdk-contracts.json">IEIT NetFn 0x3c analysis</a>',
            '<a href="../zipmi/data/sources/ieit-nf5468m6-ami-netfn32-contracts.json">AMI NetFn 0x32 analysis</a>',
            '<a href="../zipmi/data/sources/ieit-nf5468m6-aux-contracts.json">PNM, HPM, chassis, and ATS analysis</a>',
            '<a href="../zipmi/data/sources/ieit-nf5468m6-live-evidence.json">Safe live evidence</a>',
            '<a href="../zipmi/scapy_ipmi/oem/ieit.py">Packaged target implementation</a>',
        ],
    }


def compact_page() -> dict:
    rows = []
    for key, command in IEIT_COMMANDS.items():
        identity = _identity(key, command)
        rows.append({
            "address": f"0x{key[0]:02x} / 0x{key[1]:02x}",
            "qualifier": (
                "selector " + " ".join(f"{byte:02x}" for byte in identity)
                + (f" at byte {command['selector_offset']}"
                   if command.get("selector_offset") not in (None, 0) else "")
                if identity else "top-level registration"
            ),
            "handler": command["name"],
            "privilege": command["privilege"],
            "request": _length(command["request_length"]),
            "activation": command["activation"],
            "evidence": _evidence(command),
        })
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "IEIT NF5468M6 compact OEM command table",
        "scope": "One row per named top-level or selector operation in the pinned firmware catalog.",
        "provenance": [
            ("Firmware SHA-256", f"<code>{IEIT_FIRMWARE_SHA256}</code>"),
            ("IEIT PDK SHA-256", f"<code>{IEIT_PDK_SHA256}</code>"),
            ("Registration denominator", "324 rows / 323 unique addresses"),
        ],
        "metrics": [
            (324, "Firmware registration rows"),
            (323, "Unique NetFn/Cmd addresses"),
            (len(rows), "Named operation routes"),
            (sum(bool(_identity(key, command))
                 for key, command in IEIT_COMMANDS.items()), "Selector-specific routes"),
        ],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/ieit-nf5468m6-dispatch.json", "label": "Dispatch ledger"},
            {"href": "../zipmi/data/sources/ieit-nf5468m6-ami-netfn32-contracts.json", "label": "AMI contracts"},
            {"href": "../zipmi/data/sources/ieit-nf5468m6-pdk-contracts.json", "label": "IEIT PDK contracts"},
            {"href": "../zipmi/data/sources/ieit-nf5468m6-aux-contracts.json", "label": "Auxiliary contracts"},
            {"href": "ieit-nf5468m6-command-reference.html", "label": "Detailed command reference"},
        ],
    }


def emit(path: Path, document: str, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text() == document
    path.write_text(document)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    documents = (
        (REFERENCE, render_reference(reference_page())),
        (TABLE, render_command_table(compact_page())),
    )
    valid = all(emit(path, document, args.check) for path, document in documents)
    if args.check and not valid:
        print("IEIT NF5468M6 generated documentation is stale", file=sys.stderr)
        return 1
    if not args.check:
        for path, _document in documents:
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
