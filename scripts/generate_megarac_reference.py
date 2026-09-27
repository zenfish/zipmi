#!/usr/bin/env python3
# z-artifact: d45ff092-0b98-4af2-bb80-f275b4c9c819
"""Generate the AMI MegaRAC/YAFU reference and compact command table."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from oem_command_table import render_command_table
from oem_reference import render_reference
from zipmi.scapy_ipmi.oem.megarac import MEGARAC_COMMANDS
from zipmi.scapy_ipmi.oem.yafu import YAFU_BLOCKS, YAFU_COMMANDS


ROOT = Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "docs/megarac-command-reference.html"
TABLE = ROOT / "docs/megarac-command-table.html"
REFERENCE_ARTIFACT = "a11fdc11-c603-4439-8fb1-97a1de0d3e5f generated"
TABLE_ARTIFACT = "6202be82-1c40-41ec-a5df-6cc1106d5697 generated"
CATALOGS = (("megarac", MEGARAC_COMMANDS), ("yafu", YAFU_COMMANDS))
DISRUPTIVE = {
    "AMIActiveSessionClose", "AMICtrlPLDM", "AMIMediaRedirectionStartStop",
    "AMIRISStartStop", "AMIRestartWebService", "ActivateFlashDevice",
    "ActivateFlashMode", "DeactivateFlash", "ResetDevice", "SwitchFlashDevice",
}
DESTRUCTIVE = {
    "AMIManageBMCConfig", "AMIRestoreFactoryDefaults", "AMISetSDCardPartition",
    "AMIStartTFTPFwUpdate", "AMIStartTFTPFwupdate", "AMIYAFUReplaceSignedImageKey",
    "ClearMemory", "EraseCopyFlash", "EraseFlash", "WriteFlash",
}


def safety(entry: dict) -> str:
    """Translate the three source tiers without weakening explicit risk notes."""
    if entry["name"] in DESTRUCTIVE:
        return "destructive"
    if entry["name"] in DISRUPTIVE:
        return "disruptive"
    if entry.get("security"):
        return "sensitive"
    if entry["tier"] in {"mutates", "destructive"}:
        return "state-changing"
    if entry["tier"] == "safe":
        return "read-only"
    return "unknown"


def length(entry: dict, field: str) -> str:
    value = entry.get(field)
    if isinstance(value, int):
        return f"Exactly {value} payload bytes"
    return "Not recovered"


def layout(entry: dict, field: str, length_field: str) -> dict:
    value = entry.get(field)
    return {
        "status": "Partial" if value else "Unknown",
        "length": length(entry, length_field),
        "summary": value or "Not recovered",
        "fields": None,
    }


def send(vendor: str, entry: dict, unsafe: bool) -> str:
    words = ["zipmi", "oem", vendor]
    if unsafe:
        words.append("--unsafe")
    words.append(shlex.quote(entry["name"]))
    exact = entry.get("req_len") if vendor == "yafu" else None
    if exact:
        words.append(f"<{exact} payload bytes>")
    elif exact != 0:
        words.append("<payload bytes>")
    return " ".join(words)


def operation_rows() -> list[dict]:
    rows = []
    for vendor, catalog in CATALOGS:
        for key, entry in sorted(catalog.items()):
            security = entry.get("security")
            unsafe = entry["tier"] != "safe" or bool(security)
            source_tier = entry["tier"]
            block = (entry.get("block") or "unclassified").replace("_", " ")
            if vendor == "yafu":
                block = YAFU_BLOCKS.get(entry.get("block", ""), block)
            rows.append({
                "id": f"{key[0]:02x}/{key[1]:02x}",
                "name": entry["name"],
                "purpose": entry["desc"],
                "send": send(vendor, entry, unsafe),
                "safety": safety(entry),
                "safety_note": (
                    f"Source tier: {source_tier}. "
                    + (f"Security note: {security}" if security else "No separate security note.")
                ),
                "execution": "Requires --unsafe" if unsafe else "Allowed by default",
                "request": layout(entry, "request", "req_len"),
                "response": layout(entry, "response", "resp_len"),
                "privilege": (entry.get("priv") or
                              "Not recovered; target firmware policy varies"),
                "interface": "IPMI session transport; LUN not separately recovered",
                "availability": (
                    "Cataloged MegaRAC registration; exact NetFn 0x30 versus possible 0x3e "
                    "split is unresolved" if vendor == "megarac" else
                    "YAFU protocol-family catalog; target registration is not established"
                ),
                "completion_codes": "Not separately documented",
                "live": False,
                "live_text": "No target-bound request capture is attached to this catalog",
                "evidence": (
                    f"MEGARAC_COMMANDS registration metadata; module {entry['module']}; "
                    f"block {block}" if vendor == "megarac" else
                    f"YAFU_COMMANDS protocol-family metadata; block {block}"
                ),
                "confidence": (
                    "Recovered registration and privilege; payload fields remain prose" if
                    vendor == "megarac" else
                    "Cross-firmware protocol catalog; target activation and privilege unproved"
                ),
            })
    return rows


def reference_page() -> dict:
    rows = operation_rows()
    commands = sorted(set(MEGARAC_COMMANDS) | set(YAFU_COMMANDS))
    if (len(commands), len(rows)) != (137, 137):
        raise SystemExit("unexpected MegaRAC/YAFU reference denominator")
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "AMI MegaRAC and YAFU OEM IPMI command reference",
        "scope": ("Catalog-level reference for 95 recovered MegaRAC registrations and 42 "
                  "cross-firmware YAFU protocol commands. It is not a claim that every YAFU "
                  "command is active on a particular controller."),
        "provenance": [
            ("MegaRAC source", "<code>MEGARAC_COMMANDS</code>; 95 recovered registrations"),
            ("YAFU source", "<code>YAFU_COMMANDS</code>; 42 protocol-family commands"),
            ("Firmware binding", "No single target firmware image or hash applies to this combined catalog"),
            ("Wire caveat", "MegaRAC 0x30 versus possible 0x3e split remains unresolved"),
            ("Policy caveat", "YAFU target activation and minimum privilege remain unproved"),
        ],
        "links": [
            {"label": "Compact MegaRAC/YAFU command table",
             "href": "megarac-command-table.html"},
        ],
        "operations": rows,
        "commands": commands,
        "gaps": ("MegaRAC command bytes and per-registration privileges were recovered, but the "
                 "0x30/possible-0x3e dispatcher split is not closed. YAFU is a protocol-family "
                 "catalog: presence and privilege must be established per target. Request and "
                 "response descriptions are prose contracts; exact field offsets are not claimed."),
        "live_evidence": ("No target-bound capture set is attached. Historical observations in "
                          "individual catalog descriptions are context, not a complete live-test "
                          "denominator for this page."),
        "sources": [
            '<a href="../zipmi/scapy_ipmi/oem/megarac.py">Packaged MegaRAC registration catalog</a>',
            '<a href="../zipmi/scapy_ipmi/oem/yafu.py">Packaged YAFU protocol catalog</a>',
        ],
    }


def compact_page() -> dict:
    rows = []
    for vendor, catalog in CATALOGS:
        for key, entry in sorted(catalog.items()):
            rows.append({
                "address": f"0x{key[0]:02x} / 0x{key[1]:02x}",
                "qualifier": "MegaRAC registration" if vendor == "megarac" else "YAFU family",
                "handler": entry["name"],
                "privilege": entry.get("priv") or "Not recovered per target",
                "request": (length(entry, "req_len") if vendor == "yafu" else
                            "Constraint not recovered; see prose contract"),
                "activation": (
                    "Recovered registration; 0x30/possible 0x3e split unresolved" if
                    vendor == "megarac" else
                    "Protocol-family entry; target activation unproved"
                ),
                "evidence": (
                    f"MEGARAC_COMMANDS; module {entry['module']}; source tier {entry['tier']}" if
                    vendor == "megarac" else
                    f"YAFU_COMMANDS; block {entry.get('block', 'unclassified')}; "
                    f"source tier {entry['tier']}"
                ),
            })
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "AMI MegaRAC and YAFU compact command table",
        "scope": ("Compact identities from the 95-entry MegaRAC registration catalog and "
                  "42-entry YAFU protocol-family catalog. The family qualifier keeps their "
                  "different evidence boundaries visible."),
        "provenance": [
            ("MegaRAC denominator", "95 recovered registrations"),
            ("YAFU denominator", "42 protocol-family entries"),
            ("Firmware binding", "No single target firmware image or hash applies"),
        ],
        "metrics": [(137, "Command rows"), (137, "Unique NetFn/Cmd addresses"),
                    (95, "MegaRAC registrations"), (42, "YAFU family entries")],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/scapy_ipmi/oem/megarac.py", "label": "MegaRAC catalog"},
            {"href": "../zipmi/scapy_ipmi/oem/yafu.py", "label": "YAFU catalog"},
            {"href": "megarac-command-reference.html", "label": "Detailed command reference"},
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
        print("MegaRAC/YAFU generated documentation is stale", file=sys.stderr)
        return 1
    if not args.check:
        for path, _document in documents:
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
