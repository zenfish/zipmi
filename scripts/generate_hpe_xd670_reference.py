#!/usr/bin/env python3
# z-artifact: f04c3a84-290a-4168-a505-2aff6cb54f0d
"""Generate the firmware-bound HPE Cray XD670 v1.27 OEM references."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oem_command_table import render_command_table
from oem_reference import render_reference
from zipmi.scapy_ipmi.oem.hpe_xd670 import (
    FIRMWARE_SHA256,
    HPE_XD670_COMMANDS,
    HPE_XD670_REGISTRATIONS,
    REGISTRATION_SHA256,
    ROOTFS_SHA256,
)


REFERENCE = ROOT / "docs/hpe-xd670-command-reference.html"
TABLE = ROOT / "docs/hpe-xd670-command-table.html"
REFERENCE_ARTIFACT = "995c8eb4-31d4-45a1-92c4-2d2aa9d7e058 generated"
TABLE_ARTIFACT = "932bbcca-7946-439a-bd43-5e694b9c6e83 generated"


def _length(layout: dict) -> str:
    low, high = layout["minimum_bytes"], layout["maximum_bytes"]
    if low == high and low is not None:
        return f"Exactly {low} payload bytes"
    if low is None and high is None:
        return "Not recovered"
    return f"{low or 0}–{high if high is not None else 'unknown'} payload bytes"


def _layout(layout: dict) -> dict:
    return {
        "status": layout["status"],
        "length": _length(layout),
        "summary": layout["summary"],
        "fields": layout["fields"],
    }


def operation_rows() -> list[dict]:
    rows = []
    for (netfn, command), entry in sorted(HPE_XD670_COMMANDS.items()):
        if not entry["runnable"]:
            continue
        live = entry["live"]
        prefix = " ".join(f"0x{byte:02x}" for byte in (entry["prefix"] or b""))
        response = live["responseHex"] or "(empty)"
        rows.append({
            "id": f"{netfn:02x}/{command:02x}",
            "name": entry["name"],
            "purpose": entry["purpose"],
            "send": f"zipmi oem hpe-xd670 {entry['name']}",
            "safety": entry["safety"],
            "safety_note": entry["side_effects"],
            "execution": "Allowed by default",
            "request": _layout(entry["request"]),
            "response": _layout(entry["response"]),
            "privilege": entry["privilege"],
            "interface": entry["registration"]["interface_decoded"],
            "availability": entry["registration"]["active_if_enabled"],
            "completion_codes": f"Observed 0x{live['completionCode']:02x}",
            "live": True,
            "live_text": (
                f"{live['observed']}; CC 0x{live['completionCode']:02x}; data {response}"
            ),
            "evidence": (
                f"{entry['registration']['plugin']}:{entry['registration']['table_symbol']}; "
                f"selector prefix {prefix or 'none'}; zBMC run "
                "20261012T203124Z-77b23da6-aa05-4c9d-850d-36ad62509d34"
            ),
            "confidence": entry["confidence"],
        })
    return rows


def reference_page() -> dict:
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "HPE Cray XD670 BMC v1.27 OEM IPMI command reference",
        "scope": ("Exact-image reference for four statically reviewed, read-only named routes. "
                  "The full 143-row registration history remains in the compact table; "
                  "unreviewed, variable, and shadowed handlers are not executable by name."),
        "provenance": [
            ("Signed firmware SHA-256", f"<code>{FIRMWARE_SHA256}</code>"),
            ("Pristine rootfs SHA-256", f"<code>{ROOTFS_SHA256}</code>"),
            ("Registration CSV SHA-256", f"<code>{REGISTRATION_SHA256}</code>"),
            ("Dispatch denominator", "143 registrations / 142 effective NetFn-command addresses"),
            ("Duplicate precedence", "0x32/0x2c AMIYAFUStateless wins; AMIOemSetRedisDB is shadowed"),
        ],
        "links": [{"label": "Compact registration table", "href": "hpe-xd670-command-table.html"}],
        "operations": operation_rows(),
        "commands": sorted(HPE_XD670_COMMANDS),
        "gaps": ("Only four read-only handlers have reviewed execution contracts. Registration "
                 "metadata selector_prefix_raw is never treated as request data; only the separately "
                 "reviewed 0x32/0x44 selector 0 is auto-prefixed. A registration proves dispatch, "
                 "not handler safety, runtime feature state, or response schema."),
        "live_evidence": ("Four no-mutation probes were captured on the disposable XD670 zBMC guest. "
                          "0x32/0xa6 and 0x32/0x44 succeeded; 0x30/0xe0 returned 0xc7 and "
                          "0x32/0x9d returned 0xff. Error completion codes are not reported as success."),
        "sources": [
            '<a href="../zipmi/data/sources/hpe-xd670-oem-registrations.csv">Frozen exact-image registration catalog</a>',
            '<a href="../zipmi/data/sources/hpe-xd670-reviewed-contracts.json">Reviewed contracts and live evidence</a>',
            '<a href="../zipmi/scapy_ipmi/oem/hpe_xd670.py">Packaged target module</a>',
        ],
    }


def compact_page() -> dict:
    rows = []
    for row in HPE_XD670_REGISTRATIONS:
        address = f"{row['wire_netfn']} / {row['command']}"
        qualifier = f"{row['registration_class']}; {row['duplicate_status']}"
        rows.append({
            "address": address,
            "qualifier": qualifier,
            "handler": row["handler"],
            "privilege": row["privilege_decoded"],
            "request": row["request_length_decoded"],
            "activation": row["active_if_enabled"],
            "evidence": (f"{row['plugin']}; {row['table_symbol']} + {row['record_offset']}; "
                         f"raw {row['record_raw']}; blocker: {row['blocker']}"),
        })
    return {
        "artifact_marker": TABLE_ARTIFACT,
        "title": "HPE Cray XD670 BMC v1.27 compact OEM registration table",
        "scope": ("All 143 recovered registrations from the pinned image. Both 0x32/0x2c "
                  "registrations are retained so the effective core winner and shadowed Redis "
                  "write handler remain auditable."),
        "provenance": [
            ("Signed firmware SHA-256", f"<code>{FIRMWARE_SHA256}</code>"),
            ("Pristine rootfs SHA-256", f"<code>{ROOTFS_SHA256}</code>"),
            ("Registration CSV SHA-256", f"<code>{REGISTRATION_SHA256}</code>"),
        ],
        "metrics": [(143, "Registration rows"), (142, "Effective addresses"),
                    (1, "Shadowed registration"), (4, "Reviewed named routes")],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/hpe-xd670-oem-registrations.csv", "label": "Frozen registration catalog"},
            {"href": "../zipmi/data/sources/hpe-xd670-reviewed-contracts.json", "label": "Reviewed contracts"},
            {"href": "hpe-xd670-command-reference.html", "label": "Detailed reviewed-operation reference"},
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
    documents = ((REFERENCE, render_reference(reference_page())),
                 (TABLE, render_command_table(compact_page())))
    valid = all(emit(path, document, args.check) for path, document in documents)
    if args.check and not valid:
        print("HPE XD670 generated documentation is stale", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
