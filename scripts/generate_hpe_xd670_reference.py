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


def _status(value: str | None) -> str:
    normalized = (value or "unknown").strip().lower()
    return {"complete": "Complete", "partial": "Partial"}.get(normalized, "Unknown")


def _source_fields(fields: list[dict] | None) -> list[dict] | None:
    if not fields:
        return fields
    return [{
        "offset": field["offset"],
        "name": field["name"],
        "type": field.get("type", f"{field.get('encoding', 'bytes')} / {field.get('size', '?')} byte(s)"),
        "meaning": field["meaning"],
    } for field in fields]


def _selector_state(analysis: dict | None) -> tuple[str, str]:
    if analysis is None:
        return "none", "No request-derived switch was recovered."
    state = analysis["canonical_status"]
    acceptance = analysis.get("closed_acceptance_domain")
    if acceptance:
        resolution = acceptance["resolution"]
        return state, (f"{acceptance['unique_reachable_request_path_count']} exact request "
                       f"paths; {resolution}.")
    if state == "known":
        return "known", (f"{analysis['accepted_semantic_path_count']} accepted semantic "
                         "paths; selector domain resolved.")
    return "unresolved", "; ".join(analysis["unresolved"])


def _request_layout(entry: dict) -> dict:
    if entry["request"]:
        return _layout(entry["request"])
    paths = entry["closed_core_request_paths"]
    if paths:
        lengths = sorted({path["request"]["dispatcher_length"] for path in paths})
        selectors = [path["selector"] for path in paths if path["selector"]]
        return {
            "status": "Complete",
            "length": "; ".join(lengths),
            "summary": f"{len(paths)} closed exact-image request path(s).",
            "fields": ([{
                "offset": selector["offset"], "name": selector["name"],
                "type": "u8 selector", "meaning": selector["meaning"],
            } for selector in selectors] or _source_fields(paths[0]["request"].get("fields"))),
        }
    contract = entry["implementation_contract"]["request"]
    analysis = entry["selector_analysis"]
    state, selector_note = _selector_state(analysis)
    fields = None
    if analysis:
        fields = [{
            "offset": value, "name": "request byte", "type": "decoded access",
            "meaning": f"Proven request access; selector status: {state}.",
        } for value in analysis["request_accesses"]["proven_offsets"]]
    length = contract.get("dispatcher_length", contract.get(
        "dispatcher_length_contract", entry["registration"]["request_length_decoded"]))
    evidence_present = bool(contract.get("handler_observed_byte_offsets") or analysis)
    return {
        "status": _status(contract.get("status", "partial" if evidence_present else "unknown")),
        "length": str(length),
        "summary": ((contract.get("summary") or contract.get("field_semantics") or
                     "Request bytes are not decoded.") + f" Selector domain: {selector_note}"),
        "fields": fields,
    }


def _response_layout(entry: dict) -> dict:
    if entry["response"]:
        return _layout(entry["response"])
    paths = entry["closed_core_request_paths"]
    if paths:
        lengths = sorted({str(path["response"]["length"]) for path in paths})
        return {
            "status": "Complete", "length": ", ".join(lengths),
            "summary": f"Response layout decoded for {len(paths)} closed request path(s).",
            "fields": _source_fields(paths[0]["response"].get("fields")),
        }
    contract = entry["implementation_contract"]["response"]
    expressions = contract.get("response_length_expressions", [])
    evidence_present = bool(contract.get("handler_observed_byte_offsets") or expressions)
    return {
        "status": _status(contract.get("status", "partial" if evidence_present else "unknown")),
        "length": ", ".join(expressions) if expressions else "Not recovered",
        "summary": (contract.get("summary") or contract.get("field_semantics") or
                    "Response bytes are not decoded."),
        "fields": None,
    }


def _safety(entry: dict) -> tuple[str, str]:
    if entry["safety"] != "unknown":
        return entry["safety"], entry["side_effects"]
    paths = entry["closed_core_request_paths"]
    if paths:
        ranks = {"read-only": 0, "sensitive": 1, "state-changing": 2,
                 "disruptive": 3, "destructive": 4, "unknown": 5}
        aliases = {"sensitive-read": "sensitive",
                   "state-changing-or-control": "state-changing"}
        values = [(aliases.get(path["effect"]["class"], path["effect"]["class"]),
                   path["effect"]["summary"]) for path in paths]
        safety, _ = max(values, key=lambda value: ranks.get(value[0], 5))
        return safety, "; ".join(dict.fromkeys(note for _, note in values))
    effect = entry["implementation_contract"]["effect"]
    effect_class = effect.get("class", effect.get("inferred_class", "unknown"))
    safety = {"read/query": "unknown", "read-only": "read-only",
              "sensitive-read": "sensitive", "state-changing": "state-changing",
              "state-changing-or-control": "state-changing", "destructive": "destructive",
              "disruptive": "disruptive"}.get(effect_class, "unknown")
    return safety, effect.get("summary", effect.get("exact_side_effects", "Unknown."))


def _completion(entry: dict) -> str:
    paths = entry["closed_core_request_paths"]
    if paths:
        values = sorted({value for path in paths
                         for value in path["completion"]["direct_completion_codes"]})
    else:
        completion = entry["implementation_contract"]["completion"]
        values = completion.get("codes_assigned_directly_in_exact_decomp")
        if values is None:
            values = [item["code"] for item in completion.get("literal_codes_written", [])]
    return f"Direct writes: {', '.join(values)}; complete map not recovered" if values else "No complete map recovered"


def operation_rows() -> list[dict]:
    rows = []
    for (netfn, command), entry in sorted(HPE_XD670_COMMANDS.items()):
        live = entry["live"]
        selector_state, selector_note = _selector_state(entry["selector_analysis"])
        safety, safety_note = _safety(entry)
        response = live["responseHex"] or "(empty)" if live else None
        rows.append({
            "id": f"{netfn:#04x}/{command:#04x}", "name": entry["handler"],
            "purpose": entry["purpose"] if entry["runnable"] else safety_note,
            "send": (f"zipmi oem hpe-xd670 {entry['name']}" if entry["runnable"]
                     else f"not exposed — raw {netfn:#04x}/{command:#04x}"),
            "safety": safety, "safety_note": safety_note,
            "execution": "Allowed by default" if entry["runnable"] else "No distinct named route",
            "request": _request_layout(entry), "response": _response_layout(entry),
            "privilege": entry["privilege"],
            "interface": entry["registration"]["interface_decoded"],
            "availability": entry["registration"]["active_if_enabled"],
            "completion_codes": _completion(entry), "live": live is not None,
            "live_text": (f"{live['observed']}; CC 0x{live['completionCode']:02x}; "
                          f"data {response}" if live else "Not live-tested"),
            "evidence": (f"{entry['implementation_id']}; "
                         f"{entry['registration']['plugin']}:{entry['registration']['table_symbol']}; "
                         f"selector domain {selector_state}: {selector_note}"),
            "confidence": entry["confidence"] if entry["runnable"] else
                          str(entry["implementation_contract"].get("confidence", "Decoded static evidence")),
        })
    return rows


def reference_page() -> dict:
    return {
        "artifact_marker": REFERENCE_ARTIFACT,
        "title": "HPE Cray XD670 BMC v1.27 OEM IPMI command reference",
        "scope": ("Exact-image reference for all 141 effective command addresses. It separates "
                  "closed request paths, conditional selector domains, and unresolved control "
                  "topology; only four reviewed read-only routes are executable by name."),
        "provenance": [
            ("Signed firmware SHA-256", f"<code>{FIRMWARE_SHA256}</code>"),
            ("Pristine rootfs SHA-256", f"<code>{ROOTFS_SHA256}</code>"),
            ("Registration CSV SHA-256", f"<code>{REGISTRATION_SHA256}</code>"),
            ("Dispatch denominator", "143 registrations / 142 unique addresses / 141 effective commands"),
            ("Path evidence", "55 closed core request paths; 30 selector analyses; no unsupported global semantic-operation count"),
            ("Reusable wire layouts", "25 normalized YAFU contracts with explicit exact-handler/client proof"),
            ("Implementation reuse key", "Exact binary SHA-256 plus handler symbol; target wiring remains in overlays"),
            ("Duplicate precedence", "0x32/0x2c AMIYAFUStateless wins; AMIOemSetRedisDB is shadowed"),
        ],
        "links": [{"label": "Compact registration table", "href": "hpe-xd670-command-table.html"}],
        "operations": operation_rows(),
        "commands": sorted(HPE_XD670_COMMANDS),
        "command_metric_label": "Effective commands",
        "operation_metric_label": "Address contracts",
        "row_noun_singular": "address contract",
        "row_noun_plural": "address contracts",
        "gaps": ("All effective addresses are represented. Selector evidence is labeled known, "
                 "conditional, or unresolved instead of counting control-flow cases as operations. "
                 "Many field meanings, response layouts, interface-mask names, indirect authorization "
                 "checks, and completion-code maps remain explicitly partial or unknown. Only four "
                 "read-only routes have reviewed execution contracts."),
        "live_evidence": ("Four no-mutation probes were captured on the disposable XD670 zBMC guest. "
                          "0x32/0xa6 and 0x32/0x44 succeeded; 0x30/0xe0 returned 0xc7 and "
                          "0x32/0x9d returned 0xff. Error completion codes are not reported as success."),
        "sources": [
            '<a href="../zipmi/data/sources/hpe-xd670-oem-registrations.csv">Frozen exact-image registration catalog</a>',
            '<a href="../zipmi/data/sources/hpe-xd670-reviewed-contracts.json">Reviewed contracts and live evidence</a>',
            '<a href="../zipmi/data/sources/hpe-xd670-operation-contracts.json">Canonical implementation, wire-layout, overlay, and path evidence</a>',
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
        "metrics": [(143, "Registration rows"), (142, "Unique addresses"),
                    (141, "Effective commands"), (30, "Selector analyses"),
                    (25, "Proven reusable wire layouts"),
                    (1, "Shadowed registration"),
                    (4, "Reviewed named routes")],
        "rows": rows,
        "sources": [
            {"href": "../zipmi/data/sources/hpe-xd670-oem-registrations.csv", "label": "Frozen registration catalog"},
            {"href": "../zipmi/data/sources/hpe-xd670-reviewed-contracts.json", "label": "Reviewed contracts"},
            {"href": "../zipmi/data/sources/hpe-xd670-operation-contracts.json", "label": "Canonical operation contracts"},
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
