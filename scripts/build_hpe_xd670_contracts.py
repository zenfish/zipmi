#!/usr/bin/env python3
# z-artifact: 1a8bb9fe-e855-42f9-919e-1ed77444a43b
"""Build the evidence-layered HPE XD670 contract artifact."""

from __future__ import annotations

import argparse
import csv
from copy import deepcopy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "zipmi/data/sources/hpe-xd670-operation-contracts.json"
REGISTRATIONS = ROOT / "zipmi/data/sources/hpe-xd670-oem-registrations.csv"
REVIEWED = ROOT / "zipmi/data/sources/hpe-xd670-reviewed-contracts.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _address(netfn: str, command: str) -> str:
    return f"0x{int(netfn, 0):02x}/0x{int(command, 0):02x}"


def _implementation_id(binary_sha256: str, handler: str) -> str:
    return f"sha256:{binary_sha256}:symbol:{handler}"


def _binary_sha256(implementation_id: str) -> str:
    parts = implementation_id.split(":")
    if len(parts) not in (3, 4) or parts[0] != "sha256":
        raise ValueError(f"invalid implementation id: {implementation_id}")
    return parts[1]


def _effective(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    owners = {
        _address(row["wire_netfn"], row["command"]): row
        for row in rows if not row["duplicate_status"].startswith("loser")
    }
    return {key: row for key, row in owners.items()
            if not row["active_if_enabled"].startswith("no")}


def _overlay(row: dict[str, str], implementation_id: str,
             reviewed: dict | None) -> dict:
    return {
        "address": _address(row["wire_netfn"], row["command"]),
        "netfn": row["wire_netfn"],
        "command": row["command"],
        "handler": row["handler"],
        "library": row["plugin"].split(" (", 1)[0],
        "implementation_id": implementation_id,
        "feature_gate": row["feature_gate"],
        "feature_state": row["feature_state"],
        "active_if_enabled": row["active_if_enabled"],
        "registration_class": row["registration_class"],
        "privilege_raw": row["privilege_raw"],
        "privilege_decoded": row["privilege_decoded"],
        "request_length_raw": row["request_length_raw"],
        "request_length_decoded": row["request_length_decoded"],
        "selector_prefix_raw": row["selector_prefix_raw"],
        "selector_prefix_decoded": row["selector_prefix_decoded"],
        "interface_raw": row["interface_raw"],
        "interface_decoded": row["interface_decoded"],
        "load_order": int(row["load_order"]),
        "duplicate_status": row["duplicate_status"],
        "table_symbol": row["table_symbol"],
        "record_offset": row["record_offset"],
        "record_raw": row["record_raw"],
        "blocker": row["blocker"],
        "reviewed_live_contract": reviewed,
    }


def _core(core: dict) -> tuple[dict[str, dict], list[dict], list[dict], dict[str, str]]:
    implementations: dict[str, dict] = {}
    paths = []
    normalized_wire = []
    address_to_implementation = {}
    for contract in core["contracts"]:
        source_id = contract["implementation_id"]
        binary_sha256 = _binary_sha256(source_id)
        implementation_id = _implementation_id(binary_sha256, contract["handler"])
        address = _address(contract["address"]["netfn"], contract["address"]["command"])
        address_to_implementation.setdefault(address, implementation_id)
        if address_to_implementation[address] != implementation_id:
            raise SystemExit(f"multiple core implementations at {address}")
        implementations.setdefault(implementation_id, {
            "implementation_id": implementation_id,
            "binary_sha256": binary_sha256,
            "handler": contract["handler"],
            "source_family": "core-yafu-acd-node-manager",
            "contract_status": "decoded target contract; request paths are separate",
            "authorization_channel": deepcopy(contract["authorization_channel"]),
            "activation_runtime": deepcopy(contract["activation_runtime"]),
            "evidence": deepcopy(contract["evidence"]),
            "unknowns": deepcopy(contract["unknowns"]),
            "source_contract_ids": [],
        })["source_contract_ids"].append(contract["id"])

        path = deepcopy(contract)
        path["implementation_id"] = implementation_id
        paths.append(path)
        if contract["reuse"]["status"].startswith("proven-"):
            normalized_wire.append({
                "id": f"normalized-wire:{contract['id']}",
                "implementation_id": implementation_id,
                "handler": contract["handler"],
                "source_contract_id": contract["id"],
                "request": deepcopy(contract["request"]),
                "response": deepcopy(contract["response"]),
                "completion": deepcopy(contract["completion"]),
                "proof": deepcopy(contract["reuse"]["proof"]),
                "scope": contract["reuse"]["scope"],
            })
    return implementations, paths, normalized_wire, address_to_implementation


def _extensions(extensions: dict, rejected_offsets: dict[str, set[int]]) -> tuple[dict[str, dict], dict[str, str]]:
    implementations = {}
    address_to_implementation = {}
    for command in extensions["commands"]:
        wire = command["wire"]
        binary_sha256 = command["provenance"]["binary_sha256"]
        implementation_id = _implementation_id(binary_sha256, wire["handler"])
        address = _address(wire["netfn"], wire["command"])
        request = deepcopy(command["request"])
        observed = request.get("handler_observed_byte_offsets", [])
        rejected = rejected_offsets.get(wire["handler"], set())
        request["discarded_non_request_offsets"] = [value for value in observed if value in rejected]
        request["handler_observed_byte_offsets"] = [value for value in observed if value not in rejected]
        contract = {
            "implementation_id": implementation_id,
            "binary_sha256": binary_sha256,
            "handler": wire["handler"],
            "library": wire["library"],
            "source_family": "ami-extensions",
            "contract_status": "decoded exact-image implementation; explicit unknowns preserved",
            "request": request,
            "response": deepcopy(command["response"]),
            "authorization": deepcopy(command["authorization"]),
            "interface": deepcopy(command["interface"]),
            "effect": deepcopy(command["effect"]),
            "activation": deepcopy(command["activation"]),
            "completion": deepcopy(command["completion"]),
            "provenance": deepcopy(command["provenance"]),
            "confidence": deepcopy(command["confidence"]),
            "unknowns": deepcopy(command["unknowns"]),
        }
        if implementation_id in implementations:
            raise SystemExit(f"duplicate extension implementation: {implementation_id}")
        implementations[implementation_id] = contract
        address_to_implementation[address] = implementation_id
    return implementations, address_to_implementation


def _selector_status(analysis: dict) -> tuple[str, str]:
    acceptance = analysis.get("closed_acceptance_domain")
    if acceptance:
        resolution = acceptance["resolution"]
        status = "conditional" if ("conditional" in resolution or
                                     "feature-gate" in resolution) else "known"
        return status, resolution
    if analysis["resolution_status"] == "selector-domain-resolved":
        return "known", analysis["resolution_status"]
    return "unresolved", "; ".join(analysis["unresolved"])


def build(evidence_root: Path) -> dict:
    core_path = evidence_root / "core-yafu/contracts.json"
    extensions_path = evidence_root / "ledger/ami-extensions.json"
    request_paths_path = evidence_root / "ledger/ami-request-paths.json"
    acceptance_path = evidence_root / "unresolved/xd670-selector-acceptance.json"
    lineage_path = evidence_root / "lineage/lineage-proof.json"
    inputs = [core_path, extensions_path, request_paths_path, acceptance_path, lineage_path]
    core, extensions, request_paths, acceptance, lineage = map(_load, inputs)
    reviewed_document = _load(REVIEWED)
    with REGISTRATIONS.open(newline="") as stream:
        registrations = list(csv.DictReader(stream))
    effective = _effective(registrations)
    reviewed = {_address(row["netfn"], row["command"]): row
                for row in reviewed_document["operations"]}

    core_impls, core_paths, normalized_wire, core_by_address = _core(core)
    rejected_offsets = {
        row["handler"]: set(row["discarded_offsets"])
        for row in request_paths["validation"]["known_false_absolute_offsets_by_handler"]
    }
    extension_impls, extension_by_address = _extensions(extensions, rejected_offsets)
    implementations = {**core_impls, **extension_impls}
    by_address = {**core_by_address, **extension_by_address}
    if (len(registrations), len({_address(row["wire_netfn"], row["command"])
                                  for row in registrations}), len(effective)) != (143, 142, 141):
        raise SystemExit("registration denominator changed")
    if len(implementations) != 141 or set(by_address) != set(effective):
        raise SystemExit("implementation coverage does not match 141 effective addresses")

    acceptance_by_handler = {row["handler"]: row for row in acceptance["handlers"]}
    selector_analyses = []
    for analysis in request_paths["handlers"]:
        item = deepcopy(analysis)
        item["implementation_id"] = by_address[item["wire"]["address"]]
        item["closed_acceptance_domain"] = deepcopy(
            acceptance_by_handler.get(item["wire"]["handler"])
        )
        item["canonical_status"], item["canonical_status_note"] = _selector_status(item)
        selector_analyses.append(item)

    selector_status_counts = {
        status: sum(row["canonical_status"] == status for row in selector_analyses)
        for status in ("known", "conditional", "unresolved")
    }

    overlays = [_overlay(row, by_address[address], reviewed.get(address))
                for address, row in sorted(effective.items())]
    document = {
        "artifact_uuid": "d250a4a0-1032-4dd2-9795-02acd8b5480a",
        "schema": "zipmi.hpe-xd670.contract-evidence.v2",
        "target": "HPE Cray XD670 BMC v1.27",
        "status": ("141 effective target overlays closed; selector domains remain explicitly "
                   "known, conditional, or unresolved"),
        "inputs": {
            path.name: {"path": str(path), "sha256": _sha256(path)} for path in inputs
        } | {
            "registrations": {"path": str(REGISTRATIONS), "sha256": _sha256(REGISTRATIONS)},
            "reviewed_live_contracts": {"path": str(REVIEWED), "sha256": _sha256(REVIEWED)},
        },
        "counts": {
            "registration_rows": 143,
            "unique_registration_addresses": 142,
            "effective_target_command_overlays": 141,
            "implementation_contracts": 141,
            "closed_core_request_paths": len(core_paths),
            "proven_normalized_wire_contracts": len(normalized_wire),
            "selector_analyses": len(selector_analyses),
            "selector_acceptance_analyses": len(acceptance_by_handler),
            "selector_domains_conditional": selector_status_counts["conditional"],
            "selector_domains_known": selector_status_counts["known"],
            "selector_domains_unresolved": selector_status_counts["unresolved"],
            "reviewed_live_contracts": len(reviewed),
        },
        "denominator_policy": {
            "global_semantic_operation_count": None,
            "reason": ("control-flow switch cases are not wire operations; repeated, nested, "
                       "runtime-conditional, and unresolved paths are retained without summing"),
        },
        "lineage_policy": {
            "rule": lineage["rule"],
            "decision": lineage["decision"],
            "counts": deepcopy(lineage["counts"]),
            "exact_identity_applicability": lineage["exact_identity_applicability"],
        },
        "implementation_contracts": {key: implementations[key]
                                     for key in sorted(implementations)},
        "normalized_wire_contracts": sorted(normalized_wire, key=lambda row: row["id"]),
        "target_command_overlays": overlays,
        "closed_core_request_paths": sorted(core_paths, key=lambda row: row["id"]),
        "selector_analyses": sorted(selector_analyses,
                                    key=lambda row: row["wire"]["address"]),
    }
    assert len({row["implementation_id"] for row in overlays}) == 141
    assert len({row["id"] for row in normalized_wire}) == 25
    assert selector_status_counts == {"known": 9, "conditional": 3, "unresolved": 18}
    assert sorted(value for contract in extension_impls.values()
                  for value in contract["request"].get("discarded_non_request_offsets", [])) == [
                      69075, 69119, 69292, 69895, 71867,
                  ]
    assert all(row["sharing"]["classification"] != "exact-function-identity"
               for row in selector_analyses)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(build(args.evidence_root), indent=2,
                         sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != encoded:
            print("HPE XD670 contract artifact is stale")
            return 1
    else:
        OUTPUT.write_text(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
