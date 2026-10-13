# z-artifact: 6024529d-a95e-47bd-b664-bb8a1b064c54
"""Provenance-bound AMI handler contracts shared by target adapters."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path


SOURCE_SHA256 = "b0993ab8149b7efe5c91bc44b5080121c6755f08a8fda5f4320013c6aa2a4384"
_SOURCE = Path(__file__).parents[2] / "data/sources/hpe-xd670-operation-contracts.json"
CROSS_TARGET_SOURCE_SHA256 = "655cd2b9c80979640ce5c697f93db75e453bb26234eb391ad68ea205d1fa36e6"
_CROSS_TARGET_SOURCE = Path(__file__).parents[2] / "data/sources/ami-cross-target-fragments.json"

if hashlib.sha256(_SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
    raise RuntimeError("shared AMI contract source does not match the reviewed artifact")

_document = json.loads(_SOURCE.read_text())
if _document["schema"] != "zipmi.hpe-xd670.contract-evidence.v2":
    raise RuntimeError("unsupported shared AMI contract schema")
if _document["counts"] != {
    "closed_core_request_paths": 55,
    "effective_target_command_overlays": 141,
    "implementation_contracts": 141,
    "proven_normalized_wire_contracts": 25,
    "registration_rows": 143,
    "reviewed_live_contracts": 4,
    "selector_acceptance_analyses": 9,
    "selector_analyses": 30,
    "selector_domains_conditional": 3,
    "selector_domains_known": 9,
    "selector_domains_unresolved": 18,
    "unique_registration_addresses": 142,
}:
    raise RuntimeError("shared AMI contract denominator changed")
if _document["denominator_policy"]["global_semantic_operation_count"] is not None:
    raise RuntimeError("unproved global semantic-operation denominator")

if hashlib.sha256(_CROSS_TARGET_SOURCE.read_bytes()).hexdigest() != CROSS_TARGET_SOURCE_SHA256:
    raise RuntimeError("cross-target AMI fragment source does not match the reviewed artifact")
_cross_target_document = json.loads(_CROSS_TARGET_SOURCE.read_text())
if _cross_target_document["schema"] != "zipmi.ami-cross-target-fragments.v1":
    raise RuntimeError("unsupported cross-target AMI fragment schema")

AMI_HANDLER_CONTRACTS = _document["implementation_contracts"]
AMI_NORMALIZED_WIRE_CONTRACTS = tuple(_document["normalized_wire_contracts"])
AMI_LINEAGE_POLICY = _document["lineage_policy"]
AMI_CROSS_TARGET_FRAGMENTS = tuple(_cross_target_document["contracts"])
AMI_CROSS_TARGET_POLICY = _cross_target_document["policy"]
HPE_XD670_TARGET_OVERLAYS = tuple(_document["target_command_overlays"])
HPE_XD670_CORE_REQUEST_PATHS = tuple(_document["closed_core_request_paths"])
HPE_XD670_SELECTOR_ANALYSES = tuple(_document["selector_analyses"])
HPE_XD670_DENOMINATOR_POLICY = _document["denominator_policy"]

_by_handler: dict[str, list[dict]] = defaultdict(list)
for _contract in AMI_HANDLER_CONTRACTS.values():
    _by_handler[_contract["handler"]].append(_contract)


def contracts_for_handler(handler: str) -> tuple[dict, ...]:
    """Return exact implementation contracts; callers must choose a target overlay."""
    return tuple(_by_handler.get(handler, ()))


__all__ = [
    "AMI_HANDLER_CONTRACTS",
    "AMI_CROSS_TARGET_FRAGMENTS",
    "AMI_CROSS_TARGET_POLICY",
    "AMI_LINEAGE_POLICY",
    "AMI_NORMALIZED_WIRE_CONTRACTS",
    "HPE_XD670_CORE_REQUEST_PATHS",
    "HPE_XD670_DENOMINATOR_POLICY",
    "HPE_XD670_SELECTOR_ANALYSES",
    "HPE_XD670_TARGET_OVERLAYS",
    "SOURCE_SHA256",
    "CROSS_TARGET_SOURCE_SHA256",
    "contracts_for_handler",
]
