# z-artifact: 6024529d-a95e-47bd-b664-bb8a1b064c54
"""Provenance-bound AMI handler contracts shared by target adapters."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path


SOURCE_SHA256 = "70571d8cf5c249ad9ac2a1c2788efc8c07817dfa4a70a04160d9fea0d7cbd15e"
_SOURCE = Path(__file__).parents[2] / "data/sources/hpe-xd670-operation-contracts.json"

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

AMI_HANDLER_CONTRACTS = _document["implementation_contracts"]
AMI_NORMALIZED_WIRE_CONTRACTS = tuple(_document["normalized_wire_contracts"])
AMI_LINEAGE_POLICY = _document["lineage_policy"]
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
    "AMI_LINEAGE_POLICY",
    "AMI_NORMALIZED_WIRE_CONTRACTS",
    "HPE_XD670_CORE_REQUEST_PATHS",
    "HPE_XD670_DENOMINATOR_POLICY",
    "HPE_XD670_SELECTOR_ANALYSES",
    "HPE_XD670_TARGET_OVERLAYS",
    "SOURCE_SHA256",
    "contracts_for_handler",
]
