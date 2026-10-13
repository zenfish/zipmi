# z-artifact: d5a490be-80a0-449b-b952-e551a2e0a667
# z-artifact: pending
"""Invariant checks for the published multi-BMC deep-dive snapshots."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path


ROOT = Path(__file__).parents[2]
SOURCES = ROOT / "zipmi/data/sources"


def load(name: str) -> dict:
    return json.loads((SOURCES / name).read_text())


def test_fujitsu_path_denominator_and_reuse_boundary() -> None:
    document = load("fujitsu-irmc-s6-operation-paths.json")
    assert document["denominator"]["reachable_request_paths"] == 688
    assert document["coverage"]["evidence_state"] == {
        "Decoded": 535, "Unknown": 153,
    }
    assert sum(status.startswith("partial") and count
               for status, count in document["coverage"]["contract_status"].items()) == 329
    shared = document["coverage"]["shared_parameter_engine"]
    assert shared["end_to_end_static_paths_closed_without_provider"] == 19
    assert shared["provider_boundaries_remaining"] == 165
    dual_image = document["coverage"]["shared_dualimage_fragments"]
    assert dual_image["whole_provider_byte_identical"] is False
    assert dual_image["field_proved_selectors"] == ["0x04", "0x07"]


def test_idrac6_dispatch_and_semantic_gap_are_distinct() -> None:
    document = load("idrac6-dispatch-gap-map.json")
    counts = document["counts"]
    assert counts["registrations"] == 213
    assert counts["unique_descriptor_addresses"] == 192
    assert counts["effective_top_level_routes"] == 189
    assert counts["unique_effective_handler_implementations"] == 188
    assert counts["routes_with_decoded_semantic_paths"] == 32
    assert counts["decoded_reachable_semantic_paths"] == 160
    assert document["coverage_summary"]["effective_routes_requiring_semantic_deep_dive"] == 157


def test_idrac9_gap_and_extended_config_stay_partial() -> None:
    gap = load("idrac9-oem-gap-map.json")["denominators"]
    assert (gap["oem_netfn_registrations"], gap["oem_netfn_unique_addresses"]) == (193, 192)
    assert gap["oem_addresses_without_detailed_contracts"] == 143
    assert gap["oem_addresses_closed_in_limbo"] == 20
    assert gap["oem_addresses_remaining_without_detailed_contracts"] == 123
    extended = load("idrac9-extended-config-contracts.json")
    assert (extended["address_count"], extended["fully_closed_addresses"],
            extended["partial_addresses"]) == (3, 0, 3)
    assert "Unknown" in json.dumps(extended)


def test_x11_top_level_and_high_risk_denominators() -> None:
    paths = load("supermicro-x11-operation-paths.json")
    denominator = paths["denominator"]
    assert (denominator["effective_outer_routes"],
            paths["static_coverage"]["unique_table_handlers"],
            denominator["reachable_top_level_operation_paths"]) == (91, 89, 234)
    high_risk = load("supermicro-x11-high-risk-contracts.json")
    assert Counter(row["closure"] for row in high_risk["operations"]) == {
        "closed_at_handler_boundary": 104,
        "closed_at_event_consumer_boundary": 11,
        "partial": 5,
    }
    assert "no X10/X14/XD670" in load(
        "supermicro-x11-downstream-contracts.json"
    )["sharing"]["cross_target"]


def test_each_snapshot_has_a_browsable_report() -> None:
    for name in (
        "fujitsu-irmc-s6-deep-dive.html",
        "idrac6-command-reference.html",
        "idrac9-deep-dive.html",
        "supermicro-x11-command-reference.html",
    ):
        report = (ROOT / "docs" / name).read_text()
        assert "cdn.tailwindcss.com" in report
        assert "<html" in report
