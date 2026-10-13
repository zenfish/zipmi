# z-artifact: 6d0a819c-adc2-457e-9c6a-36dfab6f790b
"""HPE XD670 exact-image catalog, precedence, and fail-closed route tests."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys

from zipmi.cli.oem_cmds import _vendor_listing, cmd_oem_run
from zipmi.scapy_ipmi.oem.hpe_xd670 import (
    HPE_XD670_COMMANDS,
    HPE_XD670_REGISTRATIONS,
)
from zipmi.scapy_ipmi.oem.ami_contracts import (
    AMI_CROSS_TARGET_FRAGMENTS,
    AMI_CROSS_TARGET_POLICY,
    AMI_HANDLER_CONTRACTS,
    AMI_LINEAGE_POLICY,
    AMI_NORMALIZED_WIRE_CONTRACTS,
    HPE_XD670_CORE_REQUEST_PATHS,
    HPE_XD670_DENOMINATOR_POLICY,
    HPE_XD670_SELECTOR_ANALYSES,
    HPE_XD670_TARGET_OVERLAYS,
    contracts_for_handler,
)


ROOT = Path(__file__).parents[2]


def test_catalog_closes_registration_precedence() -> None:
    assert len(HPE_XD670_REGISTRATIONS) == 143
    assert len({(row["wire_netfn"], row["command"])
                for row in HPE_XD670_REGISTRATIONS}) == 142
    assert len(HPE_XD670_COMMANDS) == 141
    assert sum(row["duplicate_status"] == "unique"
               for row in HPE_XD670_REGISTRATIONS) == 141
    assert HPE_XD670_COMMANDS[(0x32, 0x2C)]["handler"] == "AMIYAFUStateless"
    assert all(row["handler"] != "AMIOemSetRedisDB"
               for row in HPE_XD670_COMMANDS.values())
    assert all(row["handler"] != "IncreasePayloadSize"
               for row in HPE_XD670_COMMANDS.values())
    duplicates = [row for row in HPE_XD670_REGISTRATIONS
                  if (row["wire_netfn"], row["command"]) == ("0x32", "0x2c")]
    assert {row["handler"] for row in duplicates} == {
        "AMIYAFUStateless", "AMIOemSetRedisDB",
    }


def test_only_reviewed_routes_are_runnable_and_prefix_is_explicit() -> None:
    runnable = {key for key, row in HPE_XD670_COMMANDS.items() if row["runnable"]}
    assert runnable == {(0x30, 0xE0), (0x32, 0x44), (0x32, 0x9D), (0x32, 0xA6)}
    assert HPE_XD670_COMMANDS[(0x32, 0x44)]["prefix"] == b"\x00"
    assert HPE_XD670_COMMANDS[(0x32, 0x2C)]["prefix"] is None
    assert all(row["prefix"] is None for key, row in HPE_XD670_COMMANDS.items()
               if key != (0x32, 0x44))


def test_contract_layers_have_unique_provenance_bound_ownership() -> None:
    assert len(AMI_HANDLER_CONTRACTS) == 141
    assert len(HPE_XD670_TARGET_OVERLAYS) == 141
    assert len({row["address"] for row in HPE_XD670_TARGET_OVERLAYS}) == 141
    assert {row["address"] for row in HPE_XD670_TARGET_OVERLAYS} == {
        f"0x{netfn:02x}/0x{command:02x}" for netfn, command in HPE_XD670_COMMANDS
    }
    assert HPE_XD670_DENOMINATOR_POLICY["global_semantic_operation_count"] is None
    assert "names alone" in AMI_LINEAGE_POLICY["rule"]
    for row in HPE_XD670_COMMANDS.values():
        implementation = row["implementation_contract"]
        assert implementation["implementation_id"] == row["implementation_id"]
        assert row["implementation_id"].startswith("sha256:")
        assert ":symbol:" in row["implementation_id"]
        assert implementation in contracts_for_handler(row["handler"])


def test_normalized_wire_contracts_have_explicit_proof() -> None:
    assert len(AMI_NORMALIZED_WIRE_CONTRACTS) == 25
    assert len({row["id"] for row in AMI_NORMALIZED_WIRE_CONTRACTS}) == 25
    for row in AMI_NORMALIZED_WIRE_CONTRACTS:
        assert row["implementation_id"] in AMI_HANDLER_CONTRACTS
        assert row["proof"]
        assert all(proof["path"] and len(proof["sha256"]) == 64
                   for proof in row["proof"])
        assert row["request"] and row["response"]
        assert row["scope"].startswith("wire fields only")


def test_cross_target_reuse_is_limited_to_proved_dual_image_fragments() -> None:
    assert AMI_CROSS_TARGET_POLICY["whole_provider_equivalence"] is False
    assert {row["selector"] for row in AMI_CROSS_TARGET_FRAGMENTS} == {
        "0x04", "0x07",
    }
    assert all(row["request_length"] == 1 for row in AMI_CROSS_TARGET_FRAGMENTS)
    assert all(row["targets"] == [
        "fujitsu_irmc_s6_02_63s", "hpe_xd670_1_27",
    ] for row in AMI_CROSS_TARGET_FRAGMENTS)


def test_request_paths_preserve_constraints_without_impossible_offsets() -> None:
    assert len(HPE_XD670_CORE_REQUEST_PATHS) == 55
    assert len(HPE_XD670_SELECTOR_ANALYSES) == 30
    assert len({row["implementation_id"] for row in HPE_XD670_SELECTOR_ANALYSES}) == 30
    assert {status: sum(row["canonical_status"] == status
                        for row in HPE_XD670_SELECTOR_ANALYSES)
            for status in ("known", "conditional", "unresolved")} == {
                "known": 9, "conditional": 3, "unresolved": 18,
            }
    by_handler = {row["wire"]["handler"]: row for row in HPE_XD670_SELECTOR_ANALYSES}
    assert by_handler["AMIGetRISConf"]["closed_acceptance_domain"][
        "unique_reachable_request_path_count"] == 45
    assert by_handler["AMISetRISConf"]["closed_acceptance_domain"][
        "unique_reachable_request_path_count"] == 157
    assert by_handler["AMIGetRAIDInfo"]["closed_acceptance_domain"][
        "unique_reachable_request_path_count"] == 87
    assert by_handler["AMISetFirewall"]["closed_acceptance_domain"][
        "unique_reachable_request_path_count"] == 72
    for analysis in HPE_XD670_SELECTOR_ANALYSES:
        assert analysis["implementation_id"] in AMI_HANDLER_CONTRACTS
        assert analysis["sharing"]["classification"] != "exact-function-identity"
        assert all(offset <= 0xff for offset in
                   analysis["request_accesses"]["proven_offsets"])
        assert len({path["path_id"] for path in analysis["paths"]}) == len(analysis["paths"])
        for path in analysis["paths"]:
            for constraint in path["constraints"]:
                assert constraint["control_site"]
                assert 0 <= constraint["request_offset"] <= 0xff
        acceptance = analysis["closed_acceptance_domain"]
        if acceptance:
            assert acceptance["unique_reachable_request_path_count"] > 0
            assert all(path["constraints"] for path in acceptance["paths"])
    for contract in AMI_HANDLER_CONTRACTS.values():
        assert all(offset <= 0xff for offset in
                   contract.get("request", {}).get("handler_observed_byte_offsets", []))


def test_reviewed_live_results_preserve_errors_as_errors() -> None:
    assert HPE_XD670_COMMANDS[(0x32, 0xA6)]["live"] == {
        "observed": "LIVE-SUCCESS", "completionCode": 0,
        "responseHex": "555443", "responseText": "UTC",
    }
    assert HPE_XD670_COMMANDS[(0x32, 0x44)]["live"]["responseHex"] == "010104070000"
    assert HPE_XD670_COMMANDS[(0x30, 0xE0)]["live"]["completionCode"] == 0xC7
    assert HPE_XD670_COMMANDS[(0x32, 0x9D)]["live"]["completionCode"] == 0xFF


def test_reviewed_routes_send_exact_bytes(monkeypatch) -> None:
    import zipmi.cli.zipmi as cli

    sent = []

    class Session:
        def send_raw(self, netfn, command, data):
            sent.append((netfn, command, bytes(data)))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    for name in ("AMIGetTimeZone", "AMIRemoteDebugGetInfo"):
        args = argparse.Namespace(cmd_name=name, data=[], unsafe=False, json=True)
        assert cmd_oem_run(args, "hpe-xd670") == 0
    assert sent == [(0x32, 0xA6, b""), (0x32, 0x44, b"\x00")]


def test_unreviewed_route_fails_closed_even_with_unsafe(capsys) -> None:
    args = argparse.Namespace(cmd_name="AMIYAFUStateless", data=[], unsafe=True, json=True)
    assert cmd_oem_run(args, "hpe-xd670") == 2
    assert "execution contract is incomplete or unsafe" in capsys.readouterr().err


def test_aliases_parse_and_load() -> None:
    import zipmi
    from zipmi.cli.zipmi import parse_cli

    for alias in ("hpe-xd670", "xd670", "megarac-hpe"):
        assert parse_cli(["oem", alias]).cmd_name is None
        zipmi.load_vendor(alias)


def test_generated_hpe_xd670_documents_are_current() -> None:
    subprocess.run(
        [sys.executable, "scripts/generate_hpe_xd670_reference.py", "--check"],
        cwd=ROOT, check=True,
    )
    reference = (ROOT / "docs/hpe-xd670-command-reference.html").read_text()
    table = (ROOT / "docs/hpe-xd670-command-table.html").read_text()
    assert reference.count('<tr data-search="') == 141
    assert table.count('<tr data-search="') == 143
    assert "AMIYAFUStateless wins; AMIOemSetRedisDB is shadowed" in reference
    assert "loser to built-in AMIYAFUStateless" in table
    assert "143 registrations / 142 unique addresses / 141 effective commands" in reference
    assert "141</strong>Effective commands" in reference
    assert "141</strong>Address contracts" in reference
    assert "Unknown</span> <strong>87 address contracts" in reference
    assert "Address Contracts" in reference
    assert "address contracts shown" in reference
    assert "no unsupported global semantic-operation count" in reference
    assert "selector domain unresolved" in reference
    assert "141</strong>Effective commands" in table
    assert "CC 0xc7" in reference and "CC 0xff" in reference
