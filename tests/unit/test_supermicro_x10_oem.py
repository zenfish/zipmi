# z-artifact: 05e8dd67-1f30-4be5-bdfd-d1a1bfbeabb8
# z-artifact: pending
"""Supermicro X10 firmware contract, CLI, documentation, and lineage closure."""

from __future__ import annotations

import argparse
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_x10_denominators_and_firmware_binding_are_closed():
    from zipmi.scapy_ipmi.oem.supermicro_x10 import (
        SUPERMICRO_X10,
        X10_CATALOG,
        X10_FIRMWARE_SHA256,
        X10_PROVIDER_SHA256,
        X10_REGISTRATIONS,
    )

    assert X10_FIRMWARE_SHA256 == "9bd3fbe8ddb8ee8e0f7d96ee37c810cef99d6c9f9566ddd13dca7ea455204214"
    assert X10_PROVIDER_SHA256 == "128d486c2de83d7e5dfddc0a25f74142f0c3fe265567ad4b1221c8defdbe3d07"
    assert len(X10_REGISTRATIONS) == 91
    assert len({row["wire_key"] for row in X10_REGISTRATIONS}) == 91
    assert len(SUPERMICRO_X10) == X10_CATALOG["closure"]["operation_rows"] == 286
    assert sum(key[:2] == (0x30, 0x68) for key in SUPERMICRO_X10) == 38
    assert sum(key[:2] == (0x30, 0x70) for key in SUPERMICRO_X10) == 113
    assert sum(key[:2] == (0x30, 0xA0) for key in SUPERMICRO_X10) == 46


def test_x10_generation_is_distinct_and_repurposed_routes_are_named():
    from zipmi.scapy_ipmi.oem.supermicro_x10 import SUPERMICRO_X10

    assert SUPERMICRO_X10[(0x30, 0xA0, 0x01)]["handler"] == "GetUploadResvID"
    assert SUPERMICRO_X10[(0x30, 0xA0, 0xFF)]["handler"] == "SetOOBDebugFlag"
    assert SUPERMICRO_X10[(0x30, 0x6E)]["handler"] == "OEMGetSMIReason"


def test_x10_every_operation_has_closed_semantics_and_safety():
    from zipmi.scapy_ipmi.oem.supermicro_x10 import X10_CATALOG

    rows = X10_CATALOG["operations"]
    assert all(row["safety"] in {
        "read-only", "sensitive", "state-changing", "disruptive", "destructive",
    } for row in rows)
    assert all(row["request"]["status"].startswith("complete") for row in rows)
    assert all(row["response"]["status"].startswith("complete") for row in rows)
    assert not [row for row in rows if row["handler"].startswith(("OEMCommandSet_68_", "OEMCommandSet_70_"))]


def test_x10_direct_bounds_are_explicit_not_scraped_from_prose():
    from scripts.build_supermicro_x10_contract import _length_bounds
    from zipmi.scapy_ipmi.oem.supermicro_x10 import SUPERMICRO_X10

    assert _length_bounds(3, None, "test", "request") == (3, 3)
    assert _length_bounds("byte 0; offset <64; 0xC7", (2, 2), "test", "request") == (2, 2)
    with pytest.raises(ValueError, match="needs explicit bounds"):
        _length_bounds("byte 0; offset <64; 0xC7", None, "test", "request")

    assert SUPERMICRO_X10[(0x3C, 0x08)]["request_length"] == (3, 3)
    assert SUPERMICRO_X10[(0x3C, 0x09)]["request_length"] == (2, 2)
    assert SUPERMICRO_X10[(0x30, 0x62)]["request_length"] == (6, None)
    assert SUPERMICRO_X10[(0x30, 0x49)]["request_length"] == (1, None)
    assert SUPERMICRO_X10[(0x30, 0x2C)]["request_length"] == (3, 4)


def test_x10_genealogy_covers_both_generations_and_behavior_deltas():
    from zipmi.scapy_ipmi.oem.supermicro_x10 import X10_CATALOG

    rows = X10_CATALOG["genealogy"]
    relations = {row["relation"] for row in rows}
    assert {"retained", "renamed-reframed", "behavior-changed", "x10-only-dropped", "x14-new", "repurposed"} <= relations
    assert any(row["lineage_id"] == "file-oob-parent-a0" and row["relation"] == "repurposed" for row in rows)
    assert any("shell" in row["risk_delta"].lower() and row["relation"] == "behavior-changed" for row in rows)


def test_x10_safe_live_evidence_is_attached_to_exact_routes():
    from zipmi.scapy_ipmi.oem.supermicro_x10 import SUPERMICRO_X10

    live = {key: row["live"] for key, row in SUPERMICRO_X10.items() if row["live"]}
    assert set(live) == {
        (0x2E, 0x05), (0x30, 0x07), (0x30, 0x0C), (0x30, 0x10),
        (0x30, 0x21), (0x30, 0x2A), (0x30, 0x70, 0x77), (0x3C, 0x03),
    }
    assert all("20261001T053123Z" in result for result in live.values())


def test_x10_generated_documents_are_current():
    subprocess.run(
        [sys.executable, "scripts/generate_supermicro_x10_reference.py", "--check"],
        cwd=ROOT, check=True,
    )
    reference = (ROOT / "docs/supermicro-x10-command-reference.html").read_text()
    table = (ROOT / "docs/supermicro-x10-command-table.html").read_text()
    genealogy = (ROOT / "docs/supermicro-x10-x14-genealogy.html").read_text()
    assert "286</strong>Documented operations" in reference
    assert "91</strong>Executed registration rows" in table
    assert 'id="operation-expand-all"' in reference
    assert 'id="identity-expand-all"' in table
    assert "behavior-changed" in genealogy
    assert "file-oob-parent-a0" in genealogy
    assert "captured eight exact read-only named routes" in reference
    assert "zipmi oem supermicro-x10 --unsafe SD3GetSetByteByName" in reference
    assert "GetPowerConsumption_30_68_16" in reference
    assert "GetPowerConsumption_30_E2" in reference


def test_x10_public_route_names_are_unique_and_resolvable():
    from zipmi.cli.oem_cmds import _find_cmd, _vendor_listing

    listing = _vendor_listing("supermicro-x10")
    assert len({row["name"] for row in listing.values()}) == len(listing)
    assert all(_find_cmd(listing, row["name"]) == [(key, row)]
               for key, row in listing.items())


def test_x10_unbounded_targets_and_incomplete_codecs_fail_closed():
    from zipmi.scapy_ipmi.oem.supermicro_x10 import (
        SUPERMICRO_X10,
        SUPERMICRO_X10_PAYLOADS,
    )

    assert SUPERMICRO_X10[(0x30, 0x23)]["requires_unsafe"]
    assert SUPERMICRO_X10[(0x3A, 0x3E)]["requires_unsafe"]
    assert SUPERMICRO_X10_PAYLOADS[(0x30, 0xE3)][0] is None


def _args(*, unsafe: bool = False):
    return argparse.Namespace(
        cmd_name=None, data=[], unsafe=unsafe, json=False,
    )


def test_x10_cli_gates_mutating_named_routes(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli import oem_cmds

    class Session:
        def send_raw(self, netfn, command, data):
            sent.append((netfn, command, bytes(data)))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    sent = []
    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    listing = oem_cmds._vendor_listing("supermicro-x10")
    unsafe = next(row for row in listing.values() if row["requires_unsafe"])
    safe = next(
        row for row in listing.values()
        if not row["requires_unsafe"]
        and row["request_min"] == len(row.get("prefix") or b"")
    )

    args = _args()
    args.cmd_name = unsafe["name"]
    assert oem_cmds.cmd_oem_run(args, "supermicro-x10") == 2
    assert not sent
    args.cmd_name = safe["name"]
    assert oem_cmds.cmd_oem_run(args, "supermicro-x10") == 0
    assert sent


def test_x10_cli_parser_accepts_unsafe():
    from zipmi.cli.zipmi import parse_cli

    args = parse_cli(["oem", "supermicro-x10", "--unsafe", "SetOOBDebugFlag"])
    assert args.unsafe is True


def test_x10_fwdump_requires_unsafe(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli import oem_cmds

    called = []
    monkeypatch.setattr(cli, "cmd_supermicro_fwdump",
                        lambda args, output: called.append(output) or 0)
    args = _args()
    args.cmd_name = "fwdump"
    assert oem_cmds.cmd_oem_run(args, "supermicro-x10") == 2
    assert called == []

    args.unsafe = True
    assert oem_cmds.cmd_oem_run(args, "supermicro-x10") == 0
    assert called == ["flash.bin"]
