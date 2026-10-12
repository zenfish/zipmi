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
    assert "handler semantics were not reviewed" in capsys.readouterr().err


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
    assert reference.count('<tr data-search="') == 4
    assert table.count('<tr data-search="') == 143
    assert "AMIYAFUStateless wins; AMIOemSetRedisDB is shadowed" in reference
    assert "loser to built-in AMIYAFUStateless" in table
    assert "143 registrations / 142 unique addresses / 141 effective commands" in reference
    assert "141</strong>Effective commands" in reference
    assert "141</strong>Effective commands" in table
    assert "CC 0xc7" in reference and "CC 0xff" in reference
