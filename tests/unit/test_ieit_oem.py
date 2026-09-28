# z-artifact: 4bf04105-b3f4-4aeb-99c7-c310c36dcea4
"""Closure checks for the firmware-bound IEIT NF5468M6 OEM catalog."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
DISPATCH = ROOT / "zipmi/data/sources/ieit-nf5468m6-dispatch.json"
PDK = ROOT / "zipmi/data/sources/ieit-nf5468m6-pdk-contracts.json"
AMI = ROOT / "zipmi/data/sources/ieit-nf5468m6-ami-netfn32-contracts.json"


def test_ieit_dispatch_denominator_and_collision_are_preserved() -> None:
    catalog = json.loads(DISPATCH.read_text())
    rows = catalog["rows"]

    assert catalog["registration_rows"] == len(rows) == 324
    assert catalog["unique_addresses"] == len({
        (row["netfn"], row["cmd"]) for row in rows
    }) == 323
    assert catalog["collisions"] == {
        "0x30/0xe2": ["CommerMEOEMGetReading", "PnmOemGetReading"],
    }
    assert Counter(row["provider"].split(":", 1)[0] for row in rows) == {
        "ami-core": 86,
        "ami-plugin": 97,
        "ieit-pdk": 137,
        "intel-pnm": 3,
        "ami-hpm-oem": 1,
    }
    subprocess.run(
        [sys.executable, "scripts/generate_ieit_nf5468m6_reference.py", "--check"],
        cwd=ROOT, check=True,
    )
    reference = (ROOT / "docs/ieit-nf5468m6-command-reference.html").read_text()
    table = (ROOT / "docs/ieit-nf5468m6-command-table.html").read_text()
    from zipmi.scapy_ipmi.oem.ieit import IEIT_COMMANDS
    assert reference.count('<tr data-search="') == len(IEIT_COMMANDS)
    assert table.count('<tr data-search="') == len(IEIT_COMMANDS)
    assert "324</strong>Firmware registration rows" in table
    assert "323</strong>Unique NetFn/Cmd addresses" in table
    assert "250ccbd0943a4a5d07f679c99254fb7677b91efb526530df609aab995a27c2ab" in reference


def test_ieit_target_is_separate_from_openbmc_inspur() -> None:
    import zipmi
    from zipmi.cli.oem_cmds import VENDORS, _find_cmd, _vendor_listing, _vendor_stats
    from zipmi.scapy_ipmi.oem.ieit import (
        IEIT_COMMANDS,
        IEIT_CMD_NAMES,
        IEIT_REGISTRATIONS,
    )

    zipmi.load_vendor("ieit")
    listing = _vendor_listing("ieit")
    assert len(IEIT_REGISTRATIONS) == 324
    assert len(IEIT_COMMANDS) == len(listing)
    assert len(IEIT_CMD_NAMES) == sum(
        all(byte <= 0xff for byte in key) for key in IEIT_COMMANDS
    )
    assert _vendor_stats("ieit") == (len(listing), len(listing))
    assert len({contract["name"] for contract in IEIT_COMMANDS.values()}) == len(IEIT_COMMANDS)
    assert len(_find_cmd(listing, IEIT_COMMANDS[(0x32, 0x16, 0x00)]["name"])) == 1
    assert "ieit" in VENDORS and VENDORS["ieit"].get("cmd_names") is None
    assert "CommerMEOEMGetReading / PnmOemGetReading" in IEIT_CMD_NAMES[(0x30, 0xE2)]
    assert IEIT_CMD_NAMES[(0x3C, 0x7A)] == "IEIT CommerGetSetBIOSPassword"


def test_ieit_pdk_operation_and_selector_closure() -> None:
    source = json.loads(PDK.read_text())
    operations = [
        operation
        for registration in source["registrations"]
        for operation in registration["operations"]
    ]
    referenced = [
        leaf
        for operation in operations
        for leaf in operation["selector_leaf_ids"] + operation["validation_leaf_ids"]
    ]

    assert source["coverage"]["registrations"] == len(source["registrations"]) == 129
    assert source["coverage"]["normalized_operations"] == len(operations) == 282
    assert len(referenced) == len(set(referenced)) == 277
    assert sum("auto_prefix" in operation for operation in operations) == 177
    assert sum(operation.get("selector_offset") == 28 for operation in operations) == 4


def test_ieit_ami_netfn32_operation_closure() -> None:
    source = json.loads(AMI.read_text())
    operations = [
        operation
        for registration in source["registrations"]
        for operation in registration["normalized_operations"]
    ]

    assert source["counts"]["registrations"] == len(source["registrations"]) == 183
    assert source["counts"]["normalized_operations"] == len(operations) == 470
    assert len({operation["operation_id"] for operation in operations}) == 470
    assert sum(operation["auto_prefix"] is not None for operation in operations) == 287
    assert sum(
        operation["selector_hex"] is not None and operation["auto_prefix"] is None
        for operation in operations
    ) == 28


def test_ieit_named_routes_fail_closed(monkeypatch, capsys) -> None:
    from zipmi.cli.oem_cmds import cmd_oem_run
    from zipmi.cli.zipmi import parse_cli

    parsed = parse_cli(["oem", "ieit", "--unsafe", "OemGetflashstatus"])
    assert parsed.unsafe is True

    def unexpected_session(_args):
        pytest.fail("invalid or unacknowledged IEIT requests must fail before transport")

    monkeypatch.setattr("zipmi.cli.zipmi._open_session", unexpected_session)
    blocked = type("Args", (), {
        "cmd_name": "CommerGetChassisIdentify", "data": [],
        "unsafe": False, "json": False,
    })()
    assert cmd_oem_run(blocked, "ieit") == 2
    assert "add --unsafe" in capsys.readouterr().err

    wrong_length = type("Args", (), {
        "cmd_name": "OemGetflashstatus", "data": ["0"], "unsafe": True, "json": False,
    })()
    assert cmd_oem_run(wrong_length, "ieit") == 2
    assert "requires exactly 0 payload bytes" in capsys.readouterr().err

    caller_selector = type("Args", (), {
        "cmd_name": "Remote update selector x01", "data": ["0"] * 30,
        "unsafe": True, "json": False,
    })()
    assert cmd_oem_run(caller_selector, "ieit") == 2
    assert "requires selector 01 at payload offset 28" in capsys.readouterr().err

    smtp_selector = type("Args", (), {
        "cmd_name": "SetSMTPConfigParams.smtp_enable", "data": ["1"] * 5,
        "unsafe": True, "json": False,
    })()
    assert cmd_oem_run(smtp_selector, "ieit") == 2
    assert "requires selector 00 at payload offset 1" in capsys.readouterr().err

    pnm_reading = type("Args", (), {
        "cmd_name": "Intel PNM OEM Get Reading", "data": ["0"] * 4,
        "unsafe": True, "json": False,
    })()
    assert cmd_oem_run(pnm_reading, "ieit") == 2
    assert "violates its recovered field constraints" in capsys.readouterr().err

    pnm_state = type("Args", (), {
        "cmd_name": "Intel PNM OEM ME Power State Change", "data": ["1"],
        "unsafe": True, "json": False,
    })()
    assert cmd_oem_run(pnm_state, "ieit") == 2
    assert "violates its recovered field constraints" in capsys.readouterr().err

def test_ieit_bios_and_switch_selector_routes_are_bounded(monkeypatch, capsys) -> None:
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run
    from zipmi.scapy_ipmi.oem.ieit import IEIT_COMMANDS

    writes = [
        key for key in IEIT_COMMANDS
        if key[:2] == (0x38, 0x12) and len(key) == 5
    ]
    reads = [
        key for key in IEIT_COMMANDS
        if key[:2] == (0x38, 0x11) and len(key) == 4 and key[-1] != 0xFF
    ]
    assert len(writes) == 88
    assert len(reads) == 31
    assert IEIT_COMMANDS[(0x38, 0x12, 0, 0, 1)]["name"] == (
        "Set BIOS Processor0Ht = Enabled"
    )

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, b"\x01"

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    read = Namespace(cmd_name="Read BIOS Processor0Ht", data=[], unsafe=False, json=False)
    assert cmd_oem_run(read, "ieit") == 0
    assert sent == [(0x38, 0x11, b"\x00\x00")]

    write = Namespace(
        cmd_name="Set BIOS Processor0Ht = Enabled", data=[], unsafe=False, json=False,
    )
    assert cmd_oem_run(write, "ieit") == 2
    assert "add --unsafe" in capsys.readouterr().err
    write.unsafe = True
    assert cmd_oem_run(write, "ieit") == 0
    assert sent[-1] == (0x38, 0x12, b"\x00\x00\x01")

    switch = Namespace(
        cmd_name="Disable PCIe/I2C scans", data=[], unsafe=True, json=False,
    )
    assert cmd_oem_run(switch, "ieit") == 0
    assert sent[-1] == (0x34, 0x1A, b"\x09")
