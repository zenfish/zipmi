# z-artifact: 759a3cab-a685-4bae-93d4-136671843a93
"""Firmware-bound iRMC S6 dispatch-table invariants."""
from collections import Counter
from hashlib import sha256
from importlib.resources import files
from argparse import Namespace
from pathlib import Path
import re
import subprocess
import sys

from zipmi.cli.oem_cmds import _cmd_oem_help, _vendor_listing, cmd_oem_run
from zipmi.scapy_ipmi.oem.fujitsu import (
    FUJITSU_CMD_NAMES, FUJITSU_OPERATION_NAMES, FUJITSU_OPERATIONS, FUJITSU_RECORDS,
    FUJITSU_SELECTOR_PAYLOADS, FUJITSU_TOP_LEVEL,
)
from zipmi.scapy_ipmi.oem._registry import lookup_payload


def test_generated_irmc_reference_uses_shared_standard() -> None:
    root = Path(__file__).parents[2]
    subprocess.run(
        [sys.executable, "scripts/generate_fujitsu_irmc_reference.py", "--check"],
        cwd=root, check=True,
    )
    reference = (root / "docs/fujitsu-irmc-s6-command-reference.html").read_text()

    assert '<link rel="stylesheet" href="assets/oem-command-reference.css">' in reference
    assert "135</strong>Unique NetFn/Cmd addresses" in reference
    assert "355</strong>Documented operations" in reference
    assert ("22 / 331 / 2</strong>Named operation route: default / --unsafe / "
            "no distinct route" in reference)
    assert "22</strong>Operations with captured live requests" in reference
    assert reference.count('<tr data-search="') == 355
    assert '<summary>Recovered from</summary>' in reference
    assert Counter(re.findall(r'data-execution="([^"]+)"', reference)) == {
        "Allowed by default": 22,
        "Requires --unsafe": 331,
        "No distinct named route": 2,
    }
    assert Counter(re.findall(r'data-live="([^"]+)"', reference)) == {
        "false": 333, "true": 22,
    }
    assert Counter(re.findall(r'data-request="([^"]+)"', reference)) == {
        "Partial": 296, "Unknown": 37, "Complete": 22,
    }
    assert Counter(re.findall(r'data-response="([^"]+)"', reference)) == {
        "Partial": 296, "Unknown": 55, "Complete": 4,
    }
    assert Counter(re.findall(r'data-safety="([^"]+)"', reference)) == {
        "read-only": 116, "state-changing": 105, "unknown": 102,
        "sensitive": 14, "disruptive": 7, "destructive": 11,
    }

    assert "148 registration records, 138 LUN-aware identities" in reference
    assert "F5/A4&#x27;s 40 inner selectors" in reference
    assert "E0/04&#x27;s 50 maintenance subcommands" in reference
    assert "92 backup/restore parameter records" in reference
    assert "35839f7ab40993898666425d50e18654d68791c7dfe3bb5a3c3496e4daa23804" in reference
    assert "6c25538d508e398135855d59550148b3fd93cdcc045bc9556e4f79c335f72dfa" in reference
    assert "20260926T200725Z-7ecec0c7-f88e-4945-b3b2-2fe97bcb9e3a" in reference
    assert "zipmi oem fujitsu &#x27;iRMC_Get last power-on reason_01_15&#x27;" in reference
    assert "zipmi oem fujitsu --unsafe OEMFTSChassisControl &lt;1 payload bytes&gt;" in reference
    assert "Not available through zipmi over LAN" in reference
    assert "parent handler OEMFTSBiosCmds" in reference
    assert "destructive reset of memory PDA data" in reference
    assert "performs I2C write/read" in reference
    assert 'id="operation-scrollbar"' in reference
    assert "document.createTreeWalker" in reference
    assert "Top-level dispatch names" not in reference
    assert "Selector and group operations" not in reference


def test_pinned_irmc_s6_dispatch_table() -> None:
    source = files("zipmi").joinpath(
        "data/sources/fujitsu-irmc-s6-command-tables.tsv"
    )
    assert sha256(source.read_bytes()).hexdigest() == (
        "6c25538d508e398135855d59550148b3fd93cdcc045bc9556e4f79c335f72dfa"
    )
    assert len(FUJITSU_RECORDS) == 148
    assert len({(r.netfn, r.cmd) for r in FUJITSU_RECORDS}) == 135
    assert len({(r.netfn, r.cmd, r.lun) for r in FUJITSU_RECORDS}) == 138
    assert Counter(r.netfn for r in FUJITSU_RECORDS) == {
        0x00: 3, 0x04: 1, 0x06: 7, 0x0A: 10, 0x0C: 1,
        0x2C: 2, 0x2E: 20, 0x30: 58, 0x34: 46,
    }
    assert sum(r.lun == 3 for r in FUJITSU_RECORDS) == 3
    assert len(FUJITSU_CMD_NAMES) == 135
    assert len(FUJITSU_OPERATIONS) == len(FUJITSU_OPERATION_NAMES) == 232
    assert len(FUJITSU_TOP_LEVEL) == 128
    assert len({op.name for op in FUJITSU_OPERATIONS}) == 232
    assert sum(not op.requires_unsafe for op in FUJITSU_OPERATIONS) == 22
    assert sum(not op.runnable for op in FUJITSU_OPERATIONS) == 2


def test_irmc_named_execution_is_fail_closed_without_wire_contract(capsys) -> None:
    listing = _vendor_listing("fujitsu")
    assert len(listing) == 367
    assert listing[(0x2E, 0x01, 0x80, 0x28, 0x00, 0x15)]["requires_unsafe"] is False
    nvram = listing[(0x2E, 0xE0, 0x80, 0x28, 0x00, 0x04)]
    assert nvram["requires_unsafe"] is True
    assert "IDPROM" in nvram["security"]
    assert "page_size" in listing[(0x34, 0x46)]["request"].lower()
    assert "host power" in listing[(0x00, 0x02)]["security"].lower()
    assert listing[(0x2E, 0xF1)]["runnable"] is False
    assert listing[(0x2C, 0x02, 0x52, 0xA5)]["runnable"] is False
    assert "any other selector" in listing[(0x2C, 0x02, 0x52, 0xA5)]["request"]
    assert _cmd_oem_help("fujitsu", listing[(0x2C, 0x02, 0x52, 0xA5)]["name"]) == 0
    help_text = capsys.readouterr().out
    assert "not runnable over LAN" in help_text
    assert " raw " not in help_text
    assert cmd_oem_run(Namespace(cmd_name=listing[(0x2E, 0xF1)]["name"], data=[], unsafe=True), "fujitsu") == 2
    assert "no supported LAN execution contract" in capsys.readouterr().err
    assert cmd_oem_run(Namespace(cmd_name=listing[(0x34, 0x39)]["name"], data=[], unsafe=False), "fujitsu") == 2
    assert "add --unsafe" in capsys.readouterr().err
    safe_f1 = listing[(0x2E, 0xF1, 0x80, 0x28, 0, 0x21)]["name"]
    assert cmd_oem_run(Namespace(cmd_name=safe_f1, data=["0x00"], unsafe=False), "fujitsu") == 2
    assert "requires exactly 4 payload bytes" in capsys.readouterr().err


def test_irmc_safe_power_read_codecs() -> None:
    assert len(FUJITSU_SELECTOR_PAYLOADS) == 22
    for operation in FUJITSU_OPERATIONS:
        if operation.exact_safe_length == 4:
            pair = lookup_payload("fujitsu", operation.netfn, operation.cmd,
                                  operation.prefix)
            assert pair is not None
            assert bytes(pair[0]()) == operation.prefix
    for selector, response_hex, value_field in (
        (0x15, "008028000100", "reason"),
        (0x16, "008028000100", "reason"),
        (0x18, "008028000400000000", "runtime_power_field"),
        (0x1D, "008028000100", "inhibit"),
    ):
        pair = lookup_payload("fujitsu", 0x2E, 0x01,
                              bytes([0x80, 0x28, 0, selector]))
        assert pair is not None
        request, response = pair
        assert bytes(request()) == bytes([0x80, 0x28, 0, selector])
        decoded = response(bytes.fromhex(response_hex))
        assert decoded.completion_code == 0
        assert getattr(decoded, value_field) == 0
