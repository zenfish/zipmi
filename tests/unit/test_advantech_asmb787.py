"""ASMB-787 canonical catalog, corrected layout, and named raw bytes."""

from __future__ import annotations

import argparse
import csv
from contextlib import contextmanager
from pathlib import Path


def test_catalog_has_every_unique_firmware_dispatch_pair():
    from zipmi.scapy_ipmi.oem.advantech_asmb787 import ASMB787_COMMANDS

    assert len(ASMB787_COMMANDS) == 187
    assert len(set(ASMB787_COMMANDS)) == 187
    assert {netfn for netfn, _ in ASMB787_COMMANDS} == {0x30, 0x32, 0x3A}
    assert all(row["confidence"] and row["semantic_confidence"]
               for row in ASMB787_COMMANDS.values())
    assert all(row["request_semantics"] and row["response_semantics"]
               for row in ASMB787_COMMANDS.values())


def test_generated_catalog_exactly_matches_canonical_csv():
    from zipmi.scapy_ipmi.oem.advantech_asmb787 import ASMB787_COMMANDS

    source = (Path(__file__).parents[2] / "zipmi/data/sources/"
              "advantech-asmb787-oem-dispatch.csv")
    with source.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    canonical = {(int(row["netfn"], 0), int(row["cmd"], 0)): row for row in rows}
    assert len(canonical) == len(rows) == 187
    assert ASMB787_COMMANDS == canonical


def test_generated_markdown_contains_every_canonical_row():
    reference = (Path(__file__).parents[2] / "docs/"
                 "advantech_ASMB787-command-reference.md").read_text()
    rows = [line for line in reference.splitlines() if line.startswith("| `0x")]
    assert len(rows) == 187
    assert any("`0x32/0x66`" in line and "`AMIRestoreDefaults`" in line
               for line in rows)


def test_corrected_cmd_handler_layout_values():
    from zipmi.scapy_ipmi.oem.advantech_asmb787 import ASMB787_COMMANDS

    restore = ASMB787_COMMANDS[(0x32, 0x66)]
    assert (restore["privilege_raw"], restore["privilege"]) == (
        "0x04", "Administrator")
    assert (restore["request_length_raw"], restore["request_length_semantics"]) == (
        "0x00", "exactly 0 request payload bytes")
    assert ASMB787_COMMANDS[(0x32, 0x90)]["privilege"] == "Operator"
    assert ASMB787_COMMANDS[(0x32, 0xE6)]["privilege"] == "Administrator"


def test_activation_evidence_stratification():
    from zipmi.scapy_ipmi.oem.advantech_asmb787 import ASMB787_COMMANDS

    statuses = [row["activation_status"] for row in ASMB787_COMMANDS.values()]
    assert sum(s == "statically registered in owning dispatcher table" for s in statuses) == 92
    assert sum("explicitly enabled" in s for s in statuses) == 85
    unproved = {key for key, row in ASMB787_COMMANDS.items()
                if "absent from extracted" in row["activation_status"]}
    assert unproved == {
        (0x32, 0xC0), (0x32, 0xC1), (0x32, 0xCA), (0x32, 0xCB),
        (0x32, 0xD5), (0x32, 0xD6), (0x32, 0xD7), (0x32, 0xD8),
        (0x32, 0xD9), (0x32, 0xDC),
    }


def test_cli_does_not_upgrade_plugin_eligibility_to_registration():
    from zipmi.cli.oem_cmds import _vendor_listing

    listing = _vendor_listing("advantech-asmb787")
    assert "statically registered" in listing[(0x32, 0x66)]["desc"]
    assert "feature enabled; runtime registration unproved" in listing[(0x32, 0x11)]["desc"]
    assert "feature absent; runtime registration unproved" in listing[(0x32, 0xC0)]["desc"]


def test_named_resolution_emits_exact_netfn_cmd_bytes():
    from zipmi.cli.oem_cmds import _find_cmd, _vendor_listing

    listing = _vendor_listing("advantech-asmb787")
    cases = {
        "ControlMEUpdate": b"\x30\x01",
        "AMIRestoreDefaults": b"\x32\x66",
        "PDK_SDRGetNominalReading": b"\x3a\x01",
    }
    for name, expected in cases.items():
        hits = _find_cmd(listing, name)
        assert len(hits) == 1
        assert bytes(hits[0][0][:2]) == expected


def test_named_restore_requires_explicit_unsafe_acknowledgement(capsys):
    from zipmi.cli.oem_cmds import cmd_oem_run

    args = argparse.Namespace(cmd_name="AMIRestoreDefaults", data=[], unsafe=False)
    assert cmd_oem_run(args, "advantech-asmb787") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_sibling_header_schema_still_requires_unsafe_acknowledgement(capsys):
    from zipmi.cli.oem_cmds import _vendor_listing, cmd_oem_run

    listing = _vendor_listing("advantech-asmb787")
    row = next(row for row in listing.values()
               if row["tier"] == "safe"
               and row["semantic_confidence"].startswith("medium"))
    data = ["0"] * int(row["req_len_raw"], 0)
    args = argparse.Namespace(cmd_name=row["name"], data=data, unsafe=False)
    assert cmd_oem_run(args, "advantech-asmb787") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_named_raw_rejects_out_of_range_bytes(capsys):
    from zipmi.cli.oem_cmds import cmd_oem_run

    args = argparse.Namespace(cmd_name="ControlMEUpdate", data=["256", "0"], unsafe=True)
    assert cmd_oem_run(args, "advantech-asmb787") == 2
    assert "between 0 and 255" in capsys.readouterr().err


def test_fixed_dispatcher_request_length_is_enforced(capsys):
    from zipmi.cli.oem_cmds import cmd_oem_run

    args = argparse.Namespace(cmd_name="ControlMEUpdate", data=["0x01"], unsafe=True)
    assert cmd_oem_run(args, "advantech-asmb787") == 2
    assert "requires exactly 2 payload bytes" in capsys.readouterr().err


def test_unsafe_named_restore_emits_exact_empty_request(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, data))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    args = argparse.Namespace(
        cmd_name="AMIRestoreDefaults", data=[], unsafe=True, json=False,
    )
    assert cmd_oem_run(args, "advantech-asmb787") == 0
    assert sent == [(0x32, 0x66, b"")]


def test_help_prints_valid_oem_invocation(capsys):
    from zipmi.cli.oem_cmds import _cmd_oem_help

    assert _cmd_oem_help("advantech-asmb787", "AMIRestoreDefaults") == 0
    output = capsys.readouterr().out
    assert "oem advantech-asmb787 --unsafe AMIRestoreDefaults" in output


def test_cli_parser_accepts_documented_unsafe_invocation():
    from zipmi.cli.zipmi import parse_cli

    args = parse_cli([
        "oem", "advantech-asmb787", "--unsafe", "AMIRestoreDefaults",
    ])
    assert args.unsafe is True
    assert args.cmd_name == "AMIRestoreDefaults"


def test_advantech_alias_and_iana_registration():
    import zipmi
    from zipmi.scapy_ipmi.oem._registry import ENTERPRISE_IDS, OEM_CMD_NAMES

    zipmi.load_vendor("asmb787")
    assert ENTERPRISE_IDS[10297] == "advantech-asmb787"
    assert OEM_CMD_NAMES[(0x32, 0x66)] == "AMIRestoreDefaults"


def test_yafu_does_not_claim_universal_privilege():
    from zipmi.scapy_ipmi.oem.yafu import YAFU_COMMANDS

    assert {entry["priv"] for entry in YAFU_COMMANDS.values()} == {None}
