"""ASMB-787 canonical catalog, corrected layout, and named raw bytes."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path

import pytest


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


def test_sibling_header_context_preserves_all_dispatch_rows():
    source = (Path(__file__).parents[2] / "zipmi/data/sources/"
              "advantech-asmb787-header-contracts.csv")
    with source.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 187
    coverage = {
        "full": sum(not row["unresolved"] for row in rows),
        "partial": sum(bool(row["unresolved"])
                       and bool(row["request_type"] or row["response_type"])
                       for row in rows),
        "none": sum(not row["request_type"] and not row["response_type"]
                    for row in rows),
    }
    assert coverage == {"full": 153, "partial": 6, "none": 28}
    assert {row["source_artifact_uuid"] for row in rows} == {
        "a726253a-edfa-5f2e-baa0-4c1d31af48ab"}


def test_generated_markdown_contains_every_canonical_row():
    reference = (Path(__file__).parents[2] / "docs/"
                 "advantech_ASMB787-command-reference.md").read_text()
    rows = [line for line in reference.splitlines() if line.startswith("| `0x")]
    assert len(rows) == 187
    assert any("`0x32/0x66`" in line and "`AMIRestoreDefaults`" in line
               for line in rows)


def test_generated_html_contains_every_exact_operation():
    reference = (Path(__file__).parents[2] / "docs/"
                 "advantech_ASMB787-command-reference.html").read_text()
    assert reference.count("<td class='p-2 font-mono'>0x") == 462 + 187
    assert "462 operations across 187 command pairs" in reference
    assert "structured fixed-width codecs for 81 operations" in reference
    assert "462</strong><div>handler-proven operations" in reference
    assert "381 remain raw-exact" in reference
    assert "33</strong><div>live-backed operations" in reference
    assert "31 destructive operations" in reference
    assert "55 security-sensitive operations" in reference
    assert "157 mutates operations" in reference
    assert 'id="operation-filter"' in reference
    assert 'id="effect-filter"' in reference
    assert 'id="dispatch-filter"' in reference
    assert 'id="dispatch-effect-filter"' in reference
    assert "byte 0</code> · <code>mode</code>: u8" in reference
    assert "<strong>Does:</strong> Writes ptpd configuration" in reference
    assert "Queries AMI YAFU Get Flash Info; response layout:" in reference
    assert "20260926T031044Z-cc48e36e-4cc4-4f24-8052-6baa12c24fa2" in reference

    class TableRows(HTMLParser):
        def __init__(self):
            super().__init__()
            self.section = None
            self.current = None
            self.rows = {"operation-rows": [], "dispatch-rows": []}

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "tbody" and attrs.get("id") in self.rows:
                self.section = attrs["id"]
            elif self.section and tag == "tr":
                self.current = {"cells": 0, **attrs}
            elif self.current is not None and tag in {"td", "th"}:
                self.current["cells"] += 1

        def handle_endtag(self, tag):
            if tag == "tr" and self.current is not None:
                self.rows[self.section].append(self.current)
                self.current = None
            elif tag == "tbody":
                self.section = None

    parser = TableRows()
    parser.feed(reference)
    operations = parser.rows["operation-rows"]
    dispatch = parser.rows["dispatch-rows"]
    assert len(operations) == 462 and {row["cells"] for row in operations} == {6}
    assert Counter(row["data-effect"] for row in operations) == {
        "safe": 219, "mutates": 157, "security-sensitive": 55, "destructive": 31}
    assert len(dispatch) == 187 and {row["cells"] for row in dispatch} == {9}
    assert all(row.get("data-search") and row.get("data-effect") for row in dispatch)


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
    assert sum(s.startswith("runtime registered:") for s in statuses) == 93
    skipped = {key for key, row in ASMB787_COMMANDS.items()
               if row["activation_status"].startswith("not runtime registered:")}
    assert skipped == {(0x32, 0xD5), (0x32, 0xD6)}


def test_cli_reports_proven_plugin_registration():
    from zipmi.cli.oem_cmds import _vendor_listing

    listing = _vendor_listing("advantech-asmb787")
    assert "statically registered" in listing[(0x32, 0x66)]["desc"]
    assert "runtime registered" in listing[(0x32, 0x11)]["desc"]
    assert "runtime registered" in listing[(0x32, 0xC0)]["desc"]
    assert "not runtime registered" in listing[(0x32, 0xD6)]["desc"]


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


def test_variable_length_safe_command_still_requires_unsafe_acknowledgement(capsys):
    from zipmi.cli.oem_cmds import _vendor_listing, cmd_oem_run

    listing = _vendor_listing("advantech-asmb787")
    row = next(row for row in listing.values()
               if row["tier"] == "safe"
               and row["semantic_confidence"] == "target-proven"
               and row["req_len_raw"] == "0xff"
               and row["prefix"] is None)
    args = argparse.Namespace(cmd_name=row["name"], data=[], unsafe=False)
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


def test_safe_exact_operation_emits_full_proven_prefix_without_unsafe(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, data))
            return 0, b"\x00"

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    args = argparse.Namespace(
        cmd_name="ControlMEUpdate.query", data=[], unsafe=False, json=False,
    )
    assert cmd_oem_run(args, "advantech-asmb787") == 0
    assert sent == [(0x30, 0x01, b"\x30\x02")]


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


def test_exact_operation_contracts_and_codecs_are_generated():
    import zipmi
    zipmi.load_vendor("advantech-asmb787")
    from zipmi.scapy_ipmi.oem.advantech_asmb787 import (
        ASMB787_COMMANDS, ASMB787_OPERATIONS, ASMB787_PAYLOADS,
    )

    assert len(ASMB787_OPERATIONS) == 462
    assert {tuple(row["command"]) for row in ASMB787_OPERATIONS} == set(ASMB787_COMMANDS)
    assert sum(row["codec_state"] == "verified" for row in ASMB787_OPERATIONS) == 81
    assert len(ASMB787_PAYLOADS) == 81
    assert all(row["codec_state"] == "raw-exact" for row in ASMB787_OPERATIONS
               if row["id"].startswith("AMISetNTPCfg."))
    assert (0x32, 0xA8) not in ASMB787_PAYLOADS
    fw_version = next(row for row in ASMB787_OPERATIONS if row["id"] == "AMIGetFwVersion")
    assert fw_version["evidence"]["module_sha256"].startswith("1bee4dbf")
    assert fw_version["evidence"]["dispatch_module_sha256"].startswith("23e5b17b")
    live_safe_codecs = [row for row in ASMB787_OPERATIONS
                        if row["effect"] == "safe" and row["codec_state"] == "verified"]
    assert len(live_safe_codecs) == 32
    assert all(row.get("live_evidence", {}).get("request_data_hex") is not None
               for row in live_safe_codecs)
    by_id = {row["id"]: row for row in ASMB787_OPERATIONS}
    assert all(by_id[name]["effect"] == "security-sensitive" for name in (
        "AMIYAFUReadFlash", "AMIYAFUVerifyFlash", "AMIYAFUReadMemory",
        "AMIYAFUCompareMemory", "AMIGetRadiusConf.secret",
        "GetSMTPConfigParams.password", "GetSMTPConfigParams.password2",
        "AMIGetSSLCertStatus.private_key_info",
    ))
    assert "reads arbitrary BMC memory" in by_id["AMIYAFUReadMemory"]["side_effects"]
    assert "RADIUS shared secret" in by_id["AMIGetRadiusConf.secret"]["side_effects"]
    assert ASMB787_COMMANDS[(0x32, 0x22)]["safety_tier"] == "security-sensitive"
    assert ASMB787_COMMANDS[(0x32, 0x79)]["safety_tier"] == "security-sensitive"
    assert ASMB787_COMMANDS[(0x32, 0xC3)]["safety_tier"] == "security-sensitive"

    req_type, resp_type = ASMB787_PAYLOADS[(0x32, 0x18, 0x00)]
    assert bytes(req_type()) == b"\x00"
    response = resp_type(b"\x00\x03")
    assert (response.completion_code, response.retry_count) == (0, 3)

    for operation in ASMB787_OPERATIONS:
        if operation["codec_state"] != "verified":
            continue
        key = tuple(operation["command"] + (operation.get("prefix") or []))
        request_type, response_type = ASMB787_PAYLOADS[key]
        values = {}
        for field in operation["request"]["fields"]:
            if "constant" in field:
                continue
            values[field["name"]] = (
                b"\0" * field["length"] if field["kind"] == "bytes" else 0)
        assert len(bytes(request_type(**values))) == int(operation["request"]["length"])
        response_length = int(operation["response"]["length_including_cc"])
        assert isinstance(response_type(b"\0" * response_length), response_type)


def test_mutating_codec_requires_fields_and_preserves_constants():
    import zipmi
    zipmi.load_vendor("advantech-asmb787")
    from zipmi.scapy_ipmi.oem.advantech_asmb787 import ASMB787_PAYLOADS

    req_type, _ = ASMB787_PAYLOADS[(0x32, 0x37)]
    with pytest.raises(ValueError, match="missing required fields"):
        bytes(req_type())
    packet = req_type(mode=1, transport=1, delay_mechanism=0,
                      two_step=1, domain=b"\0" * 6)
    assert bytes(packet) == b"\x01\x01\x00\x01" + b"\0" * 6

    selected_type, _ = ASMB787_PAYLOADS[(0x32, 0x18, 0x00)]
    with pytest.raises(ValueError, match="constant fields changed"):
        bytes(selected_type(selector=1))


def test_oem_error_response_decode_tolerates_truncation():
    import zipmi
    zipmi.load_vendor("advantech-asmb787")
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response

    response = decode_payload_response(
        "advantech-asmb787", 0x32, 0x36, b"", 0xC1, b"",
    )
    assert response is not None
    assert response.completion_code == 0xC1


def test_yafu_does_not_claim_universal_privilege():
    from zipmi.scapy_ipmi.oem.yafu import YAFU_COMMANDS

    assert {entry["priv"] for entry in YAFU_COMMANDS.values()} == {None}
