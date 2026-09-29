# z-artifact: 76dc5790-1e26-40b2-892f-480a68347061
"""X14-shipped Intel Node Manager wire contracts and named execution."""
from __future__ import annotations

import argparse
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest


def _zero_kwargs(packet_type):
    return {
        field.name: 0
        for field in packet_type.fields_desc
        if not field.name.startswith("iana")
    }


def test_intel_nm_catalog_and_fixed_codecs_are_closed():
    from zipmi.scapy_ipmi.oem.intel import (
        INTEL_COMMANDS, INTEL_NM_IANA_PREFIX, INTEL_NM_PAYLOADS,
    )

    assert len(INTEL_COMMANDS) == len(INTEL_NM_PAYLOADS) == 11
    assert {key[1] for key in INTEL_COMMANDS} == {
        0xC0, 0xC1, 0xC2, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xD0, 0xD1, 0xF2,
    }
    assert INTEL_NM_IANA_PREFIX == (0x57, 0x01, 0x00)
    assert sum(row["safety"] == "read-only" for row in INTEL_COMMANDS.values()) == 6

    for key, (request_type, response_type) in INTEL_NM_PAYLOADS.items():
        contract = INTEL_COMMANDS[key]
        request = bytes(request_type(**_zero_kwargs(request_type)))
        assert request.startswith(bytes(INTEL_NM_IANA_PREFIX))
        assert len(request) == contract["request_length"][0]
        response = bytes(response_type(**_zero_kwargs(response_type)))
        assert response[1:4] == bytes(INTEL_NM_IANA_PREFIX)
        assert len(response) == contract["response_length"][0] + 1


def test_intel_nm_codecs_pin_endianness_and_required_fields():
    from zipmi.scapy_ipmi.oem.intel import INTEL_NM_PAYLOADS

    set_policy, _ = INTEL_NM_PAYLOADS[(0x2E, 0xC1, 0x57, 0x01, 0x00)]
    raw = bytes(set_policy(
        domain_enabled=0x11, policy_id=2, trigger_config=3,
        alert_shutdown=1, limit=0x1234, correction_time=0x12345678,
        trigger_limit=0x9ABC, statistics_period=0xDEF0,
    ))
    assert raw == bytes.fromhex("57010011020301341278563412bc9af0de")
    with pytest.raises(ValueError, match="missing required fields"):
        bytes(set_policy())
    with pytest.raises(ValueError, match="constant fields changed"):
        bytes(set_policy(
            iana0=0, domain_enabled=0, policy_id=0, trigger_config=0,
            alert_shutdown=0, limit=0, correction_time=0,
            trigger_limit=0, statistics_period=0,
        ))


def test_intel_nm_lookup_and_response_decode_use_iana_route():
    import zipmi
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload

    zipmi.load_vendor("intel")
    request_type, _ = lookup_payload("intel", 0x2E, 0xD1, b"\x57\x01\x00\x80\x03")
    assert bytes(request_type(domain_component=0x80, component_id=3)) == bytes.fromhex(
        "5701008003"
    )
    decoded = decode_payload_response(
        "intel", 0x2E, 0xD1, bytes.fromhex("5701008003"), 0,
        bytes.fromhex("5701003412"),
    )
    assert decoded.completion_code == 0
    assert decoded.budget == 0x1234


def test_intel_nm_cli_prefix_bounds_and_unsafe_gate(monkeypatch, capsys):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, bytes.fromhex("5701000102030405")

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    mutating = argparse.Namespace(
        cmd_name="NM Set Power Draw Range", data=["1", "10", "0", "20", "0"],
        unsafe=False, json=False,
    )
    assert cmd_oem_run(mutating, "intel") == 2
    assert "add --unsafe" in capsys.readouterr().err

    mutating.unsafe = True
    assert cmd_oem_run(mutating, "intel") == 0
    assert sent[-1] == (0x2E, 0xCB, bytes.fromhex("570100010a001400"))

    wrong_length = argparse.Namespace(
        cmd_name="NM Get Policy", data=["1"], unsafe=False, json=False,
    )
    assert cmd_oem_run(wrong_length, "intel") == 2
    assert "requires exactly 2 data bytes after the fixed prefix" in capsys.readouterr().err

    readonly = argparse.Namespace(
        cmd_name="NM Get Version", data=[], unsafe=False, json=False,
    )
    assert cmd_oem_run(readonly, "intel") == 0
    assert sent[-1] == (0x2E, 0xCA, bytes.fromhex("570100"))

    root = Path(__file__).parents[2]
    parsed = subprocess.run(
        [sys.executable, "-m", "zipmi.cli.zipmi", "oem", "openbmc-intel",
         "--unsafe", "NM Set Power Draw Range", "help"],
        cwd=root, capture_output=True, text=True,
    )
    assert parsed.returncode == 0, parsed.stderr
    assert "0x57 0x01 0x00" in parsed.stdout
