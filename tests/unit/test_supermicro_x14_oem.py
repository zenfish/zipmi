# z-artifact: 887d7b39-b81c-41ca-a794-bbc746bda8ac
"""Firmware-bound Supermicro X14 contract, codec, and CLI closure tests."""

from __future__ import annotations

import argparse
from contextlib import contextmanager


def _registration_identity(row: dict) -> tuple:
    netfn = int(row["netfn"], 0) if isinstance(row["netfn"], str) else row["netfn"]
    command = int(row["command"], 0) if isinstance(row["command"], str) else row["command"]
    if row.get("classification") == "group":
        return netfn, command, int(row["group_id"], 0)
    if row.get("classification") == "oem_iana_0x000157":
        return netfn, command, 0x157
    return netfn, command


def test_x14_registration_and_operation_denominators_are_closed():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import (
        SUPERMICRO_X14,
        X14_CATALOG,
        X14_REGISTRATIONS,
    )

    identities = {_registration_identity(row) for row in X14_REGISTRATIONS}
    assert len(X14_REGISTRATIONS) == 116
    assert len(identities) == 115
    assert len(X14_CATALOG["primary"]["registrations"]) == 68
    assert len(X14_CATALOG["primary"]["operations"]) == 150
    assert X14_CATALOG["primary"]["unresolved_boundaries"] == []
    assert len(SUPERMICRO_X14) == 213
    assert sum(key[:2] == (0x30, 0x68) for key in SUPERMICRO_X14) == 78
    assert sum(key[:2] == (0x30, 0x51) for key in SUPERMICRO_X14) == 38
    assert sum(key[:2] == (0x30, 0x70) for key in SUPERMICRO_X14) == 3
    assert sum(key[:2] == (0x30, 0xAD) for key in SUPERMICRO_X14) == 4
    assert sum(key[:2] == (0x30, 0xA0) for key in SUPERMICRO_X14) == 27


def test_x14_group_routes_preserve_real_identity_and_interface_limits():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    fingerprint = SUPERMICRO_X14[(0x2C, 0x01, 0x52)]
    bootstrap = SUPERMICRO_X14[(0x2C, 0x02, 0x52)]
    assert fingerprint["handler"] == "GetMgrCertFingerprint"
    assert fingerprint["request_length"] == (2, 2)
    assert fingerprint["response_length"] == (33, 33)
    assert not fingerprint["runnable"]
    assert bootstrap["handler"] == "GetBootstrapAccountCredentials"
    assert bootstrap["safety"] == "sensitive"
    assert not bootstrap["runnable"]
    assert {(0x2C, 0x03, 0x52, action) for action in range(4, 13)} <= set(SUPERMICRO_X14)
    assert {(0x2C, 0x01, 0xDC, selector) for selector in range(1, 7)} <= set(SUPERMICRO_X14)


def test_x14_fixed_selector_codec_matches_wire_contract():
    import zipmi
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload

    zipmi.load_vendor("supermicro-x14")
    request, _response = lookup_payload("supermicro-x14", 0x30, 0x68, b"\x02")
    assert bytes(request()) == b"\x02"
    decoded = decode_payload_response("supermicro-x14", 0x30, 0x68, b"\x02", 0, b"\x01")
    assert decoded.completion_code == 0
    assert decoded.response0 == 1


def test_x14_cli_gates_mutation_host_only_and_asset_tag_bounds(monkeypatch, capsys):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, b"\x01"

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)

    safe = argparse.Namespace(cmd_name="I2CAccessCheck", data=[], unsafe=False, json=False)
    assert cmd_oem_run(safe, "supermicro-x14") == 0
    assert sent == [(0x30, 0x68, b"\x02")]

    mutating = argparse.Namespace(cmd_name="ClearChassisIntrusion", data=[], unsafe=False, json=False)
    assert cmd_oem_run(mutating, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err

    host_only = argparse.Namespace(
        cmd_name="Get Manager Certificate Fingerprint", data=["1"], unsafe=True, json=False,
    )
    assert cmd_oem_run(host_only, "supermicro-x14") == 2
    assert "no supported LAN execution contract" in capsys.readouterr().err

    bad_asset = argparse.Namespace(
        cmd_name="Set Asset Tag", data=["0", "2", "0x41"], unsafe=True, json=False,
    )
    assert cmd_oem_run(bad_asset, "supermicro-x14") == 2
    assert "asset-tag bounds" in capsys.readouterr().err

    good_asset = argparse.Namespace(
        cmd_name="Set Asset Tag", data=["0", "2", "0x41", "0x42"], unsafe=True, json=False,
    )
    assert cmd_oem_run(good_asset, "supermicro-x14") == 0
    assert sent[-1] == (0x2C, 0x08, b"\xdc\x00\x02AB")
