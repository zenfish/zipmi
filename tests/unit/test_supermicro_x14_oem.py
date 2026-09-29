# z-artifact: 887d7b39-b81c-41ca-a794-bbc746bda8ac
"""Firmware-bound Supermicro X14 contract, codec, and CLI closure tests."""

from __future__ import annotations

import argparse
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
    assert len(SUPERMICRO_X14) == 233
    assert sum(key[:2] == (0x30, 0x68) for key in SUPERMICRO_X14) == 78
    assert sum(key[:2] == (0x30, 0x51) for key in SUPERMICRO_X14) == 60
    assert sum(key[:2] == (0x30, 0x70) for key in SUPERMICRO_X14) == 3
    assert sum(key[:2] == (0x30, 0xAD) for key in SUPERMICRO_X14) == 4
    assert sum(key[:2] == (0x30, 0xA0) for key in SUPERMICRO_X14) == 27


def test_x14_generated_references_are_closed_and_current():
    subprocess.run(
        [sys.executable, "scripts/generate_supermicro_x14_reference.py", "--check"],
        cwd=ROOT, check=True,
    )
    reference = (ROOT / "docs/supermicro-x14-command-reference.html").read_text()
    table = (ROOT / "docs/supermicro-x14-command-table.html").read_text()

    assert reference.count('<tr data-search="') == 244
    assert table.count('<tr data-search="') == 116
    assert "65</strong>Unique NetFn/Cmd addresses" in reference
    assert "244</strong>Documented operations" in reference
    assert "187 / 57 / 0 / 0</strong>Request layout:" in reference
    assert "180 / 64 / 0 / 0</strong>Response layout:" in reference
    assert "116</strong>Executed registration rows" in table
    assert "115</strong>Unique wire identities" in table
    assert "66</strong>OEM/group identities" in table
    assert "150</strong>Hidden primary selector operations" in table
    assert 'id="operation-expand-all"' in reference
    assert 'id="identity-expand-all"' in table
    assert "details[data-bulk-disclosure]" in reference
    assert "Intel Get NM Version" in reference
    assert "openbmc-intel --unsafe &#x27;NM Set Policy&#x27; &lt;14 payload bytes&gt;" in reference
    assert "AddBRCMConfiguration_30_68_A1" in reference
    assert "GetMgrCertFingerprint" in table
    assert "8af1ba767ed0363653537ee6e2fab3fabd66d838e397903cb99e9cd00caaa792" in reference
    assert "20260929T004726Z-90bbc3db-d22b-4660-a34b-e64abb8c8016" in reference
    assert "22 named child routes" in reference
    assert "RasSetData" in reference


def test_x14_group_routes_preserve_real_identity_and_interface_limits():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    fingerprint = SUPERMICRO_X14[(0x2C, 0x01, 0x52)]
    bootstrap = SUPERMICRO_X14[(0x2C, 0x02, 0x52)]
    assert fingerprint["handler"] == "GetMgrCertFingerprint"
    assert fingerprint["request_length"] == (2, 2)
    assert fingerprint["response_length"] == (34, 34)
    assert not fingerprint["runnable"]
    assert bootstrap["handler"] == "GetBootstrapAccountCredentials"
    assert bootstrap["safety"] == "sensitive"
    assert not bootstrap["runnable"]
    assert {(0x2C, 0x03, 0x52, action) for action in range(4, 13)} <= set(SUPERMICRO_X14)
    assert {(0x2C, 0x01, 0xDC, selector) for selector in range(1, 5)} <= set(SUPERMICRO_X14)
    assert (0x2C, 0x01, 0xDC, 5) not in SUPERMICRO_X14
    assert (0x2C, 0x01, 0xDC, 6) not in SUPERMICRO_X14
    group_routes = {key: command for key, command in SUPERMICRO_X14.items() if key[0] == 0x2C}
    assert len(group_routes) == 19
    assert all(command["response_fields"][0]["meaning"].startswith("echoed group")
               for command in group_routes.values())
    assert {key[3]: command["response_length"] for key, command in group_routes.items()
            if key[:3] == (0x2C, 0x01, 0xDC)} == {
                1: (7, 7), 2: (9, 9), 3: (6, 6), 4: (7, 7),
            }
    private_lengths = {
        key[3]: command["response_length"] for key, command in group_routes.items()
        if key[:3] == (0x2C, 0x03, 0x52)
    }
    assert private_lengths == {
        0x04: (2, 2), 0x05: (2, 2), 0x06: (1, 1), 0x07: (1, 1),
        0x08: (1, 1), 0x09: (2, 2), 0x0A: (1, 1), 0x0B: (1, 1), 0x0C: (2, 2),
    }


def test_x14_primary_semantics_have_named_fields_and_explicit_safety():
    import re

    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG, X14_PRIMARY_PROVIDER_SHA256

    rows = X14_CATALOG["primary"]["operations"]
    assert len(rows) == 150
    assert all(row.get("safety_class") in {
        "read-only", "sensitive", "state-changing", "disruptive", "destructive",
    } for row in rows)
    assert not [
        (row["command"], row["selector"], direction, field["name"])
        for row in rows
        for direction in ("request", "response")
        for field in row[direction]["fields"]
        if re.match(r"^(?:arg|response|field)\d+", field["name"])
    ]

    unsafe_handlers = {
        "OEMGetSetLANMode", "SetSystemEventFlag", "FakeSensorData",
        "OEMSetGetLinkConf", "OEMSetGetACPowerOn",
    }
    assert all(
        row["safety_class"] != "read-only"
        for row in rows if row["handler"] in unsafe_handlers
    )
    assert unsafe_handlers <= {row["handler"] for row in rows}
    no_op_handlers = {
        "NotifyBMCSensorStart", "BIOSSetTimertoTriggerPowerOn",
        "OEMGetSetBBPTimoutSetting", "OEMGetSetTDM",
    }
    assert all(
        row["safety_class"] == "read-only"
        for row in rows if row["handler"] in no_op_handlers
    )
    psu = next(row for row in rows if row["handler"] == "OEMGetPSUInfo")
    assert psu["safety_class"] == "read-only"
    assert psu["runnable_status"] == "authenticated-read-query"
    assert "read-to-clear" in psu["semantic_safety_note"]
    nvme = next(row for row in rows if row["handler"] == "OEMGetSetNVMeSSDParameters")
    assert nvme["response"]["maximum_bytes"] == 216
    assert any("0xD4 system lockdown" in code for code in nvme["completion_codes"])
    adc = next(row for row in rows if row["handler"] == "OEMGetADCValues")
    assert adc["semantic_unresolved_reason"] is None
    assert "1023.0" in adc["response"]["fields"][0]["constraints"]
    assert adc["semantic_evidence"]["provider_sha256"] == X14_PRIMARY_PROVIDER_SHA256
    brcm_bitmap = next(row for row in rows if row["handler"] == "GetBRCMHDDBitmap")
    assert [(field["offset"], field["type"]) for field in brcm_bitmap["response"]["fields"]] == [
        (0, "bytes[32]"), (32, "bytes[8]"), (40, "bytes[32]"), (72, "bytes[8]"),
    ]
    assert "backend property meaning unresolved" in brcm_bitmap["response"]["fields"][2]["meaning"]
    closed_stubs = {
        "NotifyBMCSensorStart", "BIOSLicenseSource", "BIOSSetTimertoTriggerPowerOn",
        "GetRiserCardID", "OEMGetSetBBPTimoutSetting", "OEMGetSetTDM",
        "SetIPProtocolStatus",
    }
    assert all(
        row["semantic_unresolved_reason"] is None
        for row in rows if row["handler"] in closed_stubs
    )


def test_x14_recovered_request_bounds_are_closed_where_proven():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    expected = {
        "FakeSensorData": (3, 5),
        "SetIPProtocolStatus": (2, 2),
        "SetFanControl": (3, 4),
        "OEMGetSensorTempAndDutyCycle": (2, 2),
        "OEMRequestI2C": (11, 11),
        "LicenseFileAction": (3, 3),
        "ChangeHeartBeatLedFreq": (2, 2),
    }
    rows = {row["handler"]: row for row in X14_CATALOG["primary"]["operations"]}
    for handler, bounds in expected.items():
        row = rows[handler]
        assert (
            row["request"]["minimum_bytes_including_selector"],
            row["request"]["maximum_bytes_including_selector"],
        ) == bounds
    assert rows["ReadMemoryCmd"]["request"]["minimum_bytes_including_selector"] == 6
    assert rows["ReadMemoryCmd"]["request"]["maximum_bytes_including_selector"] is None
    assert rows["OEMGetCMProvision"]["safety_class"] == "destructive"
    response_bounds = {
        "GetBRCMHDDBitmap": (80, 80),
        "GetBRCMLogicalDriveBitmap": (32, 32),
        "GetBRCMSpecificHDDInfo": (151, 151),
        "GetBRCMControllerCompactInfo": (123, 123),
        "GetBRCMCompactSpecificHDDInfo": (89, 89),
        "GetBRCMSpecificLogicalDriveInfo": (54, 54),
        "GetBRCMCompactSpecificLogicalDriveInfo": (45, 45),
        "BiosSWHandShake": (0, 48),
        "LicenseFileAction": (0, 2),
        "OEMGetSetSyslogInfo": (0, 0),
        "OEMGetSetTDM": (0, 8),
        "OEMGetSMCCPLDVersions": (3, 3),
        "GetSMCCPLDVersions": (3, 3),
        "OEMReportDebugMessage": (0, 0),
    }
    for handler, bounds in response_bounds.items():
        assert (
            rows[handler]["response"]["minimum_bytes"],
            rows[handler]["response"]["maximum_bytes"],
        ) == bounds
    assert rows["LicenseFileAction"]["safety_class"] == "destructive"
    assert rows["OEMGetSetSyslogInfo"]["safety_class"] == "read-only"


def test_x14_cm_provision_parent_disabled_and_child_census_closed():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    command = SUPERMICRO_X14[(0x30, 0x51, 0x28)]
    assert not command["runnable"]
    assert command["safety"] == "destructive"
    child_commands = {
        key[3] for key in SUPERMICRO_X14
        if len(key) == 4 and key[:3] == (0x30, 0x51, 0x28)
    }
    implemented = {0, 1, 2, 3, *range(5, 11), 0x0F, 0x20, 0x21, 0x30,
                   0x54, 0x55, *range(0x84, 0x88), 0xDB, 0xFF}
    assert child_commands == implemented
    assert len(set(range(0x88)) - child_commands) == 116
    child = SUPERMICRO_X14[(0x30, 0x51, 0x28, 0x05)]
    assert [field["type"] for field in child["request_fields"][-2:]] == ["u8", "u8"]
    for subcommand in (0x07, 0x08):
        child = SUPERMICRO_X14[(0x30, 0x51, 0x28, subcommand)]
        assert child["response_fields"][0]["type"] == "u16be"
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload
    _request, response = lookup_payload("supermicro-x14", 0x30, 0x51, b"\x28\x07\x00")
    assert response is not None
    decoded = decode_payload_response("supermicro-x14", 0x30, 0x51, b"\x28\x07\x00", 0, b"\x34\x12")
    assert decoded.result == 0x3412
def test_x14_dcmi_temperature_record_wire_order_and_bound():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    command = SUPERMICRO_X14[(0x2C, 0x10, 0xDC)]
    assert command["response_length"] == (3, 19)
    record = command["response_fields"][-1]
    assert record["name"] == "readings"
    assert "Temperature bits0:6 and sign bit7, followed by entity instance" in record["meaning"]


def test_x14_fixed_selector_codec_matches_wire_contract():
    import zipmi
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload

    zipmi.load_vendor("supermicro-x14")
    request, _response = lookup_payload("supermicro-x14", 0x30, 0x68, b"\x02")
    assert bytes(request()) == b"\x02"
    decoded = decode_payload_response("supermicro-x14", 0x30, 0x68, b"\x02", 0, b"\x01")
    assert decoded.completion_code == 0
    assert decoded.i2c_access_allowed == 1

    request, _response = lookup_payload("supermicro-x14", 0x2C, 0x01, b"\x52\x01")
    assert bytes(request(certificate_number=1)) == b"\x52\x01"
    decoded = decode_payload_response(
        "supermicro-x14", 0x2C, 0x01, b"\x52\x01", 0,
        b"\x52\x01" + bytes(range(32)),
    )
    assert decoded.group_id == 0x52
    assert decoded.hash_algorithm == 1
    assert decoded.fingerprint == bytes(range(32))

    request, _response = lookup_payload("supermicro-x14", 0x2C, 0x01, b"\xdc\x01")
    assert bytes(request()) == b"\xdc\x01"
    decoded = decode_payload_response(
        "supermicro-x14", 0x2C, 0x01, b"\xdc\x01", 0,
        b"\xdc\x01\x05\x02\x00\x01\x05",
    )
    assert decoded.group_id == 0xDC
    assert decoded.conformance_major == 1
    assert decoded.capabilities_2 == 5


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

    no_op = argparse.Namespace(
        cmd_name="BIOSSetTimertoTriggerPowerOn", data=["0"], unsafe=False, json=False,
    )
    assert cmd_oem_run(no_op, "supermicro-x14") == 0
    assert sent[-1] == (0x30, 0x68, b"\x55\x00")

    mutating = argparse.Namespace(cmd_name="ClearChassisIntrusion", data=[], unsafe=False, json=False)
    assert cmd_oem_run(mutating, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err

    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14, X14_CATALOG
    unsafe_handlers = {
        "OEMGetSetLANMode", "SetSystemEventFlag", "FakeSensorData",
        "OEMSetGetLinkConf", "OEMSetGetACPowerOn",
    }
    for row in X14_CATALOG["primary"]["operations"]:
        if row["handler"] not in unsafe_handlers:
            continue
        command = SUPERMICRO_X14[(
            int(row["netfn"], 0), int(row["command"], 0), int(row["selector"], 0),
        )]
        prefix = command.get("prefix") or b""
        minimum = command["request_length"][0]
        body_length = max(0, (minimum or len(prefix)) - len(prefix))
        denied = argparse.Namespace(
            cmd_name=command["name"], data=["0"] * body_length, unsafe=False, json=False,
        )
        assert cmd_oem_run(denied, "supermicro-x14") == 2
        assert "add --unsafe" in capsys.readouterr().err
    assert len(sent) == 2
    assert sent[1] == (0x30, 0x68, b"\x55\x00")

    sensitive = argparse.Namespace(
        cmd_name="OEMGetPayload", data=["0", "0", "0", "0"], unsafe=False, json=False,
    )
    assert cmd_oem_run(sensitive, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err

    bios_trigger = argparse.Namespace(
        cmd_name="TrigerBiosCfgService", data=[], unsafe=False, json=False,
    )
    assert cmd_oem_run(bios_trigger, "supermicro-x14") == 2
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

    clear_cmos = argparse.Namespace(cmd_name="Clear CMOS", data=[], unsafe=False, json=False)
    assert cmd_oem_run(clear_cmos, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err

    invalid_task = argparse.Namespace(
        cmd_name="Get Provision Task Status by Index", data=["4"], unsafe=False, json=False,
    )
    assert cmd_oem_run(invalid_task, "supermicro-x14") == 2
    assert "recovered provisioning subcommand contract" in capsys.readouterr().err
    assert len(sent) == 3

    task_status = argparse.Namespace(
        cmd_name="Get Provision Task Status by Index", data=["3"], unsafe=False, json=False,
    )
    assert cmd_oem_run(task_status, "supermicro-x14") == 0
    assert sent[-1] == (0x30, 0x51, b"\x28\x07\x03")

    clear_ra = argparse.Namespace(cmd_name="Clear RA Provisioning", data=[], unsafe=False, json=False)
    assert cmd_oem_run(clear_ra, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_x14_every_advertised_exact_name_resolves_to_its_wire_key():
    from zipmi.cli.oem_cmds import _find_cmd, _vendor_listing

    listing = _vendor_listing("supermicro-x14")
    for key, command in listing.items():
        assert _find_cmd(listing, command["name"]) == [(key, command)]
