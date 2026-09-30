# z-artifact: 887d7b39-b81c-41ca-a794-bbc746bda8ac
"""Firmware-bound Supermicro X14 contract, codec, and CLI closure tests."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_x14_virtual_media_status_values_match_provider_behavior():
    source = json.loads(
        (ROOT / "zipmi/data/sources/supermicro-x14-contracts.json").read_text()
    )
    pending = [source]
    rows = []
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("handler") == "OEMGetVMDeviceStatus":
                rows.append(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)

    assert len(rows) == 1
    row = rows[0]
    assert row["semantic_unresolved_reason"] is None
    meaning = row["response"]["fields"][0]["meaning"]
    assert "VirtualMedia1/2/3" in meaning
    assert "0=active with an ImageURL ending in .ima or .img" in meaning
    assert "4=active with any other ImageURL suffix" in meaning


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
    assert sum(key[:2] == (0x30, 0x70) for key in SUPERMICRO_X14) == 78
    assert sum(key[:2] == (0x30, 0x68) for key in SUPERMICRO_X14) == 60
    assert sum(key[:2] == (0x30, 0xAD) for key in SUPERMICRO_X14) == 3
    assert sum(key[:2] == (0x30, 0x51) for key in SUPERMICRO_X14) == 4
    assert sum(key[:2] == (0x30, 0xA0) for key in SUPERMICRO_X14) == 27

    association = X14_CATALOG["primary"]["selector_map_association"]["wire_commands"]
    assert "consumed by OEM51Handler; 4 selectors" in association["0x51"]
    assert "consumed by OEM68Handler; 38 selectors" in association["0x68"]
    assert "consumed by OEM70Handler; 78 selectors" in association["0x70"]
    assert "consumed by OEMADHandler; 3 selectors" in association["0xad"]

    assert SUPERMICRO_X14[(0x30, 0x68, 0x03)]["handler"] == "OEMSSLCertificateStatus"
    assert SUPERMICRO_X14[(0x30, 0x70, 0x63)]["handler"] == "OEMSetGetLinkConf"
    assert SUPERMICRO_X14[(0x30, 0x51, 0xD3)]["handler"] == "OEMSetBIOSCap"
    assert SUPERMICRO_X14[(0x30, 0xAD, 0x07)]["handler"] == "OEMSetSmartPowerOption"


def test_x14_generated_references_are_closed_and_current():
    subprocess.run(
        [sys.executable, "scripts/generate_supermicro_x14_reference.py", "--check"],
        cwd=ROOT, check=True,
    )
    reference = (ROOT / "docs/supermicro-x14-command-reference.html").read_text()
    table = (ROOT / "docs/supermicro-x14-command-table.html").read_text()

    assert "OEMAddDelUser: operation 1 carries slot 1..15" in table
    assert "only 0x00000004 emits MEL 0x7b" in table
    assert "child 0x03 reads SecurityManager.readCPLDVersion() as int64" in table
    assert "0x0a value 0x03 for the BoardId-7504 extended fan-delay workaround" in table
    assert "separate /dev/spi1nand0 write of 0x13 to offset 0x18" in table
    assert "ioctl 0xc0046b01 with the register index in bits 16..23" in table
    assert "provider directly calls smci::core::get_rot_cpld_reg" in table
    assert "child 0xdb reads /usr/share/log/3068db.log only for operand a=5" in table
    assert "child 0x0f operand B is a device selector passed to dumpDboot(B, 0)" in table
    assert "/tmp/cpld_flash_dump.bin" in table
    assert "three 64-KiB blocks (0x30000 bytes on success)" in table
    assert "register 0x00 bit 4 enables MSMI latching" in reference
    assert "ioctl 0xc0046b01 with the register index in bits 16..23" in reference
    assert "not proven to share the D-Bus backend" in reference
    assert "selector 0x79 OEMGetPSUInfo" in table
    assert "10 helper calls with 100 ms sleeps before throwing std::logic_error" in table
    assert reference.count('<tr data-search="') == 244
    assert table.count('<tr data-search="') == 116
    assert "65</strong>Unique NetFn/Cmd addresses" in reference
    assert "244</strong>Documented operations" in reference
    assert "187 / 57 / 0 / 0</strong>Request layout:" in reference
    assert "182 / 62 / 0 / 0</strong>Response layout:" in reference
    assert "116</strong>Executed registration rows" in table
    assert "115</strong>Unique wire identities" in table
    assert "66</strong>OEM/group identities" in table
    assert "150</strong>Hidden primary selector operations" in table
    assert 'id="operation-expand-all"' in reference
    assert 'id="identity-expand-all"' in table
    assert "details[data-bulk-disclosure]" in reference
    assert "Intel Get NM Version" in reference
    assert "openbmc-intel --unsafe &#x27;NM Set Policy&#x27; &lt;14 payload bytes&gt;" in reference
    assert "AddBRCMConfiguration_30_70_A1" in reference
    assert "GetMgrCertFingerprint" in table
    assert "8af1ba767ed0363653537ee6e2fab3fabd66d838e397903cb99e9cd00caaa792" in reference
    assert "20260930T225207Z-56f75a49-1b7e-479e-a1f7-6737c59b6d00" in reference
    assert "22 named child routes" in reference
    assert "RasSetData" in reference
    assert "RemoveBeforeButton at 6..7 and 14..15" in reference
    assert "LastPresence u16le at 4..5" in reference
    assert "SFT-OOB-LIC" in reference and "SFT-DCMS-SINGLE" in reference
    assert "SFT-OOB-LIC" in table and "SFT-DCMS-SINGLE" in table
    assert "100M half-duplex" in reference and "1G full-duplex" in reference
    assert "100M half-duplex" in table and "1G full-duplex" in table


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
    cot = next(row for row in rows if row["handler"] == "OEMRequestCOT")
    assert cot["semantic_evidence"]["dbus_endpoint"]["method"] == "Set"
    assert cot["semantic_evidence"]["dbus_endpoint"]["arguments"]["property_name"] == "RequestedBMCTransition"
    assert cot["semantic_evidence"]["dbus_endpoint"]["arguments"]["variant_string"].endswith("Transition.Reboot")
    assert "requests a BMC reboot" in cot["effects"]
    assert cot["semantic_unresolved_reason"] is None
    assert "opaque internal handler-name acronym" in cot["semantic_evidence"]["naming_note"]
    assert "0xFF unspecified error (typed-handler wrapper catches std::exception)" in cot["completion_codes"]
    assert "ccUnspecifiedError" in cot["semantic_evidence"]["framework_exception_mapping"]["mapping"]
    assert cot["runnable_status"] == "lab-only-mutation"
    assert cot["safety_class"] == "disruptive"
    assert cot["semantic_evidence"]["handler_address"] == "0x000f38a8"
    assert "no relocation at the handler literal-pool words" in cot["semantic_evidence"]["relocation_check"]
    license_action = next(row for row in rows if row["handler"] == "LicenseFileAction")
    mel_map = license_action["semantic_evidence"]["mel_action_map"]
    assert mel_map["event_id"] == 5
    assert mel_map["status"] == "deactivated"
    assert mel_map["file_action_operation"] == 1
    assert mel_map["slots"] == [
        {"license_slot": 1, "license_label": "SFT-OOB-LIC"},
        {"license_slot": 2, "license_label": "SFT-DCMS-SINGLE"},
    ]
    assert mel_map["channel_context"] == {
        "ipmi_channel_type_5": "KCS", "other_channel_type": "RMCP",
    }
    assert license_action["semantic_unresolved_reason"] is None
    assert license_action["semantic_evidence"]["license_backend"]["product_map"] == {
        "0x04": "SFT-DCMS-SINGLE (license file/ID 2)",
        "0x01": "SFT-OOB-LIC (license file/ID 1)",
    }
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
        "OEMSetGetACPowerOn",
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
    fp_led = next(row for row in rows if row["handler"] == "SetFPLEDControl")
    assert fp_led["semantic_unresolved_reason"] is None
    assert fp_led["semantic_evidence"]["table_bytes"] == [0x6f, 0x74, 0x6f, 0x63]
    assert "outside 3..5" in fp_led["effects"]
    link_status = next(row for row in rows if row["handler"] == "GetLinkStatusCmd")
    assert [field["meaning"] for field in link_status["response"]["fields"]] == [
        "Middle byte of the helper's 24-bit value: NC-SI Link Status bits 1..4 (speed/duplex); when that nibble is 0xF, the byte instead carries Extended Speed and Duplex bits 31..24. Codes are defined by DMTF DSP0222 Table 51.",
        "High byte of the helper's 24-bit value; only bit 0 is populated from NC-SI Link Status bit 0 (0=down, 1=up), upper bits are zero.",
        "Low byte of the helper's 24-bit value; only bit 0 is populated from NC-SI Link Status bit 5 (1=auto-negotiation enabled), upper bits are zero.",
        "LAN_MII_INFO byte 2; value mapping is 10→0, 100→1, other values→2",
        "LAN_MII_INFO byte 3; dedicated-interface mode check result",
        "LAN_MII_INFO byte 1; equality result from a D-Bus property comparison",
        "LAN_MII_INFO byte 0; copied from the AutoNeg D-Bus property",
        "LAN_LINK_INFO byte 1; active interface selected by IF-mode helper",
        "LAN_LINK_INFO byte 0; result of UtilGetIFMode",
    ]
    assert link_status["semantic_unresolved_reason"] is None
    assert "AutoNeg property identity" in link_status["semantic_confidence"]
    assert link_status["semantic_evidence"]["helper_sha256"] == (
        "3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf"
    )
    service_status = next(row for row in rows if row["handler"] == "GetServiceStatusCmd")
    assert service_status["semantic_unresolved_reason"] is None
    assert 'isServiceActive("com.Supermicro")' in service_status["effects"]
    assert 'isServiceActive("com.Supermicro.hii.service")' in service_status["effects"]
    assert "bytes [0,14) as com.Supermicro" in service_status["semantic_evidence"]["service_literals"]
    ready_check = next(row for row in rows if row["handler"] == "DLOOBDataReadyCheck")
    assert "ignores the file-type argument" in ready_check["effects"].lower()
    assert ready_check["response"]["fields"][0]["meaning"].startswith("Always 0")
    assert ready_check["semantic_unresolved_reason"] is None
    fake_sensor = next(row for row in rows if row["handler"] == "FakeSensorData")
    assert fake_sensor["request"]["fields"][2]["name"] == "ignored_request_byte"
    assert fake_sensor["request"]["fields"][3]["presence"].endswith("3, 4, or 5 bytes including selector")
    assert fake_sensor["semantic_unresolved_reason"] is None
    assert "u16 reading to com.Supermicro.sdr / com.Supermicro.sensor / fakevalue" in fake_sensor["effects"]
    assert "only if that write fails does it set the isfake property" in fake_sensor["effects"].lower()
    assert "variant tag 3/u16 and fakevalue" in fake_sensor["semantic_evidence"]["setter_mapping"]
    debug_message = next(row for row in rows if row["handler"] == "OEMReportDebugMessage")
    assert debug_message["semantic_unresolved_reason"] is None
    assert "/usr/share/log/3068db.log" in debug_message["effects"]
    assert "256 bytes" in debug_message["effects"]
    clear_option = next(row for row in rows if row["handler"] == "ClearConfigOption")
    assert "0x02000000" in clear_option["effects"] and "0x01000000" in clear_option["effects"]
    assert "emits MEL event 0x7b" in clear_option["effects"]
    helper = clear_option["semantic_evidence"]["shared_helper"]
    assert helper["name"] == "anonymous ClearConfigOption cleanup helper"
    assert helper["address"] == "0x000a84cc"
    assert "/usr/share/log" in helper["behavior"]
    assert "three-byte ASCII string `mel`" in helper["behavior"]
    assert "removes every staged path with std::filesystem::remove" in helper["behavior"]
    assert "ELF VA 0x1ed9e0" in helper["behavior"]
    assert "/usr/share/log/rsyslog_server" in helper["behavior"]
    assert "ReloadUnit" in helper["behavior"]
    assert clear_option["semantic_unresolved_reason"] is None
    assert "No subsystem label is assigned" in clear_option["semantic_evidence"]["mask_label_boundary"]
    assert "0x98f48" in helper["evidence"] and "0x1b30c0" in helper["evidence"]
    assert "std::filesystem::directory_iterator/remove" in helper["evidence"]
    assert "passes 1 for mask 0x00000004" in helper["behavior"]
    assert "0x00040000" not in clear_option["request"]["fields"][1]["constraints"]
    assert "0x00080000" in clear_option["request"]["fields"][1]["constraints"]
    uid = next(row for row in X14_CATALOG["primary"]["registrations"] if row["handler"] == "GetUIDStatus")
    assert uid["response"]["fields"][0]["name"] == "uid_active"
    assert "(result & 0x30) != 0" in uid["response"]["fields"][0]["meaning"]
    assert "method identity is unresolved" in uid["response"]["fields"][0]["meaning"]
    prepare_done = next(row for row in rows if row["handler"] == "PrepareFileDownloadDone")
    assert "Always 1" in prepare_done["response"]["fields"][0]["meaning"]
    assert "size=0" in prepare_done["effects"]
    file_download = next(row for row in rows if row["handler"] == "FileDownload")
    assert "0x5dc (1500)" in file_download["effects"]
    assert "downloaded_size" in file_download["effects"]
    upload_done = next(row for row in rows if row["handler"] == "UploadOOBDataDone")
    assert upload_done["semantic_unresolved_reason"] is None
    assert "/usr/bin/EfiDeCompress /var/oob/sdo_diagnostic.compress /var/oob/sdo_diagnostic.html" in upload_done["effects"]
    assert "when system() returns zero" in upload_done["effects"]
    assert "1 otherwise" in upload_done["effects"]
    assert "inaccessible source returns 1" in upload_done["effects"]
    oob_status = next(row for row in rows if row["handler"] == "GetOOBFileStatus")
    assert "1=/tmp/HII/bios_restore_setting" in oob_status["effects"]
    assert "25=/var/oob/sdo_diagnostic.compress" in oob_status["effects"]
    assert "2=/tmp/HII/bios_restore_dmi" in oob_status["effects"]
    assert "entries 0, 5–7, and 9–16 have null paths" in oob_status["effects"]
    assert oob_status["semantic_unresolved_reason"] is None
    assert "normal operation only calls access()" in oob_status["effects"]
    assert oob_status["runnable_status"] == "authenticated-read-query"
    clear_oob = next(row for row in rows if row["handler"] == "ClearOOBFile")
    assert "resets the provider-global availability flag" in clear_oob["effects"]
    assert "does not unlink files or alter file contents" in clear_oob["effects"]
    assert "0x020037bf" in clear_oob["effects"]
    assert clear_oob["semantic_unresolved_reason"] is None
    report_status = next(row for row in rows if row["handler"] == "ReportDownloadStatusToBMC")
    assert "1, 2, 17–22, and 24" in report_status["effects"]
    assert "_chksum" in report_status["effects"]
    assert "not a worker callback" in report_status["effects"]
    assert report_status["safety_class"] == "destructive"
    assert report_status["semantic_unresolved_reason"] is None
    psu = next(row for row in rows if row["handler"] == "OEMGetPSUInfo")
    assert psu["semantic_unresolved_reason"] is None
    assert "0xFF unspecified error (typed-handler wrapper catches std::exception)" in psu["completion_codes"]
    psu_daemon = psu["semantic_evidence"]["matching_daemon"]
    assert psu_daemon["sha256"] == "2453900f9b112ee1ee55576e081cc1074df0d6efd5d263ad8011bbbb580487ce"
    assert psu_daemon["method"] == "GetPSURaw"
    assert "first byte as PMBus command and second as read length" in psu_daemon["callback_evidence"]
    assert "ioctl 0x707" in psu_daemon["backend_evidence"]
    assert "four ioctl attempts" in psu_daemon["backend_evidence"]
    assert "ten helper calls" in psu_daemon["failure_evidence"]
    psu_provider = psu["semantic_evidence"]
    assert "sd_bus_call" in psu_provider["provider_error_evidence"]
    assert "throws sdbusplus::exception::SdBusError" in psu_provider["provider_error_evidence"]
    psu_framework = psu_provider["framework_exception_mapping"]
    assert psu_framework["build_source_commit"] == "0ce6a5771d00f8c37f43daf722ed6774324342a8"
    assert "ccUnspecifiedError" in psu_framework["mapping"]
    assert "std::logic_error" in psu_daemon["failure_evidence"]
    assert "__cxa_throw" in psu_daemon["failure_evidence"]
    assert "returns IPMI completion code 0xFF" in psu_daemon["failure_evidence"]
    assert "throws std::logic_error" in psu["effects"]
    assert "returns IPMI completion code 0xFF with no payload" in psu["effects"]
    assert [field["offset"] for field in psu["request"]["fields"]] == list(range(7))
    assert "low nibble is ignored" in psu["request"]["fields"][3]["constraints"]
    assert "second GetPSURaw byte argument" in psu["request"]["fields"][4]["constraints"]
    assert "first GetPSURaw byte argument" in psu["request"]["fields"][5]["constraints"]
    assert "not forwarded" in psu["request"]["fields"][6]["constraints"]
    power = next(row for row in rows if row["handler"] == "OEMGetPowerConsumption")
    assert power["semantic_unresolved_reason"] is None
    assert "DayAvg:u16le then WeekAvg:u16le" in power["response"]["fields"][1]["constraints"]
    power_status = next(row for row in rows if row["handler"] == "GetPowerStatus")
    assert power_status["semantic_unresolved_reason"] is None
    assert "CurrentPowerState" in power_status["effects"]
    assert "PowerState.Off and .On" in power_status["effects"]
    assert "0=Off, 1=On" in power_status["response"]["fields"][0]["meaning"]
    cert_status = next(row for row in rows if row["handler"] == "OEMSSLCertificateStatus")
    assert cert_status["semantic_unresolved_reason"] is None
    assert "/etc/ssl/certs/https/server.pem" in cert_status["effects"]
    assert "notBefore and notAfter" in cert_status["effects"]
    assert "%h %d %H:%M:%S %Y GMT" in cert_status["response"]["fields"][0]["constraints"]
    assert "not private-key status" in cert_status["response"]["fields"][0]["meaning"]
    oob_buffer = next(row for row in rows if row["handler"] == "EnableOOBDataBuffer")
    assert oob_buffer["semantic_unresolved_reason"] is None
    assert "old_value | 0x00000002" in oob_buffer["effects"]
    assert "still returns the same empty success response" in oob_buffer["effects"]
    assert oob_buffer["safety_class"] == "state-changing"
    assert oob_buffer["runnable_status"] == "lab-only-mutation"
    remove_lighttpd = next(row for row in rows if row["handler"] == "OEMRemoveLighttpd")
    assert "SysLockdownEnable" in remove_lighttpd["effects"]
    assert "no file removal" in remove_lighttpd["effects"]
    assert remove_lighttpd["semantic_unresolved_reason"] is None
    cat_error = next(row for row in rows if row["handler"] == "OEMGetSetCATError")
    assert "any byte value" in cat_error["request"]["fields"][2]["constraints"]
    assert "present and nonzero" not in cat_error["request"]["fields"][2]["constraints"]
    assert cat_error["semantic_unresolved_reason"] is None
    assert "xyz.openbmc_project.Settings" in cat_error["effects"]
    assert "property read fails" in cat_error["effects"]
    assert "successful SET has no response data" in cat_error["effects"]
    assert cat_error["response"]["minimum_bytes"] == 0
    oob_data_status = next(row for row in rows if row["handler"] == "GetOOBDataStatus")
    assert oob_data_status["semantic_unresolved_reason"] is None
    assert oob_data_status["request"]["fields"][1]["constraints"] == "exact accepted set: 1, 2, 8, 12, 17, 18, 19, 20, 21, 22, 24; other values return 0xC1"
    assert "Type 12 has a null path slot and returns zero status/size" in oob_data_status["effects"]
    assert "<source>_chksum" in oob_data_status["effects"]
    assert "appends the checksum byte to the source" in oob_data_status["effects"]
    assert oob_data_status["semantic_evidence"]["checksum_sidecar_suffix"] == "_chksum"
    assert oob_data_status["semantic_evidence"]["type_path_map"]["17"] == "/tmp/oob/secure_boot_pk"
    assert oob_data_status["semantic_evidence"]["type_path_map"]["24"] == "/tmp/oob/https_boot.der"
    assert oob_data_status["semantic_evidence"]["type_path_map"]["12"] is None
    assert oob_data_status["safety_class"] == "state-changing"
    assert oob_data_status["runnable_status"] == "lab-only-mutation"
    nvme_params = next(row for row in rows if row["handler"] == "OEMGetSetNVMeSSDParameters")
    assert "com.Supermicro.nvmebp.action" in nvme_params["effects"]
    assert "0=Locate, 1=Dislocate, 2=setButtonEnabled, 3=RedLed, and 4=Remove" in nvme_params["effects"]
    assert nvme_params["semantic_unresolved_reason"] is None
    assert "action 4 therefore raises SdBusError" in nvme_params["effects"]
    assert "0xFF unspecified error (SET action 4 calls absent D-Bus method Remove; typed-handler wrapper catches SdBusError)" in nvme_params["completion_codes"]
    assert "no Remove registration" in nvme_params["semantic_evidence"]["matching_daemon_action_registration"]
    assert "returns ccUnspecifiedError (0xFF)" in nvme_params["semantic_evidence"]["remove_failure_mapping"]
    assert nvme_params["request"]["fields"][5]["constraints"].endswith("0=Locate, 1=Dislocate, 2=setButtonEnabled, 3=RedLed, 4=Remove")
    assert nvme_params["semantic_evidence"]["set_action_call_sites_raw"]["4"] == "0x000af3f4 -> Remove"
    assert "Id is little-endian u16 at offsets 6..7" in nvme_params["effects"]
    assert "constant 1 at 1" in nvme_params["response"]["fields"][0]["constraints"]
    nvme_result = nvme_params["response"]["fields"][0]["constraints"]
    assert "Ver u8 at 8" in nvme_result
    assert "LocateStatus u32le split between low half at 2..3 and high half at 17..18" in nvme_result
    assert "Presence u32le split between low half at 4..5 and high half at 19..20" in nvme_result
    assert nvme_params["semantic_evidence"]["get_subcommand_0_property_call_sites_raw"]["Presence"].startswith("0x000ad910")
    assert "ClassCode 0..2; VendorId u16le 3..4" in nvme_result
    assert "SerialNum 5..24 (up to 20 bytes); ModelNum 25..64 (up to 40 bytes)" in nvme_result
    assert "Port1MaxLinkWidth 68; InitialPwrRequirement 69; MaxPowerRequirement 72" in nvme_result
    assert "NSS-present flag bit 1 at 125; NSS 126; SmartWarning 127; PDLU 129" in nvme_result
    assert "All other bytes are zero: 70..71" in nvme_result
    assert "can trigger an out-of-bounds copy" in nvme_result
    assert "LastPresence u16le at 4..5" in nvme_result
    assert "zero-initialized bytes 6..11" in nvme_result
    assert nvme_params["semantic_evidence"]["get_subcommand_ff_property_call_sites_raw"]["LastPresence"].endswith("output bytes 4..5")
    assert "LocateStatus u32le low/high halves at 0..1 and 8..9" in nvme_result
    assert "RemoveBeforeButton at 6..7 and 14..15" in nvme_result
    assert nvme_params["semantic_evidence"]["get_subcommand_2_property_call_sites_raw"]["Presence"].startswith("0x000ae0e8")
    assert nvme_params["semantic_evidence"]["get_subcommand_1_zero_fill_raw"].startswith("0x000ae3a4")
    assert "RedLed" in nvme_params["request"]["fields"][5]["constraints"]
    upload_oob = next(row for row in rows if row["handler"] == "UploadOOBData")
    assert upload_oob["response"]["fields"] == []
    assert "0,1,2,3,4,5,7,8,9,10,12,13,25" in upload_oob["request"]["fields"][1]["constraints"]
    report_status = next(row for row in rows if row["handler"] == "ReportDownloadStatusToBMC")
    assert "17–22" in report_status["effects"] and "type 8 returns empty success" in report_status["effects"].lower()
    assert "/tmp/HII/boot_restore_setting.json" in report_status["effects"]
    assert report_status["semantic_evidence"]["type_1_unlink_paths"] == [
        "/tmp/HII/boot_restore_setting", "/tmp/HII/boot_restore_setting.json",
    ]
    apply_file = next(row for row in rows if row["handler"] == "ApplyFileCommand")
    assert apply_file["semantic_unresolved_reason"] is None
    assert "Action 0x11 (decimal 17, UploadLicenseFile) is joined synchronously" in apply_file["effects"]
    assert "0x0B (decimal 11, UploadIMA), are detached" in apply_file["effects"]
    action_map = apply_file["semantic_evidence"]["action_map"]
    assert len(action_map) == 28
    assert {item["action"] for item in action_map} == {
        "0x01", "0x02", "0x04", "0x05", "0x07", "0x08", "0x09", "0x0A",
        "0x0B", "0x11", "0x12", "0x81", "0x82", "0x83", "0x84", "0x85",
        "0x87", "0x89", "0x8A", "0x8B", "0x8D", "0x8F", "0x95", "0x96",
        "0x98", "0x99", "0x9A", "0x9B",
    }
    assert next(item for item in action_map if item["action"] == "0x11")["name"] == "UploadLicenseFile"
    assert next(item for item in action_map if item["action"] == "0x0B")["name"] == "UploadIMA"
    brcm_bitmap = next(row for row in rows if row["handler"] == "GetBRCMHDDBitmap")
    assert [(field["offset"], field["type"]) for field in brcm_bitmap["response"]["fields"]] == [
        (0, "bytes[32]"), (32, "bytes[8]"), (40, "bytes[32]"), (72, "bytes[8]"),
    ]
    assert "FwState u16 property equals numeric 1" in brcm_bitmap["response"]["fields"][2]["meaning"]
    assert "no semantic enum label is exposed" in brcm_bitmap["response"]["fields"][2]["meaning"]
    assert brcm_bitmap["semantic_unresolved_reason"] is None
    assert "UNCONFIGURED_GOOD=0" in brcm_bitmap["semantic_evidence"]["backend_enum_evidence"]
    assert "target numeric mapping remains unverified" in brcm_bitmap["semantic_evidence"]["cross_source_enum_reference"]["claim"]
    logical_compact = next(row for row in rows if row["handler"] == "GetBRCMCompactSpecificLogicalDriveInfo")
    assert [(field["offset"], field["name"]) for field in logical_compact["response"]["fields"][1:11]] == [
        (4, "prl"), (5, "rlq"), (6, "srl"), (7, "stripe_size"),
        (8, "num_drives"), (9, "span_depth"), (10, "state"),
        (11, "present"), (12, "logical_drive_name"), (28, "operation_flags"),
    ]
    assert logical_compact["response"]["fields"][11]["meaning"] == "ArrayRef entries (up to eight u16 references)."
    compact_drive = next(row for row in rows if row["handler"] == "GetBRCMCompactSpecificHDDInfo")
    assert [(field["offset"], field["name"]) for field in compact_drive["response"]["fields"][10:]] == [
        (51, "user_data_block_size"), (52, "selector_derived_value"), (53, "present"),
        (54, "array_ref_0"), (56, "array_ref_1"), (58, "free_size"),
        (62, "first_free_size"), (66, "temperature"), (67, "time"),
        (71, "status_flags"), (72, "capability_flags"), (73, "serial_number"),
    ]
    assert ">> 30" in compact_drive["response"]["fields"][9]["meaning"]
    cm = next(row for row in rows if row["handler"] == "OEMGetCMProvision")
    version_call = cm["semantic_evidence"]["resolved_child_calls"]["0x03"]
    assert version_call["endpoint"]["method"] == "readCPLDVersion"
    assert version_call["endpoint"]["signature"] == "() -> int64 (D-Bus type x)"
    assert version_call["response"].startswith("The provider serializes the low 24 bits")
    assert version_call["evidence"]["helper_address"] == "0x000ccba8"
    assert version_call["evidence"]["libsmci_sha256"] == (
        "3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf"
    )
    assert "uninitialized stack buffer" in version_call["response"]
    assert "ioctl 0xc0206b0c" in version_call["evidence"]["security_manager_method_evidence"]
    assert "three uninitialized stack bytes" in cm["semantic_safety_note"]
    assert "ccUnspecifiedError" in cm["semantic_evidence"]["framework_exception_mapping"]["mapping"]
    assert "0x54/0x55 are high-impact AC-cycle/CPLD sequences" in cm["effects"]
    assert "manipulate bits 0x10/0x20 of CPLD register 0x40" in cm["effects"]
    assert cm["semantic_unresolved_reason"] is None
    otp = cm["semantic_evidence"]["resolved_child_calls"]["0x86"]
    assert "`111111111`" in otp["response"]
    assert "0x1d44c-0x1d45c" in otp["backend"]
    closed_stubs = {
        "NotifyBMCSensorStart", "BIOSLicenseSource", "BIOSSetTimertoTriggerPowerOn",
        "GetRiserCardID", "OEMGetSetBBPTimoutSetting", "OEMGetSetTDM",
        "SetIPProtocolStatus",
    }
    assert all(
        row["semantic_unresolved_reason"] is None
        for row in rows if row["handler"] in closed_stubs
    )


def test_x14_ipv6_network_child_map_and_mutation_helpers_are_documented():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    ipv6 = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "OEMCGetSetIPV6Network"
    )
    assert "0=DHCPv6/SLAAC mode state" in ipv6["effects"]
    assert "3=DHCPv6 DUID" in ipv6["effects"]
    assert "PltSetIpv6SlaacStatus" in ipv6["effects"]
    gate = ipv6["semantic_evidence"]["lockdown_gate"]
    assert gate["operation"] == "1 and 2"
    assert gate["endpoint"] == {
        "service": "xyz.openbmc_project.Settings",
        "path": "/com/SMCI/SysLockdown",
        "interface": "com.SMCI.Managers.Item.SysLockdown",
        "property": "SysLockdownEnable",
        "type": "boolean",
    }
    assert "0xd4" in gate["behavior"]
    assert any("0xD4" in code for code in ipv6["completion_codes"])
    dhcp = ipv6["semantic_evidence"]["observed_dhcp_property_access"]
    assert dhcp["property"] == "DNSEnabledv6"
    assert dhcp["calls"][0]["value"] is False
    assert dhcp["calls"][0]["callsite_elf_va"] == "0x000f2b5c"
    assert "getter result is false" in dhcp["scope"]
    assert "normalized mode argument equals 2" in dhcp["scope"]
    assert "mode 2 additionally requires the SLAAC flag to be zero" in ipv6["effects"]
    assert "UtilSetDHCPPropertyStatus" in ipv6["effects"]
    assert ipv6["semantic_unresolved_reason"] is None
    op1 = ipv6["semantic_evidence"]["resolved_setter_prefix"]["operation_1"]
    assert "bytes 3..18 are the 16 network-order IPv6 address bytes" in op1
    assert "byte 19 is prefix length 1..128" in op1
    op2 = ipv6["semantic_evidence"]["resolved_setter_prefix"]["operation_2"]
    assert "13-byte vector" in op2 and "out-of-bounds index 16" in op2
    assert "three uninitialized trailing bytes" in op2
    assert ipv6["safety_class"] == "state-changing"
    assert ipv6["runnable_status"] == "lab-only-mutation"


def test_x14_mmbi_handler_has_exact_opaque_byte_vector_boundary():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    mmbi = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "OEMGetSetMMBIHashKey"
    )
    assert mmbi["request"]["maximum_bytes_including_selector"] == 57
    assert "6–55 bytes" in mmbi["request"]["fields"][2]["constraints"]
    assert "byte 0 and byte 1 must both be nonzero" in mmbi["request"]["fields"][2]["constraints"]
    assert "forwards it unchanged" in mmbi["effects"]
    assert "setEncHashData" in mmbi["effects"]
    assert "GET success only: exactly 8 bytes" in mmbi["response"]["fields"][0]["constraints"]
    backend = mmbi["semantic_evidence"]["mmbi_backend"]
    assert backend["sha256"] == "d95553c4d12415fca43e5ec933218046775a881b030988d4d899900a4478d6d3"
    assert "CBlowfish" in backend["static_findings"]
    assert "compares against a fresh BoardId read" in backend["static_findings"]
    assert "RTTI type name" in backend["static_findings"]
    assert "not a cryptographic key" in backend["static_findings"]
    assert "raw bytes as candidate Blowfish key" in backend["static_findings"]
    assert "encrypted_board_id" == mmbi["response"]["fields"][0]["name"]
    assert "encrypted 8-byte block" in mmbi["effects"]
    assert mmbi["semantic_unresolved_reason"] is None
    assert backend["callbacks"]["setEncHashData"]["signature"] == "ay -> n"
    assert backend["callbacks"]["getEncHashData"]["signature"] == "() -> n, ay"
    assert backend["callbacks"]["checkEncHashData"]["called_by_ipmi_provider"] is False
    assert "status is 0" in mmbi["effects"]
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14
    route = SUPERMICRO_X14[(0x30, 0x68, 0x20)]
    assert "exact registered target callbacks" in route["evidence"]


def test_x14_bbp_validator_is_read_only_and_not_a_mutator():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    bbp = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "OEMGetSetBBP"
    )
    assert bbp["runnable_status"] == "authenticated-read-query"
    assert bbp["safety_class"] == "read-only"
    assert bbp["semantic_unresolved_reason"] is None
    assert "No branch reads or writes BBP state" in bbp["effects"]
    assert "Opaque compatibility byte" in bbp["request"]["fields"][2]["meaning"]
    assert "Opaque compatibility byte" in bbp["request"]["fields"][3]["meaning"]
    assert any("0xD4 SystemLockdownEnable is true" in code for code in bbp["completion_codes"])


def test_x14_prepare_download_types_resolve_to_worker_save_actions():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    prepare = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "PrepareFileDownload"
    )
    mapping = prepare["semantic_evidence"]["type_to_action_map"]
    assert len(mapping) == 17
    assert mapping[0] == {"type": 1, "action": "0x81", "name": "SaveConfig"}
    assert mapping[-1] == {"type": 27, "action": "0x9B", "name": "SaveBIOSBootCfg"}
    assert "packed_argument >> 24" in prepare["semantic_evidence"]["worker_extracts_type"]
    assert "no callback" in prepare["semantic_evidence"]["unmapped_type_behavior"].lower()
    assert prepare["semantic_unresolved_reason"] is None


def test_x14_broadcom_records_use_producer_backed_tail_layouts():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    rows = {row["selector"]: row for row in X14_CATALOG["primary"]["operations"]}
    hdd = rows["0x4d"]
    assert [(field["offset"], field["type"]) for field in hdd["response"]["fields"][-3:]] == [
        (146, "u8 bitfield"), (147, "u16le"), (149, "bytes[2]"),
    ]
    assert "PDDeviceId" in hdd["response"]["fields"][-2]["meaning"]
    assert "zero-filled" in hdd["response"]["fields"][-1]["meaning"]
    assert "useSSEraseType" in hdd["response"]["fields"][-3]["meaning"]
    assert "sanitizeType" in hdd["response"]["fields"][-3]["meaning"]
    assert hdd["semantic_evidence"]["producer_sha256"] == (
        "5132797e2a16a3f5fd5f726921bcab11e2263a8a9294c8f8f1c40bbb094b9625"
    )
    logical_drive = rows["0x52"]
    assert logical_drive["response"]["fields"][1]["meaning"] == "StripeSize"
    assert logical_drive["response"]["fields"][-1]["meaning"] == "scaled Progress value"
    assert [field["meaning"].split(" property")[0] for field in logical_drive["response"]["fields"][4:8]] == [
        "StripeSize", "NumDrives", "SpanDepth", "State",
    ]
    assert logical_drive["semantic_unresolved_reason"] is None
    compact_drive = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "GetBRCMCompactSpecificHDDInfo"
    )
    scaled_size = next(
        field for field in compact_drive["response"]["fields"]
        if field["offset"] == 47
    )
    assert "CoercedSize u64 × UserDataBlockSize u16) >> 30" in scaled_size["meaning"]
    assert "only when both inputs are nonzero" in scaled_size["meaning"]
    assert compact_drive["semantic_unresolved_reason"] is None
    compact_logical = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "GetBRCMCompactSpecificLogicalDriveInfo"
    )
    compact_fields = compact_logical["response"]["fields"]
    assert [field["name"] for field in compact_fields[1:8]] == [
        "prl", "rlq", "srl", "stripe_size", "num_drives", "span_depth", "state",
    ]
    assert "0x0f single disk" in compact_fields[1]["meaning"]
    assert "0x02 rotating-parity-N with data restart" in compact_fields[2]["meaning"]
    assert "0x03 spanned" in compact_fields[3]["meaning"]
    assert compact_logical["response"]["fields"][0]["meaning"] == (
        "(Size u64 × userDataBlockSize u16) >> 30, encoded u32le."
    )
    assert compact_logical["semantic_unresolved_reason"] is None
    assert compact_logical["semantic_evidence"]["prl_map"]["0x06"] == "RAID-6"
    assert compact_logical["semantic_evidence"]["rlq_map"]["0x03"] == (
        "rotating parity N with data continuation"
    )
    assert compact_logical["semantic_evidence"]["srl_map"]["0x03"] == "spanned"


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
    license_backend = rows["LicenseFileAction"]["semantic_evidence"]["license_backend"]
    assert license_backend["sha256"] == "3b1af6002ffaef53d61f1564be20b4c089427cee06161aaecf8cd947665feadf"
    assert "bit 4 first" in license_backend["mask_5_result"]
    assert "/usr/share/license_file/2" in license_backend["mask_5_result"]
    assert "LicenseID 1 to SFT-OOB-LIC" in license_backend["web_ui_evidence"]
    link_conf = rows["OEMSetGetLinkConf"]
    assert link_conf["semantic_unresolved_reason"] is None
    assert link_conf["semantic_evidence"]["capability_bit_map"] == {
        "0x01": "Auto negotiation",
        "0x08": "100M half-duplex",
        "0x10": "100M full-duplex",
        "0x40": "1G full-duplex",
    }
    assert link_conf["semantic_evidence"]["bmcweb_decoder"]["speed_groups"]["mask 0x18"] == "100M"
    assert rows["OEMGetSetSyslogInfo"]["safety_class"] == "read-only"


def test_x14_cm_provision_parent_disabled_and_child_census_closed():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14, X14_CATALOG

    command = SUPERMICRO_X14[(0x30, 0x68, 0x28)]
    assert not command["runnable"]
    assert command["safety"] == "destructive"
    child_commands = {
        key[3] for key in SUPERMICRO_X14
        if len(key) == 4 and key[:3] == (0x30, 0x68, 0x28)
    }
    implemented = {0, 1, 2, 3, *range(5, 11), 0x0F, 0x20, 0x21, 0x30,
                   0x54, 0x55, *range(0x84, 0x88), 0xDB, 0xFF}
    assert child_commands == implemented
    assert len(set(range(0x88)) - child_commands) == 116
    state = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x00)]
    assert state["dbus_endpoint"] == {
        "service": "xyz.openbmc_project.ProvisionManager",
        "path": "/xyz/openbmc_project/provision",
        "interface": "xyz.openbmc_project.provision.ProvisionManager",
    }
    assert state["dbus_calls_by_operand"] == {
        "absent": "getROTState", "0x01": "isProvisioning",
        "0x03": "clearProvisioning", "0x04": "doProvisioning",
    }
    assert "asynchronous provisioning workflow" in state["purpose"]
    assert "1 when provisioning starts and 0 when rejected/already active" in state["response_fields"][0]["meaning"]
    assert state["safety"] == "state-changing"
    assert "u32 big-endian" in state["purpose"]
    run = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x01)]
    assert "asynchronous provisioning workflow" in run["purpose"]
    assert "1 when the provisioning worker starts" in run["response_fields"][0]["meaning"]
    assert run["safety"] == "state-changing"
    summary = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x30)]
    assert summary["dbus_calls"] == [
        "getI2CMapProtection", "getBmcConsoleLockout", "getBmcJtagLockout",
        "getAttestValidation", "getROTState",
    ]
    assert summary["additional_dbus_endpoint"]["method"] == "readCPLDFeatbit"
    summary_meaning = summary["response_fields"][0]["meaning"]
    assert "bit 2" in summary_meaning and "bit 6" in summary_meaning
    assert "not included in this byte" in summary_meaning
    anti_rbid = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x08)]
    assert anti_rbid["request_length"] == (4, 4)
    assert anti_rbid["dbus_endpoint"]["method"] == "getAntiRBID"
    assert anti_rbid["response_fields"][0]["type"] == "u16be"
    assert "getUFMAntiRBID" in anti_rbid["purpose"]
    assert "No live request was sent" in anti_rbid["purpose"]
    inventory = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x06)]
    assert inventory["request_length"] == (4, 4)
    assert inventory["dbus_endpoint"]["method"] == "getFWInventory"
    assert "b+1" in inventory["purpose"]
    assert "packed-BCD" in inventory["response_fields"][0]["meaning"]
    assert "no public callback/vtable entry" in inventory["purpose"]
    task_status = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x07)]
    assert task_status["request_length"] == (3, 3)
    assert task_status["dbus_endpoint"]["method"] == "getBmcConsoleLockout"
    assert task_status["dbus_endpoint"]["provider_argument"] == "u8 a+4"
    assert task_status["additional_dbus_endpoint"]["method"] == "readCPLDFeatbit"
    assert "no arguments (int64 result)" in task_status["purpose"]
    assert "not live-tested" in task_status["purpose"]
    task_byte = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x02)]
    assert task_byte["dbus_endpoint"]["method"] == "getProvisioningTaskStatus"
    assert "optional operands a and b are ignored" in task_byte["purpose"]
    rot_register = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x09)]
    assert rot_register["dbus_endpoint"]["method"] == "readCpldReg"
    assert rot_register["request_length"] == (3, 4)
    assert "accepts any byte value, with no range check" in rot_register["purpose"]
    assert "register 8 bits 6/7" in rot_register["purpose"]
    validate = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x05)]
    assert validate["dbus_endpoint"]["method"] == "validateImage"
    assert "A=0 or 1 only when B<=2" in validate["purpose"]
    update_image = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x20)]
    assert update_image["dbus_endpoint"]["method"] == "upBackupGoldenImage"
    assert "selector 8 returns the raw boolean byte" in update_image["response_fields"][0]["meaning"]
    for subcommand, method in ((0x84, "isOTP"), (0x85, "clearRaProvision")):
        child = SUPERMICRO_X14[(0x30, 0x68, 0x28, subcommand)]
        assert child["request_length"] == (2, 4)
        assert child["dbus_endpoint"]["method"] == method
        assert "optional operands a and b are ignored" in child["purpose"]
        assert "one-byte D-Bus boolean" in child["response_fields"][0]["meaning"]
    read_file = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0xDB)]
    assert read_file["request_length"] == (2, 4)
    assert "zero-padding shorter, missing, or unreadable" in read_file["purpose"]
    assert "/usr/share/log/3068db.log" in read_file["purpose"]
    child = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x05)]
    assert [field["type"] for field in child["request_fields"][-2:]] == ["u8", "u8"]
    for subcommand in (0x07, 0x08):
        child = SUPERMICRO_X14[(0x30, 0x68, 0x28, subcommand)]
        assert child["response_fields"][0]["type"] == "u16be"
    for subcommand, method, field_name in (
        (0x86, "getOTPKey", "otp_key_bytes"),
        (0x87, "getOTPSerNum", "otp_serial_number_bytes"),
    ):
        child = SUPERMICRO_X14[(0x30, 0x68, 0x28, subcommand)]
        assert child["dbus_endpoint"]["method"] == method
        assert child["response_fields"][0]["name"] == field_name
        assert child["response_fields"][0]["type"] == ("bytes[9]" if subcommand == 0x86 else "bytes[remainder]")
        assert "no appended NUL" in child["response_fields"][0]["meaning"]
    cm_contract = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "OEMGetCMProvision"
    )
    for subcommand, method in (("0x86", "getOTPKey"), ("0x87", "getOTPSerNum")):
        assert cm_contract["semantic_evidence"]["resolved_child_calls"][subcommand]["method"] == method
        assert "no terminating NUL" in cm_contract["semantic_evidence"]["resolved_child_calls"][subcommand]["response"]
    assert "(operand_a << 8) | 0x20" in cm_contract["semantic_evidence"]["resolved_child_calls"]["0x86"]["backend"]
    assert "newline is retained" in cm_contract["semantic_evidence"]["resolved_child_calls"]["0x87"]["backend"].lower()
    anti_rbid_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x08"]
    assert anti_rbid_evidence["method"] == "getAntiRBID"
    assert anti_rbid_evidence["matching_daemon"]["exported_method"] == "getUFMAntiRBID"
    assert "not live-tested" in anti_rbid_evidence["matching_daemon"]["finding"]
    inventory_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x06"]
    assert inventory_evidence["method"] == "getFWInventory"
    assert "four packed-BCD bytes" in inventory_evidence["response"]
    assert "no matching public ProvisionManager callback" in inventory_evidence["matching_daemon"]["finding"]
    task_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x07"]
    assert task_evidence["accepted_request"] == "operand_a required and <=3; operand_b forbidden."
    assert task_evidence["calls"][0]["argument"] == "u8 operand_a+4"
    assert task_evidence["calls"][1]["method"] == "readCPLDFeatbit"
    assert "virtual int64_t SecurityManager::readCPLDFeatbit()" in task_evidence["security_manager_signature_status"]
    assert task_evidence["security_manager_daemon"]["sha256"] == "4c416258c84653cfe739bafc8d3e0a5ed38977dc4b5787621672524da6e3f4f7"
    assert "call signature and result width do not match" in task_evidence["security_manager_signature_status"]
    assert cm_contract["semantic_evidence"]["resolved_child_calls"]["0x02"]["signature"] == "() -> u"
    register_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x09"]
    assert register_evidence["method"] == "readCpldReg"
    assert "low byte" in register_evidence["response"]
    assert "registers a readCpldReg callback" in register_evidence["evidence_limit"]
    assert [entry["register"] for entry in register_evidence["known_register_uses"]] == [
        "0x00", "0x01", "0x08", "0x0a", "0x0b", "0x18",
    ]
    assert "three-second extended fan-delay workaround" in register_evidence["known_register_uses"][3]["meaning"]
    assert "individual bit meanings are unknown" in register_evidence["known_register_uses"][4]["meaning"]
    assert "not proven to use the readcpldreg d-bus backend" in register_evidence["known_register_uses"][5]["meaning"].casefold()
    assert register_evidence["known_register_uses"][3]["source_sha256"] == (
        "4d53b5241996979b2adfcec43c48eae85289d2bcd06aa88ed2abbf96d65c2e12"
    )
    assert "not a complete register map" in register_evidence["evidence_limit"]
    register_reader = register_evidence["register_read_backend"]
    assert register_reader["function_elf_va"] == "0x0005c8f4"
    assert register_reader["device"] == "/dev/spitee"
    assert register_reader["ioctl_request"] == "0xc0046b01"
    assert "returns signed -5" in register_reader["failure"]
    assert "direct code xref" in register_reader["identification"]
    assert cm_contract["semantic_evidence"]["resolved_child_calls"]["0x84"]["signature"] == "() -> b"
    assert cm_contract["semantic_evidence"]["resolved_child_calls"]["0x85"]["signature"] == "() -> b"
    file_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0xdb"]
    assert "zero-padding shorter, missing, or unreadable" in file_evidence["response"]
    assert file_evidence["path"] == "/usr/share/log/3068db.log"
    assert "0xee754" in file_evidence["finding"]
    assert "access() and read_binary_file()" in file_evidence["finding"]
    validate_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x05"]
    assert validate_evidence["provider_expected_signature"] == "u -> b"
    assert "A>=2 is rejected" in validate_evidence["provider_validation"]
    image_update_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x20"]
    assert image_update_evidence["provider_expected_signature"] == "u -> b"
    assert "Accepted A values are 0..3, 5, 8, and 9" in image_update_evidence["arguments"]
    assert "A=8 returns the raw boolean byte" in image_update_evidence["response"]
    assert cm_contract["semantic_evidence"]["resolved_child_calls"]["0x0a"]["response"] == "Fixed byte 0x01; no backend call."
    erase = SUPERMICRO_X14[(0x30, 0x68, 0x28, 0x21)]
    assert "not an erase-success indicator" in erase["response_fields"][0]["meaning"]
    assert "Properties.Set" in erase["purpose"] and "stagingBIOS" in erase["purpose"]
    erase_evidence = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x21"]
    assert erase_evidence["selector_targets"]["5"] == "BIOS Staging: /dev/mmcblk0p20"
    assert "not a reliable erase-success indicator" in erase_evidence["backend_result"]
    assert "stagingBIOS" in erase_evidence["bios_staging_side_effect"]
    assert "ne_implINS2_10bad_alloc_EEEEE" in erase_evidence["bios_staging_side_effect"]
    assert "0x4bba4" in erase_evidence["bios_staging_side_effect"]
    assert "true to 0x02 and false to 0x00" in erase_evidence["backend_result"]
    assert erase_evidence["provider_expected_signature"] == "u -> b"
    assert "absent A" in erase_evidence["provider_validation"]
    dboot_dump = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x0f"]
    assert "Operand B is ignored" in dboot_dump["operand_a_0"]
    assert "dumpDboot(B, 0)" in dboot_dump["operand_a_1"]
    assert "CpldUpdateMgrSvc/CpldDevice" in dboot_dump["backend"]
    assert dboot_dump["device_map"]["B=0"].endswith("Backplane_0_CPLD_0")
    assert dboot_dump["device_map"]["B=3"].endswith("AOMboard_1_CPLD_1")
    assert dboot_dump["device_map"]["B=5"].endswith("MidplaneSBB_CPLD_1")
    assert dboot_dump["device_map"]["B=9"].endswith("Fanboard_1_CPLD_1")
    assert "/tmp/cpld_flash_dump.bin" in dboot_dump["backend"]
    assert "addresses 0x0fff0, 0x1fff0, and 0x2fff0" in dboot_dump["backend"]
    assert "flags 0x241 (O_WRONLY|O_CREAT|O_TRUNC)" in dboot_dump["backend"]
    assert dboot_dump["matching_daemon"]["implementation"] == "MachXO2::dumpCpldDBoot at ELF VA 0x2d908"
    assert dboot_dump["matching_daemon"]["sha256"] == "5bfaf5db1d33bf7212d59b0775c28e4c517cb238a364b92d432315cd5aacf6ce"
    clear_cmos = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x54"]
    assert "restores the exact old register value" in clear_cmos["backend"]
    ac_cycle = cm_contract["semantic_evidence"]["resolved_child_calls"]["0x55"]
    assert "does not restore the previous register value" in ac_cycle["backend"]
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload
    _request, response = lookup_payload("supermicro-x14", 0x30, 0x68, b"\x28\x07\x00")
    assert response is not None
    decoded = decode_payload_response("supermicro-x14", 0x30, 0x68, b"\x28\x07\x00", 0, b"\x34\x12")
    assert decoded.result == 0x3412


def test_x14_cm_provision_validate_image_operands_match_target_guard():
    from zipmi.cli.oem_cmds import _valid_x14_cm_provision

    assert all(_valid_x14_cm_provision(0x05, bytes((a, b))) for a in (0, 1) for b in (0, 1, 2))
    assert not _valid_x14_cm_provision(0x05, b"\x00\x03")
    assert not _valid_x14_cm_provision(0x05, b"\x02\x00")
    assert not _valid_x14_cm_provision(0x05, b"\x00")
    assert all(_valid_x14_cm_provision(0x20, bytes((a,))) for a in (0, 1, 2, 3, 5, 8, 9))
    assert not any(_valid_x14_cm_provision(0x20, bytes((a,))) for a in (4, 6, 7, 10))


def test_x14_cm_provision_dboot_selector_matches_provider_device_map():
    from zipmi.cli.oem_cmds import _valid_x14_cm_provision

    assert _valid_x14_cm_provision(0x0F, b"\x00")
    assert _valid_x14_cm_provision(0x0F, b"\x00\xff")  # B is ignored for status query
    assert all(_valid_x14_cm_provision(0x0F, bytes((1, selector))) for selector in (0, 3, 5, 9))
    assert not any(_valid_x14_cm_provision(0x0F, bytes((1, selector))) for selector in (1, 2, 4, 6, 7, 8, 10, 255))
    assert not _valid_x14_cm_provision(0x0F, b"\x01")
    assert not _valid_x14_cm_provision(0x0F, b"\x02\x00")


def test_x14_ipv6_network_validator_matches_target_operation_lengths():
    from zipmi.cli.oem_cmds import _valid_x14_ipv6_network
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14, X14_CATALOG

    route = SUPERMICRO_X14[(0x30, 0x68, 0x09)]
    assert route["validator"] == "x14-ipv6-network"
    assert _valid_x14_ipv6_network(b"")
    assert all(_valid_x14_ipv6_network(bytes((0, query))) for query in range(5))
    assert not _valid_x14_ipv6_network(b"\x00")
    assert not _valid_x14_ipv6_network(b"\x00\x05")
    assert _valid_x14_ipv6_network(b"\x01" + bytes(20))
    assert not _valid_x14_ipv6_network(b"\x01" + bytes(19))
    assert _valid_x14_ipv6_network(b"\x02" + bytes(16))
    assert not _valid_x14_ipv6_network(b"\x02" + bytes(15))
    assert _valid_x14_ipv6_network(b"\x02\x02\x00\x00" + bytes(13))
    assert not _valid_x14_ipv6_network(b"\x02\x02\x01\x00" + bytes(13))
    assert not _valid_x14_ipv6_network(b"\x02\x03\x00\x00" + bytes(13))
    assert not _valid_x14_ipv6_network(b"\x02\x02\x02\x00" + bytes(13))
    assert not _valid_x14_ipv6_network(b"\x02\x02\x00\x02" + bytes(13))
    assert not _valid_x14_ipv6_network(b"\x03")
    contract = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "OEMCGetSetIPV6Network"
    )
    queries = contract["semantic_evidence"]["resolved_queries"]
    assert "16 network-order address bytes plus one zero byte" in queries["4"]
    assert "decimal prefix byte" in queries["2"]
    assert "parses it base 16" in queries["3"]
    assert contract["semantic_unresolved_reason"] is None
    setter = contract["semantic_evidence"]["resolved_setter_prefix"]["operation_2"]
    assert "13-byte vector" in setter and "out-of-bounds index 16" in setter
    helper = contract["semantic_evidence"]["setter_helper_behavior"]["translateIpv6ToStr"]
    assert "memset zeroes only vector.size() bytes" in helper
    assert "final three inet_ntop input bytes" in helper and "uninitialized" in helper


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
    request, _response = lookup_payload("supermicro-x14", 0x30, 0x70, b"\x02")
    assert bytes(request()) == b"\x02"
    decoded = decode_payload_response("supermicro-x14", 0x30, 0x70, b"\x02", 0, b"\x01")
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
    assert sent == [(0x30, 0x70, b"\x02")]

    no_op = argparse.Namespace(
        cmd_name="BIOSSetTimertoTriggerPowerOn", data=["0"], unsafe=False, json=False,
    )
    assert cmd_oem_run(no_op, "supermicro-x14") == 0
    assert sent[-1] == (0x30, 0x70, b"\x55\x00")

    mutating = argparse.Namespace(cmd_name="ClearChassisIntrusion", data=[], unsafe=False, json=False)
    assert cmd_oem_run(mutating, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err

    cot = argparse.Namespace(cmd_name="OEMRequestCOT", data=["1", "0"], unsafe=False, json=False)
    assert cmd_oem_run(cot, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err
    assert sent[-1] == (0x30, 0x70, b"\x55\x00")
    cot.unsafe = True
    assert cmd_oem_run(cot, "supermicro-x14") == 0
    assert sent[-1] == (0x30, 0x68, b"\x2d\x01\x00")

    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14, X14_CATALOG
    unsafe_handlers = {
        "OEMGetSetLANMode", "SetSystemEventFlag", "FakeSensorData",
        "OEMSetGetACPowerOn",
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
    assert len(sent) == 3
    assert sent[1] == (0x30, 0x70, b"\x55\x00")
    assert sent[2] == (0x30, 0x68, b"\x2d\x01\x00")

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

    bad_nvme_page = argparse.Namespace(
        cmd_name="OEMGetSetNVMeSSDParameters",
        data=["0", "0", "0", "1", "0", "216", "1"],
        unsafe=True, json=False,
    )
    assert cmd_oem_run(bad_nvme_page, "supermicro-x14") == 2
    assert "page_offset must be at most 215" in capsys.readouterr().err

    good_nvme_page = argparse.Namespace(
        cmd_name="OEMGetSetNVMeSSDParameters",
        data=["0", "0", "0", "1", "0", "215", "1"],
        unsafe=True, json=False,
    )
    assert cmd_oem_run(good_nvme_page, "supermicro-x14") == 0
    assert sent[-1] == (0x30, 0x70, b"\x6c\x00\x00\x00\x01\x00\xd7\x01")

    good_asset = argparse.Namespace(
        cmd_name="Set Asset Tag", data=["0", "2", "0x41", "0x42"], unsafe=True, json=False,
    )
    assert cmd_oem_run(good_asset, "supermicro-x14") == 0
    assert sent[-1] == (0x2C, 0x08, b"\xdc\x00\x02AB")

    clear_cmos = argparse.Namespace(cmd_name="Clear CMOS", data=[], unsafe=False, json=False)
    assert cmd_oem_run(clear_cmos, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err

    invalid_task = argparse.Namespace(
        cmd_name="Read Lockout-Gated RoT CPLD Feature Bits", data=["4"], unsafe=False, json=False,
    )
    assert cmd_oem_run(invalid_task, "supermicro-x14") == 2
    assert "recovered provisioning subcommand contract" in capsys.readouterr().err
    assert len(sent) == 5

    feature_bits = argparse.Namespace(
        cmd_name="Read Lockout-Gated RoT CPLD Feature Bits", data=["3"], unsafe=True, json=False,
    )
    assert cmd_oem_run(feature_bits, "supermicro-x14") == 0
    assert sent[-1] == (0x30, 0x68, b"\x28\x07\x03")

    clear_ra = argparse.Namespace(cmd_name="Clear RA Provisioning", data=[], unsafe=False, json=False)
    assert cmd_oem_run(clear_ra, "supermicro-x14") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_x14_link_configuration_route_is_read_only_and_needs_no_unsafe(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    route = SUPERMICRO_X14[(0x30, 0x70, 0x63)]
    assert route["safety"] == "read-only"
    assert route["runnable"]
    args = argparse.Namespace(cmd_name=route["name"], data=["1"], unsafe=False, json=False)
    assert cmd_oem_run(args, "supermicro-x14") == 0
    assert sent == [(0x30, 0x70, b"\x63\x01")]


def test_x14_bbp_validator_route_is_read_only_and_needs_no_unsafe(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run
    from zipmi.scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    route = SUPERMICRO_X14[(0x30, 0x68, 0x13)]
    assert route["safety"] == "read-only"
    args = argparse.Namespace(cmd_name=route["name"], data=["1", "0", "0"], unsafe=False, json=False)
    assert cmd_oem_run(args, "supermicro-x14") == 0
    assert sent == [(0x30, 0x68, b"\x13\x01\x00\x00")]


def test_x14_every_advertised_exact_name_resolves_to_its_wire_key():
    from zipmi.cli.oem_cmds import _find_cmd, _vendor_listing

    listing = _vendor_listing("supermicro-x14")
    for key, command in listing.items():
        assert _find_cmd(listing, command["name"]) == [(key, command)]


def test_x14_add_delete_user_request_split_and_enable_semantics():
    from zipmi.scapy_ipmi.oem.supermicro_x14 import X14_CATALOG

    user = next(
        row for row in X14_CATALOG["primary"]["operations"]
        if row["handler"] == "OEMAddDelUser"
    )
    fields = user["request"]["fields"]
    assert [(field["name"], field["offset"]) for field in fields] == [
        ("selector", 0), ("operation", 1), ("user_slot", 2),
        ("username_length", 3), ("password_length", 4),
        ("base64_credentials", 5),
    ]
    assert user["request"]["minimum_bytes_including_selector"] == 3
    assert user["response"]["maximum_bytes"] == 0
    assert user["response"]["fields"] == []
    assert "enabled state to true" in user["effects"]
    assert "MEL event 0x15" in user["effects"] and "MEL event 0x16" in user["effects"]
    assert "does not accept a separate enable byte" in fields[-1]["meaning"]
    assert user["semantic_unresolved_reason"] is None
    assert "first ASCII 'G'" in user["effects"]
    assert "empty slot" in user["effects"]
