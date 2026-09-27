"""Lenovo XCC static OEM catalog and exact request-prefix contracts."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def test_lenovo_reference_uses_shared_standard_without_losing_inventory():
    root = Path(__file__).parents[2]
    subprocess.run(
        [sys.executable, "scripts/generate_lenovo_xcc_reference.py", "--check"],
        cwd=root, check=True,
    )
    reference = (root / "docs/lenovo-xcc-command-reference.html").read_text()
    assert '<link rel="stylesheet" href="assets/oem-command-reference.css">' in reference
    assert "<style" not in reference
    assert "210</strong>Unique NetFn/Cmd addresses" in reference
    assert "335</strong>Documented operations" in reference
    assert "66 / 222 / 46 / 1</strong>Request layout:" in reference
    assert "60 / 225 / 49 / 1</strong>Response layout:" in reference
    assert "63 / 224 / 48</strong>Named operation route:" in reference
    assert "35</strong>Operations with captured live requests" in reference
    assert reference.count('<tr data-search="') == 335
    assert reference.count('data-live="true"') == 35
    assert reference.count('<details class="evidence"><summary>Recovered from</summary>') == 335
    assert "document.createTreeWalker" in reference
    assert ".classList.toggle('is-floating',floating)" in reference
    assert 'role="scrollbar"' in reference
    assert {name: reference.count(f'data-safety="{name}"') for name in (
        "read-only", "sensitive", "state-changing", "disruptive", "destructive", "unknown",
    )} == {
        "read-only": 97, "sensitive": 17, "state-changing": 115,
        "disruptive": 14, "destructive": 7, "unknown": 85,
    }
    assert "Top-level identity inventory" not in reference
    assert "225 prefix-qualified identities" in reference
    assert "185 catalog-only decoded operations" in reference
    assert "43 identities whose leaf payload is not yet decoded" in reference
    assert "Not available through zipmi over LAN" in reference
    assert "bbe82df6-3df8-4103-8612-72b359a7fdda" not in reference
    assert "<!-- z-artifact: 80a0113f-275b-40ea-9f28-089ba1ac988e generated -->" in reference
    assert re.search(r'data-safety="destructive"[^>]*>.*?<strong>secure erase</strong>', reference)
    assert re.search(r'data-safety="destructive"[^>]*>.*?<strong>management-engine update control</strong>', reference)
    assert re.search(r'data-safety="destructive"[^>]*>.*?<strong>secured datastore delete</strong>', reference)
    assert re.search(r'data-safety="sensitive"[^>]*>.*?<strong>private account enable/query</strong>', reference)
    assert re.search(r'data-safety="sensitive"[^>]*>.*?<strong>BMU credentials get</strong>', reference)
    assert "zipmi oem lenovo --unsafe &#x27;LAN Logical Package Priority Set&#x27; &lt;channel:u8&gt; 0xd4 &lt;at least 1 data bytes&gt;" in reference
    assert "zipmi oem lenovo --unsafe &#x27;LAN Test NCSI Mapping Set&#x27; &lt;channel:u8&gt; 0xd8 &lt;additional data bytes&gt;" in reference
    assert "zipmi raw 0x3a 0xf7 0x00 &lt;remaining operation payload bytes&gt;" in reference

    reset_at = reference.index("Reset XCC to Default")
    reset_row = reference[reset_at:reference.index('<tr data-search="', reset_at)]
    assert "zipmi oem lenovo --unsafe &#x27;Reset XCC to Default&#x27;" in reset_row
    assert "exact magic request 5e 2b 00 0a 01 ff 00 00 00" in reset_row
    assert "this firmware accepted the reset from a User-privilege LAN session" in reset_row
    assert "firmware identity XCCCmdOSAOEMCmdHandler_2E_CC_5E_2B_00" in reset_row
    assert "Must be 0x5e" in reset_row and "Must be 0xff" in reset_row
    assert re.search(r"zipmi oem lenovo &#x27;Firmware Version&#x27;", reference)
    assert "2aaedcb6c5939efabd49ac4da0a8066e17c5c3dea356ad33ad0d9246c4b192c2" in reference
    assert "b72294cd8a10699e2cd3827dd1b4aa0a13943c483332af0ceae8ba603cf17485" in reference


def test_lenovo_catalog_preserves_both_dispatch_layers():
    from zipmi.scapy_ipmi.oem.lenovo import LENOVO_COMMANDS
    assert len(LENOVO_COMMANDS) == 225
    assert sum(len(c.registrations) for c in LENOVO_COMMANDS) == 192
    assert sum(c.dispatch.startswith("legacy") for c in LENOVO_COMMANDS) == 56
    assert len({(c.netfn, c.cmd, c.prefix) for c in LENOVO_COMMANDS}) == 225


def test_lenovo_parser_cast_recoveries_are_present():
    from zipmi.scapy_ipmi.oem.lenovo import lookup
    assert ("libcore.so", "initialize@001114b8") in lookup(0x3A, 0x32).registrations
    assert ("libmod_rf_usb.so.0.0.0", "initialize@00024fa8") in lookup(0x3A, 0xCE).registrations


def test_lenovo_catalog_exposes_exact_decoded_handlers():
    from zipmi.scapy_ipmi.oem.lenovo import lookup
    assert lookup(0x3A, 0x0D).handler.startswith("board_info_device::get_board_info")
    assert lookup(0x3A, 0x0D).side_effect == "likely-read-only"
    assert lookup(0x3A, 0xC3).handler.startswith("bios_device::ipmi_bios_state")
    assert lookup(0x3A, 0xC4).handler.startswith("properties_device::property_cmd")
    assert lookup(0x2E, 0x90, bytes.fromhex("66 4a 00")).handler.startswith(
        "planar_controller::datastore_access"
    )


def test_lenovo_group_extension_prefix_is_wire_little_endian():
    from zipmi.scapy_ipmi.oem.lenovo import lookup
    command = lookup(0x2E, 0x80, bytes.fromhex("66 4a 00"))
    assert command is not None
    assert command.iana == 0x4A66
    assert command.runnable


def test_xcc_device_manufacturer_is_ibm_pen():
    from zipmi.consts import IANA
    from zipmi.scapy_ipmi.oem.lenovo import LENOVO_DEVICE_IANA, LENOVO_GROUP_IANA
    assert LENOVO_DEVICE_IANA == 2 and IANA[2] == "IBM"
    assert LENOVO_GROUP_IANA == 0x4A66


def test_lenovo_vendor_load_and_listing():
    import zipmi
    zipmi.load_vendor("xcc")
    from zipmi.cli.oem_cmds import _vendor_listing
    from zipmi.scapy_ipmi.oem._registry import ENTERPRISE_IDS
    listing = _vendor_listing("lenovo")
    assert ENTERPRISE_IDS[2] in ("lenovo", "openpower")  # Shared IBM PEN.
    assert len(listing) == 307
    assert listing[(0x2E, 0x80, 0x66, 0x4A, 0x00)]["prefix"] == bytes.fromhex("66 4a 00")


def test_lenovo_codegen_is_idempotent():
    from pathlib import Path
    from zipmi.parsers.lenovo_commands_json import emit_module, parse_contract_json, parse_json
    source = Path("zipmi/data/sources/lenovo-xcc-commands.json")
    contracts = Path("zipmi/data/sources/lenovo-xcc-operation-contracts.json")
    generated = Path("zipmi/scapy_ipmi/oem/lenovo_commands_generated.py")
    assert emit_module(
        parse_json(source.read_text()), source.name,
        parse_contract_json(contracts.read_text()),
    ) == generated.read_text()


def test_lenovo_official_contracts_add_missing_native_nm_and_codecs():
    import zipmi
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload
    from zipmi.scapy_ipmi.oem.lenovo import LENOVO_CONTRACTS, LENOVO_PAYLOADS

    zipmi.load_vendor("lenovo")
    assert len(LENOVO_CONTRACTS) == 107
    assert any((c.netfn, c.cmd) == (0x3A, 0xC7) for c in LENOVO_CONTRACTS)
    assert (0x3A, 0x0D) in LENOVO_PAYLOADS
    request_type, response_type = lookup_payload("lenovo", 0x3A, 0x0D, b"")
    assert bytes(request_type()) == b""
    decoded = decode_payload_response("lenovo", 0x3A, 0x0D, b"", 0, b"\x12\x34")
    assert response_type is not None
    assert (decoded.completion_code, decoded.system_id, decoded.board_revision) == (0, 0x12, 0x34)

    request_type, response_type = lookup_payload(
        "lenovo", 0x0C, 0x02, bytes.fromhex("01 c7 00 00"),
    )
    assert bytes(request_type(channel=1)) == bytes.fromhex("01 c7 00 00")
    decoded = decode_payload_response(
        "lenovo", 0x0C, 0x02, bytes.fromhex("01 c7 00 00"), 0,
        bytes.fromhex("11 02 00 00 00 00 01"),
    )
    assert response_type is not None
    assert (decoded.revision, decoded.mac) == (0x11, bytes.fromhex("02 00 00 00 00 01"))

    request_type, response_type = lookup_payload(
        "lenovo", 0x0C, 0x02, bytes.fromhex("01 d2 00 00"),
    )
    assert bytes(request_type(channel=1)) == bytes.fromhex("01 d2 00 00")
    decoded = decode_payload_response(
        "lenovo", 0x0C, 0x02, bytes.fromhex("01 d2 00 00"), 0,
        bytes.fromhex("11 7f"),
    )
    assert response_type is not None
    assert (decoded.revision, decoded.value) == (0x11, 0x7F)


def test_lenovo_contract_named_execution_supplies_exact_magic(monkeypatch):
    import argparse
    import zipmi.cli.zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    class Session:
        sent = []
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def send_raw(self, netfn, cmd, data):
            self.sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    session = Session()
    monkeypatch.setattr(cli, "_open_session", lambda _args: session)
    args = argparse.Namespace(cmd_name="Reset XCC to Default", data=[], json=True, unsafe=True)
    assert cmd_oem_run(args, "lenovo") == 0
    assert session.sent == [(0x2E, 0xCC, bytes.fromhex("5e 2b 00 0a 01 ff 00 00 00"))]


def test_lenovo_named_command_sends_exact_group_prefix(monkeypatch):
    import argparse
    import zipmi.cli.zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    class Session:
        sent = []
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def send_raw(self, netfn, cmd, data):
            self.sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    session = Session()
    monkeypatch.setattr(cli, "_open_session", lambda _args: session)
    args = argparse.Namespace(
        cmd_name="XCCBmcEmerson_2E_80_66_4A_00", data=["0x99"], json=True,
        unsafe=True,
    )
    assert cmd_oem_run(args, "lenovo") == 0
    assert session.sent == [(0x2E, 0x80, bytes.fromhex("66 4a 00 99"))]


def test_lenovo_named_execution_is_fail_closed(monkeypatch, capsys):
    import argparse
    import zipmi.cli.zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    monkeypatch.setattr(cli, "_open_session", lambda _args: None)
    unsafe = argparse.Namespace(
        cmd_name="XCCReset_3A_38", data=["0x01"], json=True, unsafe=False,
    )
    assert cmd_oem_run(unsafe, "lenovo") == 2
    assert "--unsafe" in capsys.readouterr().err

    wrong_length = argparse.Namespace(
        cmd_name="XCCModules_3A_0D", data=["0x00"], json=True, unsafe=False,
    )
    assert cmd_oem_run(wrong_length, "lenovo") == 2
    assert "accepts at most 0 payload bytes" in capsys.readouterr().err


def test_lenovo_group_prefix_is_excluded_from_body_length(monkeypatch):
    import argparse
    import zipmi.cli.zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    class Session:
        sent = []
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def send_raw(self, netfn, cmd, data):
            self.sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    session = Session()
    monkeypatch.setattr(cli, "_open_session", lambda _args: session)
    args = argparse.Namespace(
        cmd_name="XCCModules_2E_30_D0_51_00", data=[], json=True, unsafe=True,
    )
    assert cmd_oem_run(args, "lenovo") == 0
    assert session.sent == [(0x2E, 0x30, bytes.fromhex("d0 51 00"))]


def test_lenovo_decoded_operation_contracts_are_structured():
    from zipmi.scapy_ipmi.oem.lenovo import lookup

    board = lookup(0x3A, 0x0D).operations
    assert len(board) == 1
    assert board[0].operation == "board information"
    assert board[0].request == "empty"
    assert board[0].response.startswith("2 bytes")

    bmu = lookup(0x3A, 0x7A).operations
    assert [(o.selector, o.effect) for o in bmu] == [
        ("00", "read"), ("01", "state change")]

    credentials = lookup(0x3A, 0x7B).operations
    assert len(credentials) == 2
    assert all("system-interface channel only" in o.request for o in credentials)

    inventory = lookup(0x3A, 0xA4).operations
    assert inventory[0].request == "empty"
    assert inventory[1].selector == "any-byte"
    assert inventory[1].effect == "runtime state change"


def test_lenovo_group_command_operation_preserves_wire_prefix():
    from zipmi.scapy_ipmi.oem.lenovo import lookup

    led = lookup(0x2E, 0x0C, bytes.fromhex("d0 51 00"))
    assert led.prefix == bytes.fromhex("d0 51 00")
    assert led.operations[0].operation == "LED get"
    assert "IANA d0 51 00" in led.operations[0].request


def test_lenovo_json_listing_exposes_decoded_operations():
    from zipmi.cli.oem_cmds import _vendor_listing_data

    listing = _vendor_listing_data("lenovo")
    board = next(c for c in listing["commands"] if c["netfn"] == 0x3A and c["cmd"] == 0x0D)
    assert board["operations"] == [{
        "selector": "", "operation": "board information", "request": "empty",
        "response": "2 bytes: system revision and board level",
        "completionCodes": "", "effect": "read", "evidence": "Decoded",
        "source": "libmodules.so:get_board_info@000e87e4",
    }]


def test_lenovo_second_tranche_and_live_evidence_are_exposed():
    from zipmi.cli.oem_cmds import _vendor_listing_data
    from zipmi.scapy_ipmi.oem.lenovo import LENOVO_COMMANDS, lookup

    assert sum(len(c.operations) for c in LENOVO_COMMANDS) == 201
    assert sum(bool(c.registrations) for c in LENOVO_COMMANDS) == 166
    assert all(c.operations for c in LENOVO_COMMANDS if c.registrations)
    assert len(lookup(0x3A, 0xC4).operations) == 8
    assert len(lookup(0x2E, 0x90, bytes.fromhex("66 4a 00")).operations) == 10
    assert lookup(0x2E, 0x90, bytes.fromhex("4d 4f 00")).operations[0].operation == \
        "datastore protocol alias"
    assert lookup(0x3A, 0x30).operations[0].response == "1 byte: ec"

    assert lookup(0x3A, 0x00).live_evidence["responseHex"] == "0692"
    assert lookup(0x3A, 0x6C).live_evidence["completionCode"] == 0xCE
    listing = _vendor_listing_data("lenovo")
    firmware = next(c for c in listing["commands"] if c["netfn"] == 0x3A and c["cmd"] == 0x00)
    assert firmware["liveEvidence"]["responseHex"] == "0692"
