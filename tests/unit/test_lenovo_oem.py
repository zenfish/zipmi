"""Lenovo XCC static OEM catalog and exact request-prefix contracts."""
from __future__ import annotations


def test_lenovo_catalog_preserves_both_dispatch_layers():
    from zipmi.scapy_ipmi.oem.lenovo import LENOVO_COMMANDS
    assert len(LENOVO_COMMANDS) == 222
    assert sum(len(c.registrations) for c in LENOVO_COMMANDS) == 192
    assert sum(c.dispatch.startswith("legacy") for c in LENOVO_COMMANDS) == 56
    assert len({(c.netfn, c.cmd, c.prefix) for c in LENOVO_COMMANDS}) == 222


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
    assert len(listing) == 217
    assert listing[(0x2E, 0x80, 0x66, 0x4A, 0x00)]["prefix"] == bytes.fromhex("66 4a 00")


def test_lenovo_codegen_is_idempotent():
    from pathlib import Path
    from zipmi.parsers.lenovo_commands_json import emit_module, parse_json
    source = Path("zipmi/data/sources/lenovo-xcc-commands.json")
    generated = Path("zipmi/scapy_ipmi/oem/lenovo_commands_generated.py")
    assert emit_module(parse_json(source.read_text()), source.name) == generated.read_text()


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
    args = argparse.Namespace(cmd_name="XCCBmcEmerson_2E_80_66_4A_00", data=["0x99"], json=True)
    assert cmd_oem_run(args, "lenovo") == 0
    assert session.sent == [(0x2E, 0x80, bytes.fromhex("66 4a 00 99"))]


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

    assert sum(len(c.operations) for c in LENOVO_COMMANDS) == 198
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
