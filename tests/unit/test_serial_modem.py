"""
test_serial_modem.py — Get/Set Serial/Modem Config enumeration + write primitive.

Byte-exact request assertions and ASCII rendering of the string params (dial/init
numbers live there).
"""
from __future__ import annotations

from zipmi.cli.serial_modem import (
    get_serial_param, serial_config_sweep, set_serial_param,
    build_set_string_param, SERIAL_PARAM,
)


class _Fake:
    """Answers Get Serial/Modem Config (0x0C/0x11) per param; records writes."""
    def __init__(self):
        self.sent = []

    def send_raw(self, netfn, cmd, data):
        self.sent.append((netfn, cmd, bytes(data)))
        if (netfn, cmd) == (0x0C, 0x11):                 # Get: [ch, param, ss, bs]
            param = data[1]
            body = {
                3:  bytes([0x02]),                        # connection mode (PPP)
                10: b"ATZ",                               # modem init string
                13: b"ATDT18005551234",                   # dial command w/ number
            }.get(param)
            if body is None:
                return 0xC9, b""                          # unsupported param
            return 0x00, bytes([0x11]) + body             # [param-rev] + config
        if (netfn, cmd) == (0x0C, 0x10):                  # Set
            return 0x00, b""
        raise AssertionError((netfn, cmd))


def test_get_serial_param_strips_revision():
    assert get_serial_param(_Fake(), 2, 13) == b"ATDT18005551234"


def test_get_serial_param_none_on_unsupported():
    assert get_serial_param(_Fake(), 2, 99) is None


def test_sweep_collects_and_renders_ascii():
    rows = serial_config_sweep(_Fake(), 2, params=[3, 10, 13, 99])
    by_param = {r["param"]: r for r in rows}
    assert 99 not in by_param                             # unsupported skipped
    assert by_param[3]["name"] == "connection_mode"
    assert by_param[3]["raw"] == "02"
    assert by_param[10]["ascii"] == "ATZ"                 # init string decoded
    assert by_param[13]["ascii"] == "ATDT18005551234"     # the dial number!


def test_sweep_issued_get_requests_byte_exact():
    f = _Fake()
    serial_config_sweep(f, 2, params=[13])
    assert f.sent == [(0x0C, 0x11, bytes([0x02, 0x0D, 0x00, 0x00]))]  # ch2, param13


def test_set_serial_param_byte_exact():
    f = _Fake()
    cc, _ = set_serial_param(f, 2, 3, b"\x02")
    assert cc == 0x00
    assert f.sent == [(0x0C, 0x10, bytes([0x02, 0x03, 0x02]))]        # ch2 param3 data


def test_build_set_string_param_layout():
    # write a destination dial number into param 13, block 0
    req = build_set_string_param(2, 13, 0, b"ATDT19998887777")
    assert req == bytes([0x02, 0x0D, 0x00]) + b"ATDT19998887777"
    # text is truncated to a 16-byte block
    assert len(build_set_string_param(0, 10, 0, b"A" * 40)) == 3 + 16


# --- CLI: read verb parses; write verb is --yes-gated and byte-exact ---------
import argparse
import zipmi.cli.zipmi as _z


class _EffSession:
    def __init__(self): self.sent = []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def send_raw(self, netfn, cmd, data):
        self.sent.append((netfn, cmd, bytes(data))); return 0x00, b""


def test_serial_config_parses():
    ns = _z.parse_cli(["serial", "config", "2", "--json"])
    assert ns.func.__name__ == "cmd_serial_config"
    assert ns.channel == 2 and ns.json is True


def test_serial_set_requires_yes_blocks_write(monkeypatch):
    def _boom(_a): raise AssertionError("_open_session called — write not gated!")
    monkeypatch.setattr(_z, "_open_session", _boom)
    ns = _z.parse_cli(["serial", "set", "2", "13", "415454"])   # no --yes
    assert _z.cmd_serial_set(ns) == 2                            # refused, no write


def test_serial_set_with_yes_writes_exact_bytes(monkeypatch):
    fake = _EffSession()
    monkeypatch.setattr(_z, "_open_session", lambda _a: fake)
    ns = _z.parse_cli(["serial", "set", "2", "13", "415454"])   # param 13, "ATT" hex
    ns.yes = True
    assert _z.cmd_serial_set(ns) == 0
    # Set Serial/Modem Config (0x0C/0x10): [ch=2, param=13] + data
    assert fake.sent == [(0x0C, 0x10, bytes([0x02, 0x0D]) + bytes.fromhex("415454"))]


class _DialFake:
    """Returns the dial-out params: init(10), dial cmd(13), phone number(21)."""
    def send_raw(self, netfn, cmd, data):
        if (netfn, cmd) == (0x0C, 0x11):
            param = data[1]
            body = {10: b"ATE0", 13: b"ATDT", 21: b"18005551234"}.get(param)
            return (0x00, bytes([0x11]) + body) if body else (0xC9, b"")
        raise AssertionError


def test_param_21_is_the_phone_number_and_labeled():
    # param 21 = Destination Dial String — the number the BMC dials (freeipmi
    # _DESTINATION_DIAL_STRINGS / ipmiutil iserial.c:261, 33-byte field).
    assert SERIAL_PARAM[21] == "destination_dial_strings"
    assert 21 in __import__("zipmi.cli.serial_modem", fromlist=["_ASCII_PARAMS"])._ASCII_PARAMS
    rows = serial_config_sweep(_DialFake(), 2, params=[10, 13, 21])
    by = {r["param"]: r for r in rows}
    assert by[21]["name"] == "destination_dial_strings"
    assert by[21]["ascii"] == "18005551234"        # decoded phone number
    assert by[13]["ascii"] == "ATDT"


def test_param_5_labeled_channel_callback_control():
    assert SERIAL_PARAM[5] == "channel_callback_control"
