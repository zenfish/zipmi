"""
test_bridge.py — Send Message (0x34) encapsulation + bridge detection.

Byte-exact assertions on the IPMB encapsulation (checksums derived by hand from
IPMI 2.0 §22.7 / IPMB spec), and completion-code interpretation of the probe.
"""
from __future__ import annotations

from zipmi.cli.bridge import (
    encapsulate_ipmb, build_send_message, probe_bridge, _csum,
)


def test_csum_is_twos_complement():
    # sum(data)+csum ≡ 0 (mod 256)
    for d in (b"\x20\x18", b"\x81\x00\x01", b"\xff\xff\x01"):
        assert (sum(d) + _csum(d)) & 0xFF == 0


def test_encapsulate_get_device_id_bytes():
    # Get Device ID (App 0x06 / 0x01), no data, to BMC 0x20 from SW 0x81 seq 0.
    #   rsSA=20 netfn/lun=(6<<2)=18 csum1=c8 | rqSA=81 seq/lun=00 cmd=01 csum2=7e
    enc = encapsulate_ipmb(0x06, 0x01)
    assert enc == bytes.fromhex("2018c88100017e")
    # both checksums self-verify
    assert (0x20 + 0x18 + enc[2]) & 0xFF == 0
    assert (0x81 + 0x00 + 0x01 + enc[6]) & 0xFF == 0


def test_encapsulate_with_data_and_netfn():
    # Chassis (0x00) Control (0x02) with 1 data byte 0x01, to 0x20 from 0x81.
    #   netfn/lun = 0<<2 = 00; csum1 = -(20+00)=e0
    enc = encapsulate_ipmb(0x00, 0x02, b"\x01")
    assert enc[0] == 0x20 and enc[1] == 0x00 and enc[2] == 0xE0
    assert enc[3] == 0x81 and enc[5] == 0x02 and enc[6] == 0x01
    assert (sum(enc[3:7]) + enc[7]) & 0xFF == 0        # csum2 over rqSA..data


def test_build_send_message_channel_and_tracking_byte():
    # track-request (01b) on channel 0 → 0x40; on channel 1 → 0x41
    m0 = build_send_message(0, 0x06, 0x01)
    assert m0 == bytes.fromhex("40") + bytes.fromhex("2018c88100017e")
    m1 = build_send_message(1, 0x06, 0x01)
    assert m1[0] == 0x41
    # encrypt+auth bits set → 0b01_11_0000 | ch = 0x70
    assert build_send_message(0, 0x06, 0x01, encrypt=True, auth=True)[0] == 0x70


class _FakeSession:
    def __init__(self, cc):
        self.cc = cc
        self.sent = []

    def send_raw(self, netfn, cmd, data):
        self.sent.append((netfn, cmd, bytes(data)))
        return self.cc, b""


def test_probe_bridge_accepted():
    s = _FakeSession(0x00)
    r = probe_bridge(s, 0)
    assert r["supported"] and r["bridgeable"]
    # it actually issued Send Message (0x34) wrapping Get Device ID onto ch0
    assert s.sent == [(0x06, 0x34, bytes.fromhex("402018c88100017e"))]


def test_probe_bridge_unsupported_on_c1():
    r = probe_bridge(_FakeSession(0xC1), 0)
    assert r["supported"] is False and r["bridgeable"] is False


def test_probe_bridge_rejected_other_cc():
    r = probe_bridge(_FakeSession(0x83), 2)     # some channel-specific reject
    assert r["supported"] is True and r["bridgeable"] is False
    assert r["cc"] == 0x83
