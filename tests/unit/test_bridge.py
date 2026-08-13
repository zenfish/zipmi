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


# === multi-hop nesting, reply parse, round-trip confirm ==================

from zipmi.cli import bridge as _b   # noqa: E402


def test_single_hop_equals_send_message():
    """One-hop path is exactly a plain Send Message — no extra wrapping."""
    assert _b.build_bridged_request([0x00], 0x06, 0x01) == build_send_message(0x00, 0x06, 0x01)


def test_two_hop_wraps_inner_send_message():
    """[a,b] == SM(a, 0x34, SM(b, real)); outer IPMB command byte is 0x34."""
    inner = build_send_message(0x02, 0x06, 0x01)
    expected = build_send_message(0x00, 0x06, 0x34, inner)
    got = _b.build_bridged_request([0x00, 0x02], 0x06, 0x01)
    assert got == expected
    assert got[6] == 0x34            # IPMB payload command == Send Message


def test_three_hop_folds_inside_out():
    """Deepest nested command is still the real 0x01 (Get Device ID)."""
    l1 = build_send_message(0x06, 0x06, 0x01)
    l2 = build_send_message(0x02, 0x06, 0x34, l1)
    l3 = build_send_message(0x00, 0x06, 0x34, l2)
    assert _b.build_bridged_request([0x00, 0x02, 0x06], 0x06, 0x01) == l3


def test_empty_path_rejected():
    import pytest
    with pytest.raises(ValueError):
        _b.build_bridged_request([], 0x06, 0x01)


def _ipmb_reply(cmd: int, cc: int, data: bytes = b"") -> bytes:
    """Minimal IPMB response: rqAddr, netfn/lun, csum1, rsAddr, seq/lun, cmd, cc,
    data..., csum2 (checksums are not validated by the parser)."""
    return bytes([0x81, 0x1C, 0x00, 0x20, 0x00, cmd, cc]) + data + bytes([0x00])


def test_parse_extracts_cmd_and_cc():
    assert _b.parse_encapsulated_reply(_ipmb_reply(0x01, 0x00, b"\x11\x22")) == (0x01, 0x00, b"\x11\x22")


def test_parse_too_short_is_none():
    assert _b.parse_encapsulated_reply(b"\x01\x02\x03") is None


def test_unwrap_plain_reply_returns_far_cc():
    assert _b._unwrap_far_cc(_ipmb_reply(0x01, 0x00, b"\xaa" * 11)) == 0x00
    assert _b._unwrap_far_cc(_ipmb_reply(0x01, 0xC7)) == 0xC7


def test_unwrap_peels_nested_send_message():
    """Nested SM(0x34)=0x00 wrapping a far reply must peel to the INNER cc."""
    outer = _ipmb_reply(0x34, 0x00, _ipmb_reply(0x01, 0xCC))
    assert _b._unwrap_far_cc(outer) == 0xCC


class _ScriptSession:
    """Replays scripted (cc, data) keyed by (netfn, cmd); records calls."""
    def __init__(self, script):
        self.script = script
        self.calls = []

    def send_raw(self, netfn, cmd, data=b""):
        self.calls.append((netfn, cmd, bytes(data)))
        return self.script[(netfn, cmd)]


def test_confirm_inline_reply():
    inline = _ipmb_reply(0x01, 0x00, b"\x20" + b"\x00" * 10)
    s = _ScriptSession({(0x06, 0x34): (0x00, inline)})
    out = _b.confirm_bridge_path(s, [0x00])
    assert out["accepted"] and out["confirmed"] and out["via"] == "inline"
    assert out["far_cc"] == 0x00
    assert (0x06, 0x31) not in [(n, c) for n, c, _ in s.calls]   # no queue poll


def test_confirm_via_get_message_queue():
    far = _ipmb_reply(0x01, 0x00, b"\x20" + b"\x00" * 10)
    s = _ScriptSession({
        (0x06, 0x34): (0x00, b""),            # accepted, nothing inline
        (0x06, 0x31): (0x00, b"\x01"),        # flags: rx message available
        (0x06, 0x33): (0x00, b"\x00" + far),  # Get Message: channel byte + reply
    })
    out = _b.confirm_bridge_path(s, [0x00])
    assert out["accepted"] and out["confirmed"] and out["via"] == "get-message"


def test_confirm_rejected_bridge():
    s = _ScriptSession({(0x06, 0x34): (0x83, b"")})
    out = _b.confirm_bridge_path(s, [0x04])
    assert not out["accepted"] and not out["confirmed"] and out["accept_cc"] == 0x83


def test_confirm_unsupported_send_message():
    out = _b.confirm_bridge_path(_ScriptSession({(0x06, 0x34): (0xC1, b"")}), [0x00])
    assert not out["accepted"] and "unsupported" in out["detail"]
