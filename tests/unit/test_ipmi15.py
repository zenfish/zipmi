"""
test_ipmi15.py — IPMI 1.5 Session + Message + checksums + commands.

WHAT     Verifies IPMB checksum math, msg_length auto-fill, command-payload
         registry lookup, and full RMCP/Session/Message/Payload round-trip.
WHY      Catches regressions in field ordering, length math, checksum
         placement, and bit-packed NetFn|LUN bytes without a live BMC.
RELATED  ipmi15.py, commands.py, IPMI-1.5.pdf §13.6, §13.8, §22.13
"""

from __future__ import annotations

import zipmi  # noqa: F401  (registers layers)
from zipmi.scapy_ipmi.commands import (
    GetChanAuthCapsReq,
    GetChanAuthCapsResp,
    GetDeviceIDResp,
    lookup,
)
from zipmi.scapy_ipmi.ipmi15 import IPMI15_Session, IPMI_Message
from zipmi.scapy_ipmi.rmcp import RMCP


def test_ipmb_checksum_matches_spec():
    """IPMB checksum is 2's complement of sum mod 256 (IPMI 1.5 §13.8)."""
    # Example from spec: bytes 0x20, 0x18 → checksum = 0xC8.
    assert IPMI_Message._ipmb_checksum(b"\x20\x18") == 0xC8


def test_get_chan_auth_caps_request_bytes():
    """Per IPMI 1.5 §22.13: 2-byte data, byte0 hi-bit + ch, byte1 priv."""
    req = GetChanAuthCapsReq(v20_ext=1, channel=0xE, max_priv=0x4)
    assert bytes(req) == b"\x8e\x04"


def test_get_chan_auth_caps_full_wire():
    """End-to-end build: sessionless Get Chan Auth Caps is 23 bytes."""
    req = GetChanAuthCapsReq(v20_ext=1, channel=0xE, max_priv=0x4)
    pkt = (
        RMCP(msg_class=0x07)
        / IPMI15_Session(auth_type=0, session_seq=0, session_id=0)
        / IPMI_Message(
            rs_addr=0x20,
            net_fn=0x06,
            rs_lun=0,
            rq_addr=0x81,
            rq_seq=0,
            rq_lun=0,
            cmd=0x38,
            data=bytes(req),
        )
    )
    wire = bytes(pkt)
    assert wire.hex() == "0600ff07000000000000000000092018c88100388e04b5"
    assert len(wire) == 23


def test_msg_length_auto_filled():
    """Session.msg_length defaults to None → auto-set from IPMB length."""
    pkt = IPMI15_Session() / IPMI_Message(net_fn=0x06, cmd=0x01)
    raw = bytes(pkt)
    # No data → IPMB length = 7 (rs, nl, ck1, rq, sq, cmd, ck2).
    # msg_length byte sits at offset 9 (no auth) — should be 7.
    assert raw[9] == 7


def test_chk2_covers_data():
    """chk2 = 2's complement of sum(rq_addr ... last data byte)."""
    msg = IPMI_Message(
        rs_addr=0x20,
        net_fn=0x06,
        rq_addr=0x81,
        rq_seq=0,
        cmd=0x38,
        data=b"\x8e\x04",
    )
    raw = bytes(msg)
    # rq_addr=0x81 + nl=0x00 + cmd=0x38 + 0x8e + 0x04 = 0x14b → chk2 = 0xb5
    assert raw[-1] == 0xB5


def test_round_trip_with_data():
    msg = IPMI_Message(net_fn=0x06, cmd=0x38, data=b"\x8e\x04")
    pkt = IPMI15_Session() / msg
    re = IPMI15_Session(bytes(pkt))
    assert re.haslayer(IPMI_Message)
    inner = re[IPMI_Message]
    assert inner.cmd == 0x38
    assert inner.net_fn == 0x06
    assert bytes(inner.data) == b"\x8e\x04"


def test_get_chan_auth_caps_resp_decode():
    """A canned response decodes auth bitmask + ext_caps correctly."""
    # Real Dell iDRAC6 response prefix observed live:
    #   cc=00 ch=01 auth=0x86 status=0x14 ext=0x03 oem=00 00 00 aux=00
    # auth=0x86 → bits 1 (MD2) + 2 (MD5) + 7 (IPMI2.0)
    raw = b"\x00\x01\x86\x14\x03\x00\x00\x00\x00"
    resp = GetChanAuthCapsResp(raw)
    assert resp.comp_code == 0x00
    assert resp.channel == 0x01
    assert "MD2" in resp.auth_types()
    assert "MD5" in resp.auth_types()
    assert "IPMI2.0" in resp.auth_types()
    assert resp.ext_caps == 0x03


def test_lookup_registry():
    entry = lookup(0x06, 0x38)
    assert entry is not None
    req_cls, resp_cls = entry
    assert req_cls is GetChanAuthCapsReq
    assert resp_cls is GetChanAuthCapsResp


def test_decode_short_response_does_not_crash():
    """When BMC returns just CC on error, _decode_response stubs gracefully."""
    from zipmi.core import _decode_response

    short = IPMI_Message(net_fn=0x07, cmd=0x39, data=b"\xC0")  # NodeBusy
    decoded = _decode_response(short)
    assert decoded is not None
    assert decoded.comp_code == 0xC0


def test_chassis_control_byte():
    """Chassis Control req: low nibble = action code."""
    from zipmi.scapy_ipmi.commands import ChassisControlReq
    req = ChassisControlReq(action=0x01)  # power up
    assert bytes(req) == b"\x01"
    req = ChassisControlReq(action=0x05)  # soft shutdown
    assert bytes(req) == b"\x05"


def test_sel_info_response_decode():
    """Real Dell reply: ver=51 entries=29 free=7536 ts=...  op=02"""
    from zipmi.scapy_ipmi.commands import GetSELInfoResp
    raw = bytes.fromhex("00" "51" "1d00" "7029" "00000000" "00000000" "02")
    resp = GetSELInfoResp(raw)
    assert resp.comp_code == 0
    assert resp.version == 0x51
    assert resp.entries == 29
    assert resp.free_space == 0x2970
