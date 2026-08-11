"""
test_channel_access.py — Get Channel Access (0x41) request/response classes.

Real byte-level assertions: request bit-packing of the access-type selector,
response field extraction. IPMI 2.0 §22.23.
"""
from __future__ import annotations

from zipmi.scapy_ipmi.commands import GetChannelAccessReq, GetChannelAccessResp


def test_req_encodes_channel_and_access_type():
    # present-volatile (0b10) on channel 1 → bytes: 01, (0b10 << 6)=0x80
    assert bytes(GetChannelAccessReq(channel=1, access_type=0b10)) == bytes([0x01, 0x80])
    # non-volatile (0b01) → second byte 0x40
    assert bytes(GetChannelAccessReq(channel=1, access_type=0b01)) == bytes([0x01, 0x40])


def test_resp_parses_access_and_priv_bytes():
    # comp_code 0, access_byte 0x22 (mode 2 + per-msg-auth-disabled bit5),
    # priv_byte 0x04 (Administrator)
    r = GetChannelAccessResp(bytes([0x00, 0x22, 0x04]))
    assert r.comp_code == 0x00
    assert r.access_byte == 0x22
    assert r.priv_byte == 0x04
