"""
test_rmcp_asf.py — round-trip dissection tests for RMCP and ASF layers.

WHAT     Verifies build/dissect symmetry, byte-exact wire format, and dispatch
         from RMCP into ASF on `msg_class == 0`.
WHY      Catches regressions in field ordering, length math, and bind_layers
         glue without needing a live BMC.
RELATED  zipmi/scapy_ipmi/rmcp.py, zipmi/scapy_ipmi/asf.py
"""

from __future__ import annotations

from scapy.packet import Raw

import zipmi  # noqa: F401  (layer registration)
from zipmi.scapy_ipmi.asf import ASF, ASFPresencePong, build_ping, parse_pong
from zipmi.scapy_ipmi.rmcp import RMCP


def test_rmcp_default_bytes():
    """Default RMCP header is exactly 4 bytes: 06 00 ff 07 (IPMI class)."""
    raw = bytes(RMCP())
    assert raw == b"\x06\x00\xff\x07"


def test_rmcp_asf_class_byte():
    """msg_class=6 (ASF, RFC 4413) sets the low 5 bits to 0b00110."""
    raw = bytes(RMCP(msg_class=0x06))
    assert raw == b"\x06\x00\xff\x06"


def test_rmcp_dissect_ipmi_class():
    pkt = RMCP(b"\x06\x00\xff\x07")
    assert pkt.version == 0x06
    assert pkt.seq == 0xFF
    assert pkt.msg_class == 0x07
    assert pkt.ack == 0


def test_rmcp_ack_bit():
    """Setting ack=1 turns on the high bit of the class byte."""
    raw = bytes(RMCP(ack=1, msg_class=0x07))
    assert raw[3] == 0x87


def test_asf_ping_build():
    ping = build_ping(msg_tag=0x42)
    raw = bytes(ping)
    # 4 (IANA) + 1 (type) + 1 (tag) + 1 (reserved) + 1 (length) = 8 bytes.
    assert len(raw) == 8
    assert raw[0:4] == b"\x00\x00\x11\xbe"  # IANA 4542 BE
    assert raw[4] == 0x80  # PresencePing
    assert raw[5] == 0x42  # tag
    assert raw[7] == 0x00  # data length


def test_rmcp_asf_dispatch():
    """Build RMCP/ASF, re-parse, confirm ASF layer dispatched correctly."""
    pkt = RMCP(msg_class=0x06) / build_ping(msg_tag=1)
    parsed = RMCP(bytes(pkt))
    assert parsed.haslayer(ASF)
    assert parsed[ASF].msg_type == 0x80
    assert parsed[ASF].msg_tag == 1


def test_pong_round_trip():
    # 4542 (ASF's own IANA) = 0x000011BE — distinct LE vs BE, so this catches an
    # endianness flip. oem_iana is emitted LSB-first on the wire (real BMCs do);
    # 674 was a bad choice because its low bytes read the same either way.
    pong = ASFPresencePong(
        oem_iana=4542,
        oem_defined=0,
        supported_entities=0x81,    # IPMI bit + ASF v1.0
        supported_interactions=0x00,
    )
    raw = bytes(pong)
    assert len(raw) == 16
    assert raw[0:4] == bytes.fromhex("be110000")   # LSB-first; big-endian would be 000011be
    again = ASFPresencePong(raw)
    assert again.oem_iana == 4542
    assert again.supported_entities == 0x81


def test_parse_pong_helper():
    """ASF header carrying a Pong body decodes via parse_pong()."""
    body = ASFPresencePong(oem_iana=4542, supported_entities=0x81)
    # confirm the on-wire bytes are little-endian (the field that regressed)
    assert bytes(body)[0:4] == bytes.fromhex("be110000")
    asf = ASF(msg_type=0x40, msg_tag=0x42, data=bytes(body))
    decoded = parse_pong(asf)
    assert decoded is not None
    assert decoded.oem_iana == 4542
    assert decoded.supported_entities & 0x80


def test_parse_pong_rejects_wrong_type():
    asf = ASF(msg_type=0x80, data=b"\x00" * 16)
    assert parse_pong(asf) is None
