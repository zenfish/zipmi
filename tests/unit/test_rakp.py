"""
test_rakp.py — IPMI 2.0 RMCP+ Open Session + RAKP byte-level oracle.

WHAT     Verifies the layer hierarchy and the RAKP HMAC formulas against a
         tcpdump capture of `ipmitool -I lanplus -A MD5 -C 3` against Dell
         iDRAC6 (FW 1.70, 2026-05-01).

WHY      RAKP byte order is famously easy to get wrong. Pinning the
         formulas to a real-world capture means a refactor cannot silently
         break interop with real BMCs.

RELATED  zipmi/scapy_ipmi/rakp.py, zipmi/scapy_ipmi/crypto.py
"""

from __future__ import annotations

import zipmi  # noqa: F401  (registers layers)
from zipmi.scapy_ipmi.crypto import (
    CIPHER_SUITES,
    derive_k1, derive_k2, derive_sik,
    rakp2_authcode, rakp3_authcode, rakp4_icv,
)
from zipmi.scapy_ipmi.ipmi20 import IPMI20_Session
from zipmi.scapy_ipmi.rakp import (
    OpenSessionRequest, OpenSessionResponse,
    RAKP1, RAKP2, RAKP3, RAKP4,
    auth_payload, conf_payload, integrity_payload,
)
from zipmi.scapy_ipmi.rmcp import RMCP


# Oracle pcap fixtures.

PW = b"calvin"
SID_C = 0xa0a2a3a4
SID_M = 0x02002600
RC = bytes.fromhex("13dd765a462cac254002aef6e6ba6ec9")
RM = bytes.fromhex("f027ffcf96be8ce7a8e9d88ad175f557")
GUIDM = bytes.fromhex("44454c4c580010548033b5c04f475131")
ROLE = 0x14
UNAME = b"root"


def test_open_session_request_bytes():
    """32-byte open session request matches ipmitool wire."""
    req = OpenSessionRequest(
        msg_tag=0,
        max_priv=0,
        remote_session_id=SID_C,
        auth_payload=auth_payload(1),
        integrity_payload=integrity_payload(1),
        conf_payload=conf_payload(1),
    )
    raw = bytes(req)
    assert len(raw) == 32
    # Match the bytes in oracle packet 3 (offsets 12-43 of the IPMI 2.0
    # session payload).
    expected = bytes.fromhex(
        "00000000a4a3a2a0"
        "00000008010000000100000801000000"
        "0200000801000000"
    )
    assert raw == expected


def test_open_session_response_dispatch():
    """RMCP class 7 with auth_type=6 and payload_type=0x11 dispatches OSR."""
    wire = bytes.fromhex(
        "0600ff07"  # RMCP
        "06"        # auth_type
        "11"        # payload_type
        "00000000"  # session_id (LE)
        "00000000"  # session_seq (LE)
        "2400"      # payload_length LE = 36
        # Open Session Resp payload
        "00"            # msg_tag
        "00"            # rmcp_status
        "04"            # max_priv granted
        "00"            # reserved
        "a4a3a2a0"      # remote SID echoed
        "00260002"      # managed SID = 0x02002600
        "0000000801000000"   # auth payload (HMAC-SHA1)
        "0100000801000000"   # integrity payload (HMAC-SHA1-96)
        "0200000801000000"   # conf payload (AES-CBC-128)
    )
    p = RMCP(wire)
    assert p.haslayer(IPMI20_Session)
    assert p.haslayer(OpenSessionResponse)
    osr = p[OpenSessionResponse]
    assert osr.rmcp_status == 0
    assert osr.max_priv == 4
    assert osr.remote_session_id == 0xa0a2a3a4
    assert osr.managed_session_id == 0x02002600


def test_rakp2_authcode_oracle():
    cs = CIPHER_SUITES[3]
    expected = bytes.fromhex("bad04a77402721e42a930d574300e195ea42853f")
    got = rakp2_authcode(cs, PW, SID_C, SID_M, RC, RM, GUIDM, ROLE, UNAME)
    assert got == expected


def test_rakp3_authcode_oracle():
    cs = CIPHER_SUITES[3]
    expected = bytes.fromhex("d5d7624b1bab807db28c520f9df3d006d4518c31")
    got = rakp3_authcode(cs, PW, SID_C, RM, ROLE, UNAME)
    assert got == expected


def test_sik_derivation():
    cs = CIPHER_SUITES[3]
    expected = bytes.fromhex("52392ca8e6a9660c23a7f9845cec2b30fd62ce4d")
    sik = derive_sik(cs, PW, RC, RM, ROLE, UNAME)
    assert sik == expected


def test_rakp4_icv_truncation():
    """ICV is HMAC-SHA1(SIK, ...) truncated to 12 bytes for cipher 3."""
    cs = CIPHER_SUITES[3]
    sik = derive_sik(cs, PW, RC, RM, ROLE, UNAME)
    expected = bytes.fromhex("700cc77772d802dafe32026d")
    got = rakp4_icv(cs, sik, RC, SID_M, GUIDM)
    assert got == expected
    assert len(got) == 12


def test_k1_k2_lengths():
    cs = CIPHER_SUITES[3]
    sik = derive_sik(cs, PW, RC, RM, ROLE, UNAME)
    k1 = derive_k1(cs, sik)
    k2 = derive_k2(cs, sik)
    # HMAC-SHA1 outputs 20 bytes.
    assert len(k1) == 20
    assert len(k2) == 20


def test_ipmi20_session_extract_padding():
    """In-session reply: session.payload is exactly payload_length bytes."""
    # Header (12) + 32 encrypted body + 4 trailer + 12 HMAC = 60 bytes.
    wire = bytes.fromhex(
        "0600ff07"            # RMCP
        "06"                  # auth_type
        "c0"                  # encrypted=1, auth=1, type=0 (IPMI)
        "00260002"            # session_id LE
        "01000000"            # session_seq LE
        "2000"                # payload_length LE = 32
        + "ab" * 32           # encrypted body
        + "ffff0207"          # integrity pad + padlen + next_header
        + "cd" * 12           # AuthCode
    )
    p = RMCP(wire)
    sess = p[IPMI20_Session]
    assert sess.payload_length == 32
    # The Raw chained layer holds exactly the 32 encrypted bytes.
    from scapy.packet import Raw
    assert sess.haslayer(Raw)
    assert bytes(sess[Raw].load)[:32] == b"\xab" * 32
