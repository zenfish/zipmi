"""
test_auth.py — IPMI 1.5 auth-code formula and session command payloads.

WHAT     Verifies the MD5 AuthCode formula against an oracle hex string
         captured from a real `ipmitool -I lan -A MD5` session vs Dell
         iDRAC6, and round-trips the session-management commands.

WHY      Auth-code byte order and what bytes go into the hash are easy
         to get wrong. Pinning the formula to a real-world capture means
         any future refactor can't silently break interop.

RELATED  zipmi/scapy_ipmi/crypto.py, zipmi/scapy_ipmi/commands.py
"""

from __future__ import annotations

from zipmi.scapy_ipmi.commands import (
    ActivateSessionReq,
    ActivateSessionResp,
    GetSessionChallengeReq,
    GetSessionChallengeResp,
    SetSessionPrivLevelReq,
)
from zipmi.scapy_ipmi.crypto import md5_auth_code, pad_password


def test_pad_password():
    assert pad_password("calvin") == b"calvin" + b"\x00" * 10
    assert len(pad_password("")) == 16
    assert pad_password(b"\x01\x02") == b"\x01\x02" + b"\x00" * 14


def test_md5_authcode_oracle():
    """
    Oracle capture: ipmitool -I lan -A MD5 -H 192.168.0.23 -U root -P calvin
    Activate Session request to Dell iDRAC6 (2026-05-01).

      session_id (temp from challenge): 0x02000700
      session_seq:                       0
      ipmb_message bytes (rsAddr..chk2):
        20 18 c8 81 0c 3a 02 04 ee 04 ff 3a 75 70 0e ef
        7d 37 ed f3 38 d9 4c b2 62 99 a4 15 cf
      expected AuthCode (16 bytes):
        ea 3f a0 d8 6b 6a 8c 58 5a 20 1e c5 8f 6d a5 c7
    """
    pw = b"calvin"
    sid = 0x02000700
    seq = 0
    ipmb = bytes.fromhex(
        "2018c8810c3a0204"
        "ee04ff3a75700eef7d37edf338d94cb2"
        "6299a415cf"
    )
    expected = bytes.fromhex("ea3fa0d86b6a8c585a201ec58f6da5c7")
    assert md5_auth_code(pw, sid, ipmb, seq) == expected


def test_get_session_challenge_req_bytes():
    """1 byte auth + 16 byte user = 17 bytes."""
    req = GetSessionChallengeReq(auth_type=0x02, user_name=pad_password("root"))
    raw = bytes(req)
    assert len(raw) == 17
    assert raw[0] == 0x02
    assert raw[1:5] == b"root"
    assert raw[5:] == b"\x00" * 12


def test_get_session_challenge_resp_decode():
    """Real BMC reply: cc=00 sid=02000700 challenge=ee04ff3a..."""
    raw = bytes.fromhex(
        "00"                # cc
        "00070002"          # temp_session_id LE = 0x02000700
        "ee04ff3a75700eef7d37edf338d94cb2"  # challenge
    )
    resp = GetSessionChallengeResp(raw)
    assert resp.comp_code == 0
    assert resp.temp_session_id == 0x02000700
    assert bytes(resp.challenge).hex() == "ee04ff3a75700eef7d37edf338d94cb2"


def test_activate_session_req_bytes():
    """1 + 1 + 16 + 4 = 22 bytes."""
    req = ActivateSessionReq(
        auth_type=0x02,
        max_priv=0x04,
        challenge=b"\xee\x04\xff\x3a\x75\x70\x0e\xef\x7d\x37\xed\xf3\x38\xd9\x4c\xb2",
        init_outbound_seq=0x15a49962,
    )
    raw = bytes(req)
    assert len(raw) == 22
    assert raw[0] == 0x02
    assert raw[1] == 0x04
    assert raw[2:18].hex() == "ee04ff3a75700eef7d37edf338d94cb2"
    assert raw[18:22] == b"\x62\x99\xa4\x15"  # LE


def test_activate_session_resp_decode():
    """Dell reply observed live: cc=00 auth=00 sid=02000800 seq=1 priv=4."""
    raw = bytes.fromhex(
        "00"          # cc
        "00"          # auth_type (per-msg auth disabled)
        "00080002"    # session_id LE = 0x02000800
        "01000000"    # init_inbound_seq LE = 1
        "04"          # max_priv
    )
    resp = ActivateSessionResp(raw)
    assert resp.comp_code == 0
    assert resp.auth_type == 0
    assert resp.session_id == 0x02000800
    assert resp.init_inbound_seq == 1
    assert resp.max_priv == 4


def test_set_session_priv_req_bytes():
    # two distinct values so this isn't a one-constant passthrough tautology
    assert bytes(SetSessionPrivLevelReq(priv=0x04)) == b"\x04"   # Administrator
    assert bytes(SetSessionPrivLevelReq(priv=0x03)) == b"\x03"   # Operator
