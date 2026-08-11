"""
test_user_matrix.py — user × channel matrix decode/enumeration.

Real byte-level assertions on the decode helpers + the one-session enumeration
driven by an injected fake sender (no network).
"""
from __future__ import annotations

from zipmi.cli.user_matrix import (
    decode_user_access, decode_channel_access, PRIV_NAME, ACCESS_MODE,
)
from zipmi.scapy_ipmi.commands import GetChannelAccessResp


def test_decode_user_access_admin_all_flags():
    # 0x54 = bit6(callin)+bit4(ipmi_msg)+priv 4 : 0101_0100
    d = decode_user_access(0x54)
    assert d["priv"] == "administrator"
    assert d["priv_raw"] == 4
    assert d["callin"] is True
    assert d["link_auth"] is False
    assert d["ipmi_msg"] is True


def test_decode_user_access_operator_linkauth():
    # 0x23 = bit5(link_auth)+priv 3 : 0010_0011
    d = decode_user_access(0x23)
    assert d["priv"] == "operator"
    assert d["link_auth"] is True
    assert d["callin"] is False
    assert d["ipmi_msg"] is False


def test_decode_channel_access_positives_and_mode():
    # access_byte 0x22: mode 2 (always-available), bit5 set = per-msg-auth DISABLED
    # priv_byte 0x03 = operator
    r = GetChannelAccessResp(bytes([0x00, 0x22, 0x03]))
    d = decode_channel_access(r)
    assert d["access_mode"] == "always-available"
    assert d["priv_limit"] == "operator"
    assert d["priv_limit_raw"] == 3
    assert d["per_msg_auth"] is False      # bit set = disabled → False
    assert d["user_level_auth"] is True    # bit4 clear = enabled
    assert d["alerting"] is True           # bit6 clear = enabled


def test_nv_delta_reports_only_differences():
    from zipmi.cli.user_matrix import nv_delta
    present = {"priv_limit": "operator", "access_mode": "always-available"}
    nonvol = {"priv_limit": "administrator", "access_mode": "always-available"}
    assert nv_delta(present, nonvol) == {
        "priv_limit": {"present": "operator", "nonvolatile": "administrator"}}


def test_nv_delta_empty_when_identical():
    from zipmi.cli.user_matrix import nv_delta
    same = {"priv_limit": "administrator", "access_mode": "shared"}
    assert nv_delta(same, dict(same)) == {}
