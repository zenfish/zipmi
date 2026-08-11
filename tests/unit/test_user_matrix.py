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


def test_decode_auth_caps_md5_ipmi20_nonnull():
    from zipmi.cli.user_matrix import decode_auth_caps
    from zipmi.scapy_ipmi.commands import GetChanAuthCapsResp
    # auth_type_support 0x84 = bit7(ipmi2.0)+bit2(md5); status 0x08 = bit3 non-null
    r = GetChanAuthCapsResp(bytes([0x00, 0x01, 0x84, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]))
    d = decode_auth_caps(r)
    assert d["ipmi20"] is True
    assert "md5" in d["auth_types"]
    assert "none" not in d["auth_types"]
    assert d["non_null_user"] is True
    assert d["anon_login"] is False


def test_decode_auth_caps_flags_none_and_anon():
    from zipmi.cli.user_matrix import decode_auth_caps
    from zipmi.scapy_ipmi.commands import GetChanAuthCapsResp
    # auth 0x01 = none; status 0x20 = anon-login
    r = GetChanAuthCapsResp(bytes([0x00, 0x01, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]))
    d = decode_auth_caps(r)
    assert "none" in d["auth_types"]
    assert d["anon_login"] is True


def test_build_matrix_one_channel_two_users():
    from zipmi.cli.user_matrix import build_matrix
    from zipmi.scapy_ipmi.commands import (
        GetChannelInfoResp, GetChannelAccessResp, GetChanAuthCapsResp,
        GetUserAccessResp, GetUserNameResp,
    )

    class FakeSender:
        """Answers only channel 1; other channels raise (unpopulated)."""
        def send_cmd(self, netfn, cmd, req):
            ch = getattr(req, "channel", None)
            uid = getattr(req, "user_id", None)
            if cmd == 0x42:                      # Get Channel Info
                if ch != 1:
                    raise RuntimeError("cc=0xcc")
                return GetChannelInfoResp(bytes([0x00, 0x01, 0x04, 0x01, 0x80,
                                                 0x00, 0x00, 0x00, 0x00, 0x00]))
            if cmd == 0x41:                      # Get Channel Access (vol/nv)
                pv = 0x03 if req.access_type == 0b10 else 0x04   # present op / nv admin
                return GetChannelAccessResp(bytes([0x00, 0x02, pv]))
            if cmd == 0x38:                      # Auth caps: md5 + ipmi2.0, non-null
                return GetChanAuthCapsResp(bytes([0x00, 0x01, 0x84, 0x08,
                                                  0, 0, 0, 0, 0]))
            if cmd == 0x44:                      # Get User Access
                if uid == 1:                     # discovery: max=3, enabled=2
                    return GetUserAccessResp(bytes([0x00, 0x03, 0x02, 0x00, 0x54]))
                acc = 0x54 if uid == 2 else 0x23   # u2 admin, u3 operator
                return GetUserAccessResp(bytes([0x00, 0x02, 0x02, 0x00, acc]))
            if cmd == 0x46:                      # Get User Name
                name = (b"root" if uid == 2 else b"admin").ljust(16, b"\x00")
                return GetUserNameResp(bytes([0x00]) + name)
            raise AssertionError(f"unexpected cmd 0x{cmd:02x}")

        def send_raw(self, netfn, cmd, payload):
            if cmd == 0x54:                      # cipher suites: channel + records 3,17
                records = bytes([0xC0, 0x03, 0x01, 0x41, 0x81,
                                 0xC0, 0x11, 0x03, 0x44, 0x81])
                return 0x00, bytes([payload[0]]) + records
            raise AssertionError

    m = build_matrix(FakeSender(), "10.0.0.1")
    assert m["target"] == "10.0.0.1"
    assert m["max_user_count"] == 3
    assert set(m["channels"].keys()) == {"1"}         # only populated
    ch1 = m["channels"]["1"]
    assert ch1["medium"] == "802.3 LAN"
    assert ch1["access"]["present"]["priv_limit"] == "operator"
    assert ch1["access"]["nv_delta"]["priv_limit"] == {
        "present": "operator", "nonvolatile": "administrator"}
    assert ch1["cipher_suites"] == [3, 17]
    assert m["users"]["2"]["name"] == "root"
    assert m["users"]["2"]["access"]["1"]["priv"] == "administrator"
    assert m["users"]["3"]["access"]["1"]["priv"] == "operator"
    assert m["findings"] == []


def test_evaluate_findings_flags_cipher0_and_anon():
    from zipmi.cli.user_matrix import evaluate_findings
    matrix = {"channels": {"1": {
        "cipher_suites": [0, 3, 17],
        "auth_caps": {"anon_login": True, "null_user": False,
                      "auth_types": ["md5"], "per_msg_auth": True,
                      "user_level_auth": True}}}, "users": {}}
    issues = {f["issue"] for f in evaluate_findings(matrix)}
    assert "cipher-0 advertised" in issues
    assert "anonymous login enabled" in issues


def test_evaluate_findings_clean_channel_empty():
    from zipmi.cli.user_matrix import evaluate_findings
    matrix = {"channels": {"1": {
        "cipher_suites": [3, 17],
        "auth_caps": {"anon_login": False, "null_user": False,
                      "auth_types": ["md5"], "per_msg_auth": True,
                      "user_level_auth": True}}}, "users": {}}
    assert evaluate_findings(matrix) == []
