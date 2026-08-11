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


def test_render_table_contains_users_channels_and_delta():
    from zipmi.cli.user_matrix import render_table
    matrix = {
        "target": "10.0.0.1", "max_user_count": 1, "enabled_user_count": 1,
        "channels": {"1": {
            "medium": "802.3 LAN", "session_support": "multi-session",
            "access": {"present": {"priv_limit": "operator"},
                       "nonvolatile": {"priv_limit": "administrator"},
                       "nv_delta": {"priv_limit": {"present": "operator",
                                                   "nonvolatile": "administrator"}}},
            "cipher_suites": [3, 17], "auth_caps": {"auth_types": ["md5"]}}},
        "users": {"2": {"name": "root",
                        "access": {"1": {"priv": "administrator", "ipmi_msg": True,
                                         "link_auth": True, "callin": False}}}},
        "findings": []}
    out = render_table(matrix)
    assert "root" in out
    assert "802.3 LAN" in out
    assert "AIL" in out                 # compact cell: administrator + ipmi-msg + link-auth
    assert "Δ" in out and "operator" in out


def test_decode_user_access_no_access_priv_uses_full_nibble():
    # 0x0F = no-access (priv nibble 15) — guards the full 4-bit mask (a 3-bit
    # mask would wrongly yield 7). Caught a coverage gap in mutation testing.
    d = decode_user_access(0x0F)
    assert d["priv"] == "no-access"
    assert d["priv_raw"] == 0x0F


def test_build_matrix_discovers_users_when_channel0_rejects():
    """Regression: user discovery must not lead with populated[0] (IPMB/KCS
    reject Get User Access). 0xE (connected channel) answers → users found."""
    from zipmi.cli.user_matrix import build_matrix
    from zipmi.scapy_ipmi.commands import (
        GetChannelInfoResp, GetUserAccessResp, GetUserNameResp)

    class Fake:
        def send_cmd(self, netfn, cmd, req):
            ch = getattr(req, "channel", None)
            uid = getattr(req, "user_id", None)
            if cmd == 0x42:                       # ch0 (IPMB) + ch1 (LAN) populated
                if ch not in (0, 1):
                    raise RuntimeError("cc=0xcc")
                medium = 0x01 if ch == 0 else 0x04
                sess = 0x00 if ch == 0 else 0x80   # ch0 sessionless, ch1 multi
                return GetChannelInfoResp(bytes([0x00, ch, medium, 0x01, sess,
                                                 0, 0, 0, 0, 0]))
            if cmd == 0x44:                       # Get User Access
                if ch == 0:                        # IPMB: BMC returns cc=0xcc (a
                    return GetUserAccessResp(bytes([0xcc, 0, 0, 0, 0]))  # response, not a raise)
                if uid == 1:                        # discovery on 0xE / ch1: max=3
                    return GetUserAccessResp(bytes([0x00, 0x03, 0x02, 0x00, 0x54]))
                return GetUserAccessResp(bytes([0x00, 0x03, 0x02, 0x00, 0x54]))
            if cmd == 0x46:
                return GetUserNameResp(bytes([0x00]) + b"root".ljust(16, b"\x00"))
            if cmd == 0x41 or cmd == 0x38:         # let access/auth-caps error out
                raise RuntimeError("cc=0xcc")
            raise AssertionError(f"cmd 0x{cmd:02x}")

        def send_raw(self, netfn, cmd, payload):
            raise RuntimeError("no cipher")         # graceful err

    m = build_matrix(Fake(), "10.0.0.1")
    assert m["max_user_count"] == 3               # not 0 — the bug
    assert set(m["users"].keys()) == {"1", "2", "3"}
    # ch0 is sessionless (IPMB) → per-user access is n/a, not a sprayed error;
    # ch1 (LAN) decodes normally.
    assert m["users"]["2"]["access"]["0"] == "n/a"
    assert not m["users"]["2"]["access"]["0"].startswith("err:")
    assert m["users"]["2"]["access"]["1"]["priv"] == "administrator"



def test_build_matrix_bridge_probe_per_channel():
    """--bridge adds a per-channel bridgeability probe (Send Message 0x34)."""
    from zipmi.cli.user_matrix import build_matrix
    from zipmi.scapy_ipmi.commands import (
        GetChannelInfoResp, GetUserAccessResp, GetUserNameResp)

    class Fake:
        def send_cmd(self, netfn, cmd, req):
            ch = getattr(req, "channel", None); uid = getattr(req, "user_id", None)
            if cmd == 0x42:
                if ch != 1: raise RuntimeError("cc=0xcc")
                return GetChannelInfoResp(bytes([0x00, 1, 0x04, 0x01, 0x80, 0,0,0,0,0]))
            if cmd == 0x44:
                return GetUserAccessResp(bytes([0x00, 0x01, 0x01, 0x00, 0x54]))
            if cmd == 0x46:
                return GetUserNameResp(bytes([0x00]) + b"root".ljust(16, b"\x00"))
            raise RuntimeError("cc=0xcc")   # access/auth-caps err → graceful
        def send_raw(self, netfn, cmd, payload):
            if cmd == 0x34:                 # Send Message → accepted (bridgeable)
                return 0x00, b""
            raise RuntimeError("no cipher")

    m = build_matrix(Fake(), "10.0.0.1", bridge=True)
    assert m["channels"]["1"]["bridge"]["bridgeable"] is True
    # and it really issued a Send Message wrapping Get Device ID onto ch1
    # (0x41 tracking/channel byte, then the encapsulated Get Device ID)


def test_build_matrix_raises_priv_and_records_effective_ceiling():
    """By default build_matrix raises session priv (Set Session Priv 0x3B) before
    walking, and records the granted level as the connected channel's effective_priv."""
    from zipmi.cli.user_matrix import build_matrix
    from zipmi.scapy_ipmi.commands import (
        GetChannelInfoResp, GetUserAccessResp, GetUserNameResp,
        SetSessionPrivLevelResp)

    class Fake:
        def send_cmd(self, netfn, cmd, req):
            ch = getattr(req, "channel", None)
            if cmd == 0x42:                         # ch1 populated; 0xE → ch1
                if ch not in (1, 0x0E): raise RuntimeError("cc=0xcc")
                return GetChannelInfoResp(bytes([0x00, 1, 0x04, 0x01, 0x80, 0,0,0,0,0]))
            if cmd == 0x44:
                return GetUserAccessResp(bytes([0x00, 0x01, 0x01, 0x00, 0x54]))
            if cmd == 0x46:
                return GetUserNameResp(bytes([0x00]) + b"root".ljust(16, b"\x00"))
            if cmd == 0x3B:                         # grant admin (0x04), reject oem (0x05)
                lvl = int(getattr(req, "priv")) & 0x0F
                if lvl == 0x04:
                    return SetSessionPrivLevelResp(bytes([0x00, 0x04]))  # comp=0, priv=4
                return SetSessionPrivLevelResp(bytes([0x80, 0x00]))      # cc=0x80 reject
            raise RuntimeError("cc=0xcc")
        def send_raw(self, netfn, cmd, payload):
            raise RuntimeError("no cipher")

    m = build_matrix(Fake(), "10.0.0.1")                     # raise is the default
    assert m["channels"]["1"]["effective_priv"] == "administrator"
    assert build_matrix(Fake(), "10.0.0.1", raise_priv=False)[
        "channels"]["1"].get("effective_priv") is None        # opt-out skips 0x3B


class _LanSender:
    """Answers Get Channel Info(0xE)→ch1 (connected) and Get LAN Config params."""
    def send_cmd(self, netfn, cmd, req):
        from zipmi.scapy_ipmi.commands import GetChannelInfoResp
        if cmd == 0x42:
            ch = req.channel
            n = 1 if ch in (0x0E, 1) else ch
            if n != 1:
                raise RuntimeError("cc=0xcc")
            return GetChannelInfoResp(bytes([0x00, 1, 0x04, 0x01, 0x80, 0,0,0,0,0]))
        raise RuntimeError("cc=0xcc")

    def send_raw(self, netfn, cmd, data):
        if netfn == 0x0C and cmd == 0x02:            # Get LAN Config: [ch,param,0,0]
            param = data[1]
            body = {
                5:  bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),   # MAC
                3:  bytes([192, 168, 0, 23]),                      # IP
                4:  bytes([0x01]),                                 # source = static
                20: bytes([0x64, 0x80]),                           # VLAN 100, enabled
            }.get(param)
            if body is None:
                return 0xC9, b""
            return 0x00, bytes([0x11]) + body        # [param-rev] + config
        raise RuntimeError("no")


def test_medium_detail_lan_mac_ip_vlan():
    from zipmi.cli.user_matrix import _medium_detail
    d = _medium_detail(_LanSender(), 1, 0x04)
    assert d["mac"] == "aa:bb:cc:dd:ee:ff"
    assert d["ip"] == "192.168.0.23"
    assert d["ip_source"] == "static"
    assert d["vlan"] == 100


def test_connected_channel_resolves_0xE():
    from zipmi.cli.user_matrix import _connected_channel
    assert _connected_channel(_LanSender()) == 1
