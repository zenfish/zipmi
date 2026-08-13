"""
test_json_contract.py — the global --json output contract, per subsystem.

WHAT   Drives converted cmd_* functions with json=True through a scripted
       session and asserts the emitted JSON is (a) parseable — proving no text
       narration leaked onto stdout — and (b) carries the real decoded values,
       not a stub. Grows one block per subsystem as the emit() sweep proceeds.

WHY    The contract is "text is a VIEW of the same dict". These tests pin the
       dict: they decode a known wire response and assert the JSON fields match
       the bits, so a schema drift or a non-serializable value fails loudly.

RELATED zipmi/cli/zipmi.py (emit), tests/unit/test_firewall.py (emit() unit test)
"""
from __future__ import annotations

import argparse
import json

import pytest


class _S:
    """Scripted session: send_raw(netfn, cmd, data) -> canned (cc, bytes).
    Keys try (netfn, cmd, data) then (netfn, cmd); default = (0xC1, b'')."""
    def __init__(self, responses):
        self.responses = responses
        self.sent = []

    def send_raw(self, netfn, cmd, data=b""):
        self.sent.append((netfn, cmd, bytes(data)))
        r = self.responses
        return r.get((netfn, cmd, bytes(data))) or r.get((netfn, cmd)) or (0xC1, b"")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _run(monkeypatch, fn, session, **kw):
    """Invoke a cmd_ function with json=True and a scripted session; return the
    parsed JSON from stdout (raises if anything non-JSON leaked)."""
    import zipmi.cli.zipmi as Z
    monkeypatch.setattr(Z, "_open_session", lambda args: session)
    kw.setdefault("json", True)
    kw.setdefault("host", "test")
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(argparse.Namespace(**kw))
    return rc, json.loads(buf.getvalue())


# === mc subsystem ========================================================

def test_mc_watchdog_get_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_mc_watchdog_get
    # use_byte=0x41 (running, use=1 BIOS FRB2); actions=0x02 (action=2 power-cycle);
    # pre_to=10; expir=0; initial=0x012c/10=30.0s; present=0x00c8/10=20.0s
    s = _S({(0x06, 0x25): (0x00, bytes([0x41, 0x02, 0x0A, 0x00, 0x2C, 0x01, 0xC8, 0x00]))})
    rc, d = _run(monkeypatch, cmd_mc_watchdog_get, s)
    assert rc == 0
    assert d["running"] is True
    assert d["timer_use"]["code"] == 1
    assert d["timer_action"]["code"] == 2
    assert d["pre_timeout_interval_s"] == 10
    assert d["initial_countdown_s"] == 30.0
    assert d["present_countdown_s"] == 20.0


def test_mc_watchdog_reset_json_is_status(monkeypatch):
    from zipmi.cli.zipmi import cmd_mc_watchdog_reset
    rc, d = _run(monkeypatch, cmd_mc_watchdog_reset, _S({(0x06, 0x22): (0x00, b"")}))
    assert rc == 0 and d == {"ok": True, "action": "watchdog-reset"}


def test_mc_selftest_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_mc_selftest

    class _R:
        result = 0x55        # 0x55 = no error
        info = 0x00

    class _Sess:
        def send_cmd(self, nf, cmd):
            return _R()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    rc, d = _run(monkeypatch, cmd_mc_selftest, _Sess())
    assert rc == 0 and d["result"] == 0x55 and d["info"] == 0x00 and "name" in d


# === chassis subsystem ===================================================

def test_chassis_restart_cause_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_restart_cause
    # byte0 cause=0x04 (watchdog expiration), byte1 channel=0x0f low nibble
    s = _S({(0x00, 0x07): (0x00, bytes([0x04, 0x0F]))})
    rc, d = _run(monkeypatch, cmd_chassis_restart_cause, s)
    assert rc == 0
    assert d["cause"] == {"code": 4, "name": "watchdog expiration"}
    assert d["channel"] == 0x0F


def test_chassis_policy_list_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_policy
    # bits: bit0(always-off) + bit2(always-on) set => 0b101 = 0x05
    s = _S({(0x00, 0x06, b"\x03"): (0x00, bytes([0x05]))})
    rc, d = _run(monkeypatch, cmd_chassis_policy, s, policy="list")
    assert rc == 0
    assert d["supported_policies"] == ["always-off", "always-on"]


def test_chassis_policy_set_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_policy
    s = _S({(0x00, 0x06, b"\x02"): (0x00, b"")})   # always-on = 0x02
    rc, d = _run(monkeypatch, cmd_chassis_policy, s, policy="always-on")
    assert rc == 0
    assert d == {"ok": True, "action": "set-power-policy", "policy": "always-on"}


def test_chassis_identify_on_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_identify
    s = _S({(0x00, 0x04): (0x00, b"")})
    rc, d = _run(monkeypatch, cmd_chassis_identify, s, duration=30)
    assert rc == 0
    assert d == {"ok": True, "action": "identify", "on": True, "duration_s": 30}


def test_chassis_identify_off_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_identify
    s = _S({(0x00, 0x04): (0x00, b"")})
    rc, d = _run(monkeypatch, cmd_chassis_identify, s, duration=0)
    assert rc == 0
    assert d == {"ok": True, "action": "identify", "on": False}


# === session subsystem ===================================================

def test_session_info_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_session_info
    # handle=0x0a, possible=6, active=1, uid=2, op_priv=0x04(admin), chan=0x01,
    # then remote ip 10.0.0.5, mac 00:11:22:33:44:55, port 0x026f = 623
    payload = bytes([0x0A, 0x06, 0x01, 0x02, 0x04, 0x01,
                     10, 0, 0, 5,
                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                     0x6F, 0x02])
    s = _S({(0x06, 0x3D, b"\x00"): (0x00, payload)})
    rc, d = _run(monkeypatch, cmd_session_info, s, selector="active")
    assert rc == 0
    assert d["session_handle"] == 0x0A
    assert d["possible_sessions"] == 6 and d["active_sessions"] == 1
    assert d["user_id"] == 2
    assert d["operating_privilege"] == {"code": 4, "name": "admin"}
    assert d["channel"] == 1
    assert d["remote_ip"] == "10.0.0.5"
    assert d["remote_mac"] == "00:11:22:33:44:55"
    assert d["remote_port"] == 623


# === lan subsystem =======================================================

def test_lan_print_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_lan_print
    # param revision byte prefix (0x11) then the value bytes.
    responses = {
        (0x0C, 0x02, bytes([1, 4, 0, 0])): (0x00, bytes([0x11, 0x02])),   # dhcp
        (0x0C, 0x02, bytes([1, 3, 0, 0])): (0x00, bytes([0x11, 192, 168, 1, 50])),
        (0x0C, 0x02, bytes([1, 6, 0, 0])): (0x00, bytes([0x11, 255, 255, 255, 0])),
        (0x0C, 0x02, bytes([1, 5, 0, 0])): (0x00, bytes([0x11, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])),
        (0x0C, 0x02, bytes([1, 12, 0, 0])): (0x00, bytes([0x11, 192, 168, 1, 1])),
    }
    s = _S(responses)
    rc, d = _run(monkeypatch, cmd_lan_print, s, channel="1")
    assert rc == 0
    assert d["channel"] == 1 and d["channel_is_present"] is False
    by_label = {p["label"]: p for p in d["parameters"]}
    assert by_label["IP Source"]["value"] == "dhcp"
    assert by_label["IP Address"]["value"] == "192.168.1.50"
    assert by_label["Subnet Mask"]["value"] == "255.255.255.0"
    assert by_label["MAC Address"]["value"] == "aa:bb:cc:dd:ee:ff"
    assert by_label["Gateway IP"]["value"] == "192.168.1.1"


def test_lan_print_reports_cc_on_failure(monkeypatch):
    from zipmi.cli.zipmi import cmd_lan_print
    # IP Source succeeds, everything else defaults to cc=0xC1 in _S.
    s = _S({(0x0C, 0x02, bytes([2, 4, 0, 0])): (0x00, bytes([0x11, 0x01]))})
    rc, d = _run(monkeypatch, cmd_lan_print, s, channel="2")
    assert rc == 0
    by_label = {p["label"]: p for p in d["parameters"]}
    assert by_label["IP Source"]["value"] == "static"
    assert by_label["IP Address"]["cc"] == 0xC1
    assert "value" not in by_label["IP Address"]


# === sel subsystem =======================================================

def test_sel_time_get_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sel_time_get
    # 0x60000000 = 1611526656, comfortably past the pre-init threshold.
    s = _S({(0x0A, 0x48): (0x00, bytes([0x00, 0x00, 0x00, 0x60]))})
    rc, d = _run(monkeypatch, cmd_sel_time_get, s)
    assert rc == 0
    assert d["raw"] == 0x60000000 and d["pre_init"] is False
    assert isinstance(d["time"], str) and d["time"]


def test_sel_time_get_pre_init_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sel_time_get
    s = _S({(0x0A, 0x48): (0x00, bytes([0x01, 0x00, 0x00, 0x00]))})
    rc, d = _run(monkeypatch, cmd_sel_time_get, s)
    assert rc == 0
    assert d == {"raw": 1, "pre_init": True, "time": None}


# === fru subsystem =======================================================

def test_fru_print_common_header_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_fru_print
    # 8-byte common header: format v1, all area offsets 0 (board/product absent),
    # last byte a zero-sum checksum. size=8 so _read_fru_blob does one 8-byte read.
    hdr = bytearray([0x01, 0, 0, 0, 0, 0, 0, 0])
    hdr[7] = (-sum(hdr[:7])) & 0xFF        # zero-sum checksum
    responses = {
        (0x0A, 0x10, b"\x00"): (0x00, bytes([8, 0, 0])),   # size=8, byte access
        # Read FRU Data: dev0, offset0, want8 -> got=8 + the header bytes
        (0x0A, 0x11, bytes([0, 0, 0, 8])): (0x00, bytes([8]) + bytes(hdr)),
    }
    s = _S(responses)
    rc, d = _run(monkeypatch, cmd_fru_print, s, device_id=0)
    assert rc == 0
    assert d["device_id"] == 0 and d["size"] == 8 and d["word_access"] is False
    assert d["common_header"]["format_version"] == 1
    assert d["common_header"]["checksum_ok"] is True
    assert d["board_info"] is None and d["product_info"] is None


# === bridging privesc (confused-deputy probe) ============================

def _ipmb_reply(cmd, cc, data=b""):
    """IPMB-format bridged response the parser reads (checksums not validated)."""
    return bytes([0x81, 0x1C, 0x00, 0x20, 0x00, cmd, cc]) + data + bytes([0x00])


# one present channel (0x00, medium IPMB) discovered by _channel_media
_CH0_INFO = (0x00, bytes([0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0]))


def test_privesc_detects_escalation(monkeypatch):
    """Direct Set Session Priv(admin) REFUSED (0x80) but the bridged copy comes
    back with far cc 0x00 => the BMC ran an admin command the direct path
    refused. escalation_found must be True."""
    from zipmi.cli.zipmi import cmd_bridging_privesc
    s = _S({
        (0x06, 0x42, bytes([0x00])): _CH0_INFO,
        (0x06, 0x3B, bytes([0x04])): (0x80, b""),                     # direct refused
        (0x06, 0x34): (0x00, _ipmb_reply(0x3B, 0x00, bytes([0x04]))),  # bridged OK
    })
    rc, d = _run(monkeypatch, cmd_bridging_privesc, s, channel="all", max_priv="operator")
    assert rc == 0
    assert d["direct"]["refused"] is True and d["direct"]["cc"] == 0x80
    assert d["escalation_found"] is True
    t = next(t for t in d["targets"] if t["channel"] == 0)
    assert t["escalated"] is True and t["far_cc"] == 0x00


def test_privesc_negative_when_bridge_also_refused(monkeypatch):
    """Direct refused AND bridged returns a priv error (0xD4) => no escalation."""
    from zipmi.cli.zipmi import cmd_bridging_privesc
    s = _S({
        (0x06, 0x42, bytes([0x00])): _CH0_INFO,
        (0x06, 0x3B, bytes([0x04])): (0x80, b""),
        (0x06, 0x34): (0x00, _ipmb_reply(0x3B, 0xD4)),   # far end: insufficient priv
    })
    rc, d = _run(monkeypatch, cmd_bridging_privesc, s, channel="all", max_priv="operator")
    assert rc == 0
    assert d["escalation_found"] is False
    assert d["targets"][0]["escalated"] is False and d["targets"][0]["far_cc"] == 0xD4


def test_privesc_no_baseline_when_direct_granted(monkeypatch):
    """If the direct admin request SUCCEEDS (session not capped), there is no
    baseline: refused is False and nothing counts as escalation even if bridged
    also succeeds."""
    from zipmi.cli.zipmi import cmd_bridging_privesc
    s = _S({
        (0x06, 0x42, bytes([0x00])): _CH0_INFO,
        (0x06, 0x3B, bytes([0x04])): (0x00, bytes([0x04])),   # direct GRANTED admin
        (0x06, 0x34): (0x00, _ipmb_reply(0x3B, 0x00, bytes([0x04]))),
    })
    rc, d = _run(monkeypatch, cmd_bridging_privesc, s, channel="all", max_priv="admin")
    assert rc == 0
    assert d["direct"]["refused"] is False
    assert d["escalation_found"] is False


# === channel getaccess ===================================================

def test_channel_getaccess_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_channel_getaccess
    # byte0 max_uid=0x10=16; byte1 0x41 -> enabled_status=1(enabled), count=1;
    # byte2 fixed=2; byte3 0x14 -> priv=4(admin), msg on(0x10), link off, callin on
    s = _S({(0x06, 0x44, bytes([0x01, 0x02])): (0x00, bytes([0x10, 0x41, 0x02, 0x14]))})
    rc, d = _run(monkeypatch, cmd_channel_getaccess, s, channel=1, user_id=2)
    assert rc == 0
    assert d["channel"] == 1 and d["user_id"] == 2
    assert d["max_user_ids"] == 16
    assert d["enabled_user_count"] == 1
    assert d["fixed_name_users"] == 2
    assert d["enable_status"] == {"code": 1, "name": "enabled"}
    assert d["ipmi_messaging"] is True
    assert d["link_authentication"] is False
    assert d["callin_callback"] is True
    assert d["privilege_level"] == {"code": 4, "name": "admin"}


# === i2c / spd ===========================================================

def test_i2c_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_i2c
    # bus=public,chan=0 -> bus_byte 0; slave 0x50 -> (0x50<<1)=0xA0; read 2, no write
    s = _S({(0x06, 0x52, bytes([0x00, 0xA0, 0x02])): (0x00, bytes([0xDE, 0xAD]))})
    rc, d = _run(monkeypatch, cmd_i2c, s, tokens=["0x50", "2"])
    assert rc == 0
    assert d == {"bus_byte": 0, "slave": 0x50, "read_count": 2, "data": "dead"}


def test_i2cscan_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_i2cscan
    # 0x50 present (cc 0, returns 0xAB), everything else defaults to cc 0xC1
    s = _S({(0x06, 0x52, bytes([0x00, 0x50 << 1, 0x01])): (0x00, bytes([0xAB]))})
    rc, d = _run(monkeypatch, cmd_i2cscan, s, tokens=[], lo=0x50, hi=0x52)
    assert rc == 0
    assert d["bus_byte"] == 0 and d["found"] == 1
    assert d["devices"] == [{"addr_7bit": 0x50, "addr_8bit": 0xA0, "read1": "ab"}]


def test_i2c_id_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_i2c_id
    # reg 0xFE (SMBus MfrID) answers 0x1234; all other regs + the plain 16-read
    # default to cc 0xC1 (NAK), so plain_read_16 stays None.
    s = _S({(0x06, 0x52, bytes([0x00, 0x50 << 1, 0x01, 0xFE])): (0x00, bytes([0x12, 0x34]))})
    rc, d = _run(monkeypatch, cmd_i2c_id, s, tokens=["0x50"])
    assert rc == 0
    assert d["slave"] == 0x50 and d["plain_read_16"] is None
    by_reg = {r["reg"]: r for r in d["registers"]}
    assert by_reg[0xFE]["value"] == "1234" and by_reg[0xFE]["cc"] == 0
    assert by_reg[0xFF]["value"] is None and by_reg[0xFF]["cc"] == 0xC1


def test_spd_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_spd
    # size=16 -> one 16-byte MWR at offset 0 (write byte = 0x00)
    payload = bytes(range(16))
    s = _S({(0x06, 0x52, bytes([0x00, 0x50 << 1, 0x10, 0x00])): (0x00, payload)})
    rc, d = _run(monkeypatch, cmd_spd, s, tokens=["0x50"], size=16)
    assert rc == 0
    assert d == {"bus_byte": 0, "slave": 0x50, "size": 16, "data": payload.hex()}


# === serial set (action) =================================================

def test_serial_set_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_serial_set
    # Set Serial/Modem Config 0x0C/0x10, body = [channel, param] + data
    s = _S({(0x0C, 0x10, bytes([0x01, 0x03, 0xAA, 0xBB])): (0x00, b"")})
    rc, d = _run(monkeypatch, cmd_serial_set, s,
                 yes=True, channel=1, param="3", hexdata="aabb")
    assert rc == 0
    assert d == {"ok": True, "action": "serial-set", "channel": 1,
                 "param": 3, "data": "aabb"}


# === raw =================================================================

def test_raw_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_raw
    s = _S({(0x06, 0x01): (0x00, bytes([0x20, 0x01, 0x02]))})
    rc, d = _run(monkeypatch, cmd_raw, s, netfn="0x06", cmd="0x01", data=[])
    assert rc == 0
    assert d["netfn"] == 6 and d["cmd"] == 1 and d["cc"] == 0
    assert d["data"] == "200102"


# === sessionless list (static) ===========================================

def test_sessionless_list_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sessionless_list, PRE_SESSION_CMDS
    rc, d = _run(monkeypatch, cmd_sessionless_list, _S({}))
    assert rc == 0
    assert len(d["commands"]) == len(PRE_SESSION_CMDS)
    # Get System GUID (0x06/0x37) must be in the sessionless set.
    assert {"netfn": 0x06, "cmd": 0x37, "name": PRE_SESSION_CMDS[(0x06, 0x37)]} in d["commands"]


# === fuzz / scan leaves ==================================================

def test_fuzz_list_json():
    """fuzz list --json -> {harnesses:[{verb,state,module,description}]}."""
    import io, contextlib
    from zipmi.cli.zipmi import cmd_fuzz_list
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_fuzz_list(argparse.Namespace(json=True))
    d = json.loads(buf.getvalue())
    assert rc == 0
    assert [h["verb"] for h in d["harnesses"]] == ["sweep", "rakp", "length", "cipher"]
    assert d["harnesses"][0]["module"] == "zipmi.fuzz.sweep"


# === oem dispatcher (oem_cmds.py) ========================================
# Two output modes per dispatcher: catalog/listing (pure, no session) and
# execution (scripted send_raw). Both must honor --json.

@pytest.fixture
def _clean_oem_registry():
    """Building a vendor catalog/listing re-runs every vendor's register() into
    the process-wide OEM_CMD_NAMES dict (same side effect the text path has). One
    shared wire key, (0x30,0x70), is claimed by BOTH supermicro (as
    OEMCommandSet_70) and supermicro-x14 (as "SMC OEM pre-auth"); whichever
    registers last wins. The catalog builds x14 too, so it leaves x14 as the
    winner — which flips test_oem's OEMCommandSet_70 assertion. The registry is a
    process-global with no clean baseline (obs 24970: test_oem is already
    order-dependent), so on teardown we re-register supermicro last, restoring the
    (0x30,0x70) name a normal `load_vendor("supermicro")` session yields, without
    clearing keys other vendor tests rely on having loaded."""
    import importlib
    import zipmi.scapy_ipmi.oem.supermicro as _sm
    import zipmi.scapy_ipmi.oem.dell as _dell
    yield
    # dell/megarac also collide on NetFn 0x30 (e.g. (0x30,0xC0)); reload both
    # canonical modules so their register() runs last and reclaims their keys.
    importlib.reload(_sm)     # reclaims (0x30,0x70) -> OEMCommandSet_70
    importlib.reload(_dell)   # reclaims (0x30,0xC0) -> Dell PROCHOTThrottle


def _cap(fn, **kw):
    """Run a cmd_ func with json=True, no session; return (rc, parsed-json)."""
    import io, contextlib
    kw.setdefault("json", True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(argparse.Namespace(**kw))
    return rc, json.loads(buf.getvalue())


def test_oem_vendor_catalog_json(_clean_oem_registry):
    """`zipmi oem` --json -> {vendors:[...]} with real per-vendor rows."""
    from zipmi.cli.oem_cmds import cmd_oem_list_vendors
    rc, d = _cap(cmd_oem_list_vendors, vendor=None)
    assert rc == 0
    by = {v["vendor"]: v for v in d["vendors"]}
    assert by["idrac6"]["iana"] == 674            # Dell PEN
    assert by["idrac6"]["named"] > 0
    assert by["openbmc"]["flavors"] == 9          # nine OpenBMC flavors collapse


def test_oem_vendor_listing_json(_clean_oem_registry):
    """`zipmi oem idrac6` --json -> {commands:[...]} — a self-describing array,
    not a hex-keyed dict. A known cmd must be present with its wire bytes."""
    from zipmi.cli.oem_cmds import cmd_oem_run
    rc, d = _cap(lambda a: cmd_oem_run(a, "idrac6"), cmd_name=None, data=[])
    assert rc == 0
    assert d["vendor"] == "idrac6" and d["named"] > 0
    names = {c["name"] for c in d["commands"]}
    assert "GetSystemRestartCause" in names
    src = next(c for c in d["commands"] if c["name"] == "GetSystemRestartCause")
    assert src["netfn"] == 0x00 and src["cmd"] == 0x07


def test_openbmc_flavors_json(_clean_oem_registry):
    """`zipmi oem openbmc` --json -> {flavors:[...]} with the openbmc-<v> verb."""
    from zipmi.cli.oem_cmds import cmd_openbmc_index
    rc, d = _cap(cmd_openbmc_index, cmd_name=None)
    assert rc == 0
    by = {f["vendor"]: f for f in d["flavors"]}
    assert by["intel"]["verb"] == "openbmc-intel" and by["intel"]["iana"] == 343


def test_oem_run_execution_json(monkeypatch, _clean_oem_registry):
    """`zipmi oem idrac6 GetSystemRestartCause` --json -> raw-shaped record
    (netfn/cmd/cc/data) mirroring cmd_raw. GetSystemRestartCause resolves to
    NetFn 0x00 cmd 0x07 with no data prefix."""
    import zipmi.cli.zipmi as Z
    from zipmi.cli.oem_cmds import cmd_oem_run
    s = _S({(0x00, 0x07, b""): (0x00, bytes([0xDE, 0xAD]))})
    monkeypatch.setattr(Z, "_open_session", lambda a: s)
    rc, d = _cap(lambda a: cmd_oem_run(a, "idrac6"),
                 host="t", cmd_name="GetSystemRestartCause", data=[])
    assert rc == 0
    assert d["vendor"] == "idrac6" and d["name"] == "GetSystemRestartCause"
    assert d["netfn"] == 0x00 and d["cmd"] == 0x07
    assert d["cc"] == 0 and d["data"] == "dead"


# === groups dispatcher (groups_cmds.py) ==================================

def test_groups_catalog_json():
    """`zipmi groups` --json -> {bodies:[...]} — dcmi carries group code 0xDC."""
    from zipmi.cli.groups_cmds import cmd_groups_list
    rc, d = _cap(cmd_groups_list, body=None)
    assert rc == 0
    dcmi = next(b for b in d["bodies"] if b["body"] == "dcmi")
    assert dcmi["code"] == 0xDC and dcmi["commands"] > 0


def test_group_body_listing_json():
    """`zipmi groups dcmi` --json -> {body,code,commands:[...]} with the
    `discover` verb resolving to NetFn 0x2C cmd 0x01, group 0xDC."""
    from zipmi.cli.groups_cmds import cmd_group_run
    rc, d = _cap(lambda a: cmd_group_run(a, "dcmi"), cmd_name=None, data=[])
    assert rc == 0
    assert d["body"] == "dcmi" and d["code"] == 0xDC
    disc = next(c for c in d["commands"] if c["verb"] == "discover")
    assert disc["netfn"] == 0x2C and disc["cmd"] == 0x01 and disc["group_code"] == 0xDC


def test_group_run_execution_json(monkeypatch):
    """`zipmi dcmi discover` --json -> raw-shaped record; the echoed group-code
    byte (0xDC) is stripped from data, matching the text view."""
    import zipmi.cli.zipmi as Z
    from zipmi.cli.groups_cmds import cmd_group_run
    # discover = cmd 0x01, no verb prefix; payload = [0xDC]; reply echoes 0xDC.
    s = _S({(0x2C, 0x01, bytes([0xDC])): (0x00, bytes([0xDC, 0x01, 0x00, 0x02]))})
    monkeypatch.setattr(Z, "_open_session", lambda a: s)
    rc, d = _cap(lambda a: cmd_group_run(a, "dcmi"),
                 host="t", cmd_name="discover", data=[])
    assert rc == 0
    assert d["body"] == "dcmi" and d["verb"] == "discover"
    assert d["netfn"] == 0x2C and d["cmd"] == 0x01 and d["group_code"] == 0xDC
    assert d["cc"] == 0 and d["data"] == "010002"     # 0xDC stripped


# === chassis reads (Get Chassis Capabilities, Get POH Counter) ===========

def test_chassis_caps_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_caps
    # flags 0x0f = all four caps set; addrs 0x20/0x21/0x22/0x23 (+bridge 0x24)
    s = _S({(0x00, 0x00): (0x00, bytes([0x0F, 0x20, 0x21, 0x22, 0x23, 0x24]))})
    rc, d = _run(monkeypatch, cmd_chassis_caps, s)
    assert rc == 0
    assert d["intrusion_sensor"] and d["front_panel_lockout"]
    assert d["diagnostic_interrupt"] and d["power_interlock"]
    assert d["fru_device_addr"] == 0x20 and d["sel_device_addr"] == 0x22
    assert d["bridge_device_addr"] == 0x24


def test_chassis_poh_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_chassis_poh
    # 60 min/count, counter=20 (LE) -> 20*60/60 = 20.0 hours
    s = _S({(0x00, 0x0F): (0x00, bytes([60, 20, 0, 0, 0]))})
    rc, d = _run(monkeypatch, cmd_chassis_poh, s)
    assert rc == 0
    assert d["minutes_per_count"] == 60 and d["counter"] == 20 and d["hours"] == 20.0


# === app (NetFn 0x06) reads =============================================

def test_mc_global_enables_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_mc_global_enables
    # 0x1A = bit4 (SEL) + bit3 (event msg buffer) + bit1 (recv msg queue int)
    s = _S({(0x06, 0x2F): (0x00, bytes([0x1A]))})
    rc, d = _run(monkeypatch, cmd_mc_global_enables, s)
    assert rc == 0
    assert d["system_event_logging"] is True
    assert d["event_message_buffer"] is True
    assert d["event_message_buffer_full_interrupt"] is False
    assert d["receive_message_queue_interrupt"] is True
    assert d["oem_0"] is False and d["oem_1"] is False and d["oem_2"] is False


def test_mc_acpi_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_mc_acpi
    # byte0=0x05 (S5 soft-off), byte1=0x80|0x03 -> low7 = D3, bit7 reserved ignored
    s = _S({(0x06, 0x07): (0x00, bytes([0x05, 0x83]))})
    rc, d = _run(monkeypatch, cmd_mc_acpi, s)
    assert rc == 0
    assert d["system_power_state"] == 0x05
    assert d["system_power_state_name"] == "S5/G2 soft-off"
    assert d["device_power_state"] == 0x03
    assert d["device_power_state_name"] == "D3"


def test_mc_sysinfo_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_mc_sysinfo
    # set-in-progress read: rev, set-in-progress=0
    # sysinfo string param blocks: [rev, set-sel, encoding+len, chars...]
    def strblock(text):
        b = text.encode()
        return (0x00, bytes([0x11, 0x00, len(b)]) + b)
    responses = {
        (0x06, 0x59, bytes([0x00, 0x00, 0x00, 0x00])): (0x00, bytes([0x11, 0x00])),
        (0x06, 0x59, bytes([0x00, 1, 0, 0x00])): strblock("2.75"),
        (0x06, 0x59, bytes([0x00, 2, 0, 0x00])): strblock("bmc-host"),
        (0x06, 0x59, bytes([0x00, 3, 0, 0x00])): strblock("Linux"),
        (0x06, 0x59, bytes([0x00, 4, 0, 0x00])): strblock("Ubuntu"),
    }
    s = _S(responses)
    rc, d = _run(monkeypatch, cmd_mc_sysinfo, s)
    assert rc == 0
    assert d["set_in_progress"] == 0
    by = {p["name"]: p["value"] for p in d["parameters"]}
    assert by["system-fw-version"] == "2.75"
    assert by["hostname"] == "bmc-host"
    assert by["primary-os-name"] == "Linux"
    assert by["os-name"] == "Ubuntu"


def test_channel_payload_support_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_channel_payload_support
    # standard mask 0x0003 (types 0,1 = IPMI, SOL); session-setup 0x0002 (type 1);
    # oem 0x0000
    s = _S({(0x06, 0x4E, bytes([0x0E])):
            (0x00, bytes([0x03, 0x00, 0x02, 0x00, 0x00, 0x00]))})
    rc, d = _run(monkeypatch, cmd_channel_payload_support, s, channel=0x0E)
    assert rc == 0
    assert d["standard_mask"] == 0x0003
    assert d["standard_types"] == [0, 1]
    assert d["session_setup_types"] == [1]
    assert d["oem_types"] == []


def test_channel_payload_version_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_channel_payload_version
    # BCD 0x15 -> MS nibble = major = 1, LS nibble = minor = 5 (spec §24.8)
    s = _S({(0x06, 0x4F, bytes([0x0E, 0x01])): (0x00, bytes([0x15]))})
    rc, d = _run(monkeypatch, cmd_channel_payload_version, s,
                 channel=0x0E, payload_type=1)
    assert rc == 0
    assert d["raw"] == 0x15 and d["major"] == 1 and d["minor"] == 5


def test_sol_payload_instance_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sol_payload_instance
    # session id 0xA1B2C3D4 (LE), port info 0x01
    s = _S({(0x06, 0x4B, bytes([0x01, 0x01])):
            (0x00, bytes([0xD4, 0xC3, 0xB2, 0xA1, 0x01]))})
    rc, d = _run(monkeypatch, cmd_sol_payload_instance, s, instance=1)
    assert rc == 0
    assert d["session_id"] == 0xA1B2C3D4
    assert d["port_info"] == 0x01


# === storage reads (SDR/SEL alloc, SDR time, SEL UTC offset) =============

def test_sdr_alloc_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sdr_alloc
    # alloc_units=100, unit_size=16, free_units=42, largest_free=40, max_rec=64
    s = _S({(0x0A, 0x21): (0x00, bytes([100, 0, 16, 0, 42, 0, 40, 0, 64]))})
    rc, d = _run(monkeypatch, cmd_sdr_alloc, s)
    assert rc == 0
    assert d["alloc_units"] == 100 and d["alloc_unit_size"] == 16
    assert d["free_units"] == 42 and d["largest_free_block"] == 40
    assert d["max_record_size"] == 64


def test_sdr_time_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sdr_time
    # 0x60000000 = past the pre-init threshold; assert raw + a formatted string
    s = _S({(0x0A, 0x28): (0x00, bytes([0x00, 0x00, 0x00, 0x60]))})
    rc, d = _run(monkeypatch, cmd_sdr_time, s)
    assert rc == 0
    assert d["raw"] == 0x60000000 and d["pre_init"] is False
    assert isinstance(d["time"], str) and d["time"]


def test_sel_alloc_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sel_alloc
    # alloc_units=512, unit_size=16, free_units=500, largest_free=498, max_rec=16
    s = _S({(0x0A, 0x41): (0x00, bytes([0x00, 0x02, 16, 0, 0xF4, 0x01, 0xF2, 0x01, 16]))})
    rc, d = _run(monkeypatch, cmd_sel_alloc, s)
    assert rc == 0
    assert d["alloc_units"] == 512 and d["alloc_unit_size"] == 16
    assert d["free_units"] == 500 and d["largest_free_block"] == 498
    assert d["max_record_size"] == 16


def test_sel_utc_offset_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sel_utc_offset
    # -480 minutes = 0xFE20 LE (PST, UTC-8); signed decode must yield -480
    s = _S({(0x0A, 0x5C): (0x00, bytes([0x20, 0xFE]))})
    rc, d = _run(monkeypatch, cmd_sel_utc_offset, s)
    assert rc == 0
    assert d["offset_minutes"] == -480 and d["hours"] == -8.0
    assert d["unspecified"] is False


def test_sel_utc_offset_unspecified_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sel_utc_offset
    s = _S({(0x0A, 0x5C): (0x00, bytes([0xFF, 0xFF]))})   # 0xFFFF = -1 = unspecified
    rc, d = _run(monkeypatch, cmd_sel_utc_offset, s)
    assert rc == 0
    assert d["offset_minutes"] == -1 and d["unspecified"] is True


# === transport reads (IP/UDP/RMCP statistics) ============================

def test_lan_stats_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_lan_stats
    # 7 u16 LE counters; ip_pkts_rx = 0x0100 = 256, rmcp_pkts_rx = 7
    payload = bytes([1, 0, 2, 0, 3, 0, 4, 0, 0x00, 0x01, 5, 0, 7, 0])
    s = _S({(0x0C, 0x04, bytes([0x0E, 0x00])): (0x00, payload)})
    rc, d = _run(monkeypatch, cmd_lan_stats, s, channel="0x0E")
    assert rc == 0
    assert d["channel"] == 0x0E
    assert d["ip_hdr_errors"] == 1 and d["ip_addr_errors"] == 2
    assert d["fragments_rx"] == 3 and d["ip_pkts_tx"] == 4
    assert d["ip_pkts_rx"] == 256 and d["rx_pkts_dropped"] == 5
    assert d["rmcp_pkts_rx"] == 7


# === NetFn 0x04 (Sensor/Event) read commands =============================

def test_sdr_device_info_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sdr_device_info
    # 42 sensors, flags 0x0B = dynamic(bit0) + LUN1(bit1) + LUN3(bit3);
    # bits[3:1] map to LUN1/LUN2/LUN3 -> [True, False, True]
    s = _S({(0x04, 0x20): (0x00, bytes([42, 0x0B]))})
    rc, d = _run(monkeypatch, cmd_sdr_device_info, s)
    assert rc == 0
    assert d["sensor_count"] == 42
    assert d["dynamic_population"] is True
    assert d["lun_sensors"] == [True, False, True]


def test_sdr_device_reserve_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sdr_device_reserve
    s = _S({(0x04, 0x22): (0x00, bytes([0x34, 0x12]))})   # 0x1234 LE
    rc, d = _run(monkeypatch, cmd_sdr_device_reserve, s)
    assert rc == 0
    assert d["reservation_id"] == 0x1234


def test_sensor_type_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sensor_type
    # sensor type 0x01 (temperature), event/reading type 0x01 (threshold)
    s = _S({(0x04, 0x2F, bytes([0x05])): (0x00, bytes([0x01, 0x01]))})
    rc, d = _run(monkeypatch, cmd_sensor_type, s, num="0x05")
    assert rc == 0
    assert d["sensor_number"] == 5
    assert d["sensor_type"] == 0x01 and d["event_reading_type"] == 0x01


def test_sensor_event_enable_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sensor_event_enable
    # flags 0xC0 = all-msgs + scan enabled; assert mask 0x7A95, deassert 0x0000
    s = _S({(0x04, 0x29, bytes([0x05])):
            (0x00, bytes([0xC0, 0x95, 0x7A, 0x00, 0x00]))})
    rc, d = _run(monkeypatch, cmd_sensor_event_enable, s, num="5")
    assert rc == 0
    assert d["all_event_msgs_enabled"] is True and d["scanning_enabled"] is True
    assert d["assertion_mask"] == 0x7A95
    assert d["deassertion_mask"] == 0x0000


def test_sensor_event_status_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sensor_event_status
    s = _S({(0x04, 0x2B, bytes([0x05])):
            (0x00, bytes([0x80, 0x02, 0x00, 0x00, 0x00]))})
    rc, d = _run(monkeypatch, cmd_sensor_event_status, s, num="5")
    assert rc == 0
    assert d["event_msgs_enabled"] is True
    assert d["assertion_status"] == 0x0002
    assert d["deassertion_status"] == 0x0000


def test_sensor_factors_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sensor_factors
    # M=1 (low=1, high bits=0), B=0, R-exp=0xF (-1), B-exp=0 -> byte6=0xF0
    s = _S({(0x04, 0x23, bytes([0x05, 0x00])):
            (0x00, bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xF0]))})
    rc, d = _run(monkeypatch, cmd_sensor_factors, s, num="5")
    assert rc == 0
    assert d["m"] == 1 and d["b"] == 0
    assert d["r_exp"] == -1 and d["b_exp"] == 0


def test_sensor_threshold_raw_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sensor_threshold
    # readable mask 0x30 = uc(bit4)+unr(bit5); no send_cmd on _S -> raw-only.
    # bytes: lnc lc lnr unc uc unr = 00 00 00 00 5A 64
    s = _S({(0x04, 0x27, bytes([0x05])):
            (0x00, bytes([0x30, 0x00, 0x00, 0x00, 0x00, 0x5A, 0x64]))})
    rc, d = _run(monkeypatch, cmd_sensor_threshold, s, num="5")
    assert rc == 0
    assert d["readable_mask"] == 0x30
    assert d["thresholds"]["uc"]["readable"] is True
    assert d["thresholds"]["uc"]["raw"] == 0x5A
    assert d["thresholds"]["uc"]["cooked"] is None    # no SDR meta available
    assert d["thresholds"]["unr"]["raw"] == 0x64
    assert d["thresholds"]["lnc"]["readable"] is False


def test_sensor_hysteresis_raw_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_sensor_hysteresis
    s = _S({(0x04, 0x25, bytes([0x05, 0xFF])): (0x00, bytes([0x02, 0x02]))})
    rc, d = _run(monkeypatch, cmd_sensor_hysteresis, s, num="5")
    assert rc == 0
    assert d["positive_raw"] == 2 and d["negative_raw"] == 2
    assert d["positive_cooked"] is None    # no SDR meta available


def test_pef_caps_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_pef_caps
    # version 0x51, actions 0x2F (alert+pd+reset+pcycle+diag), 40 entries
    s = _S({(0x04, 0x10): (0x00, bytes([0x51, 0x2F, 40]))})
    rc, d = _run(monkeypatch, cmd_pef_caps, s)
    assert rc == 0
    assert d["version"] == 0x51
    assert d["alert"] is True and d["power_down"] is True
    assert d["oem_action"] is False and d["diagnostic_interrupt"] is True
    assert d["event_filter_entries"] == 40


def test_pef_last_event_json(monkeypatch):
    from zipmi.cli.zipmi import cmd_pef_last_event
    # ts=0x00001000, sw=0x0007, bmc=0x0007
    s = _S({(0x04, 0x15): (0x00,
            bytes([0x00, 0x10, 0x00, 0x00, 0x07, 0x00, 0x07, 0x00]))})
    rc, d = _run(monkeypatch, cmd_pef_last_event, s)
    assert rc == 0
    assert d["timestamp"] == 0x1000
    assert d["last_sw_processed"] == 7 and d["last_bmc_processed"] == 7
