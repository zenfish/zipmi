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
