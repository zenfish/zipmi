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
