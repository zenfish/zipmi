"""
tests/unit/test_maser.py

WHAT  Dell OEM MASER / LifecycleController access-state verb: get (0x30 0xAE)
      and set (0x30 0xAF). Asserts the exact wire bytes + the byte0 state
      mapping (0=enabled, non-zero=disabled) worked out from the iDRAC9
      libmaser.so handler and confirmed live.
WHY   Regression lock: the set byte0 encoding is a destructive-chain
      precondition — a flipped mapping must fail the suite.
"""
import argparse

import zipmi.cli.zipmi as Z


class _S:
    """Scripted session: send_raw(netfn, cmd, data) -> canned (cc, bytes)."""
    def __init__(self, resp):
        self.resp = resp
        self.sent = []

    def send_raw(self, netfn, cmd, data=b""):
        self.sent.append((netfn, cmd, bytes(data)))
        return self.resp.get((netfn, cmd), (0x00, b""))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch(monkeypatch, s):
    monkeypatch.setattr(Z, "_open_session", lambda args: s)


def test_maser_get_sends_2byte_selector_and_decodes(monkeypatch, capsys):
    s = _S({(0x30, 0xAE): (0x00, bytes([0x01, 0x00, 0x00]))})
    _patch(monkeypatch, s)
    rc = Z.cmd_maser_get(argparse.Namespace(json=False))
    assert rc == 0
    assert s.sent == [(0x30, 0xAE, b"\x00\x00")]      # 2-byte selector, not empty
    assert "disabled" in capsys.readouterr().out       # byte0=0x01 -> disabled


def test_maser_get_enabled_decode(monkeypatch, capsys):
    _patch(monkeypatch, _S({(0x30, 0xAE): (0x00, bytes([0x00, 0x00, 0x00]))}))
    assert Z.cmd_maser_get(argparse.Namespace(json=False)) == 0
    assert "enabled" in capsys.readouterr().out


def test_maser_set_enabled_is_byte0_zero(monkeypatch, capsys):
    s = _S({(0x30, 0xAF): (0x00, b"")})
    _patch(monkeypatch, s)
    assert Z.cmd_maser_set(argparse.Namespace(json=False, state="enabled")) == 0
    assert s.sent == [(0x30, 0xAF, b"\x00\x00\x00")]


def test_maser_set_disabled_is_byte0_nonzero(monkeypatch, capsys):
    s = _S({(0x30, 0xAF): (0x00, b"")})
    _patch(monkeypatch, s)
    assert Z.cmd_maser_set(argparse.Namespace(json=False, state="disabled")) == 0
    # byte0 must be non-zero (the disabled/wipe-precondition encoding)
    assert s.sent == [(0x30, 0xAF, b"\x01\x00\x00")]


def test_maser_get_error_cc_returns_1(monkeypatch, capsys):
    _patch(monkeypatch, _S({(0x30, 0xAE): (0xC1, b"")}))
    assert Z.cmd_maser_get(argparse.Namespace(json=False)) == 1


def test_oem_idrac9_maser_routes_get_and_set(monkeypatch):
    # maser lives under `oem idrac9|idrac10` now (Dell OEM, not a top-level verb).
    # `oem idrac9 maser get` -> cmd_maser_get (0x30/0xAE, 2-byte selector).
    sg = _S({(0x30, 0xAE): (0x00, bytes([0x00, 0x00, 0x00]))})
    _patch(monkeypatch, sg)
    ns = Z.parse_cli(["-H", "x", "oem", "idrac9", "maser", "get"])
    assert ns.func(ns) == 0
    assert sg.sent == [(0x30, 0xAE, b"\x00\x00")]
    # `oem idrac9 maser set disabled` -> cmd_maser_set, byte0 non-zero.
    ss = _S({(0x30, 0xAF): (0x00, b"")})
    _patch(monkeypatch, ss)
    ns = Z.parse_cli(["-H", "x", "oem", "idrac9", "maser", "set", "disabled"])
    assert ns.func(ns) == 0
    assert ss.sent == [(0x30, 0xAF, b"\x01\x00\x00")]


def test_top_level_maser_verb_removed():
    import pytest
    with pytest.raises(SystemExit):        # `maser` is no longer a top-level verb
        Z.parse_cli(["maser", "get"])
