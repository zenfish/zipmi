"""
tests/unit/test_cipher_env.py

WHAT  ZIPMI_CIPHER env default for -C/--cipher, and cipher-suite validation.
WHY   -C has an env fallback like -H/-U/-P; an explicit flag must still win,
      0x-prefixed values must parse, and an unsupported suite (from either the
      flag or the env) must fail loudly instead of dying deep in RAKP.
"""
from __future__ import annotations

import pytest

from zipmi.cli.zipmi import parse_cli, _normalize_interface_cipher
from zipmi.scapy_ipmi.crypto import CIPHER_SUITES


def _resolve(argv):
    ns = parse_cli(argv)
    _normalize_interface_cipher(ns)
    return ns


def test_env_sets_cipher(monkeypatch):
    monkeypatch.setenv("ZIPMI_CIPHER", "17")
    ns = _resolve(["mc", "info"])
    assert ns.cipher == 17
    assert ns.interface == "lanplus"      # a cipher implies RMCP+


def test_env_hex_value(monkeypatch):
    monkeypatch.setenv("ZIPMI_CIPHER", "0x11")
    assert _resolve(["mc", "info"]).cipher == 17


def test_flag_overrides_env(monkeypatch):
    monkeypatch.setenv("ZIPMI_CIPHER", "17")
    assert _resolve(["-C", "3", "mc", "info"]).cipher == 3


def test_unset_is_none(monkeypatch):
    monkeypatch.delenv("ZIPMI_CIPHER", raising=False)
    assert _resolve(["mc", "info"]).cipher is None    # → Session auto-discovers


def test_cipher_zero_is_valid(monkeypatch):
    # suite 0 is the cipher-zero attack surface — a real, supported value.
    monkeypatch.setenv("ZIPMI_CIPHER", "0")
    assert _resolve(["mc", "info"]).cipher == 0


@pytest.mark.parametrize("bad", ["999", "42", "-1"])
def test_unsupported_cipher_exits(monkeypatch, bad):
    monkeypatch.setenv("ZIPMI_CIPHER", bad)
    with pytest.raises(SystemExit) as e:
        _resolve(["mc", "info"])
    assert e.value.code == 2


def test_unsupported_flag_exits(monkeypatch):
    monkeypatch.delenv("ZIPMI_CIPHER", raising=False)
    with pytest.raises(SystemExit) as e:
        _resolve(["-C", "20", "mc", "info"])  # 20 is reserved — not in CIPHER_SUITES
    assert e.value.code == 2


def test_invalid_env_warns_and_ignores(monkeypatch, capsys):
    monkeypatch.setenv("ZIPMI_CIPHER", "notanint")
    ns = _resolve(["mc", "info"])
    assert ns.cipher is None
    assert "not an integer" in capsys.readouterr().err


def test_every_supported_suite_passes(monkeypatch):
    for suite in CIPHER_SUITES:
        monkeypatch.setenv("ZIPMI_CIPHER", str(suite))
        assert _resolve(["mc", "info"]).cipher == suite
