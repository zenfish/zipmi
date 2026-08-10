"""
tests/unit/test_scan_cipher_suites.py

WHAT  `zipmi scan cipher-suites` enumerates advertised RMCP+ cipher suites
      (Get Channel Cipher Suites 0x54) and `scan all` includes it.
WHY   The verb was documented in the module header but never wired; the
      enumeration plumbing lived only in bmc_id. This locks the format +
      the cipher-0 warning without a live BMC.
"""
from __future__ import annotations

import argparse
import inspect

import zipmi.cli.zipmi as z
import zipmi.cli.bmc_id as bmc_id


def _args():
    return argparse.Namespace(host="10.0.0.1", port=623, timeout=1.0,
                              verbose=False, debug=False, no_color=True,
                              palette=None)


class _DummyTransport:
    def __init__(self, *a, **k):
        pass

    def close(self):
        pass


def test_scan_cipher_suites_parses():
    ns = z.parse_cli(["scan", "cipher-suites"])
    assert ns.func.__name__ == "cmd_scan_cipher_suites"


def test_scan_all_includes_cipher_suites():
    assert "cmd_scan_cipher_suites" in inspect.getsource(z.cmd_scan_all)


def test_cipher_suites_lists_and_warns_on_zero(monkeypatch, capsys):
    monkeypatch.setattr(z, "Transport", _DummyTransport)
    monkeypatch.setattr(z, "_apply_trace", lambda *a, **k: None)
    monkeypatch.setattr(bmc_id, "probe_cipher_suites",
                        lambda t: {"cipher_list": [0, 3, 17], "cipher0": True})
    rc = z.cmd_scan_cipher_suites(_args())
    out = capsys.readouterr().out
    assert rc == 0
    assert "[0, 3, 17]" in out
    assert "17: sha256/sha256-128/aes-cbc-128" in out
    assert "CVE-2013-4783" in out                 # cipher-0 per-line flag
    assert "cipher suite 0 advertised" in out     # summary warning


def test_cipher_suites_reports_error(monkeypatch, capsys):
    monkeypatch.setattr(z, "Transport", _DummyTransport)
    monkeypatch.setattr(z, "_apply_trace", lambda *a, **k: None)
    monkeypatch.setattr(bmc_id, "probe_cipher_suites",
                        lambda t: {"error": "comp_code=193"})
    rc = z.cmd_scan_cipher_suites(_args())
    out = capsys.readouterr().out
    assert rc == 1
    assert "comp_code=193" in out
