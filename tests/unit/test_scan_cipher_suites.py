"""
tests/unit/test_scan_cipher_suites.py

WHAT  Get Channel Cipher Suites (0x54) record decoding + the `scan cipher-suites`
      verb. The parser tests use REAL on-wire bytes — the earlier stub returned
      raw bytes as if they were suite IDs and no test exercised it.
WHY   Regression lock for the by-cipher-suite record format + multi-chunk fetch.
"""
from __future__ import annotations

import argparse
import inspect

import zipmi.cli.zipmi as z
import zipmi.cli.bmc_id as bmc_id
from zipmi.cli.bmc_id import (
    parse_cipher_suite_records, parse_cipher_list, cipher_suite_algs,
    probe_cipher_suites,
)


# ── record parser: the exact bytes a live BMC returned (46.38.49.234) ────────
# C0 00 00 40 80 | C0 01 01 40 80 | C0 02 01 41 80 | C0(<-truncated chunk end)
REAL_CHUNK = bytes([192, 0, 0, 64, 128, 192, 1, 1, 64, 128,
                    192, 2, 1, 65, 128, 192])


def test_real_bytes_decode_to_real_suite_ids():
    recs = parse_cipher_suite_records(REAL_CHUNK)
    # trailing lone 0xC0 has no id → dropped; suites 0,1,2 decode
    assert [r["id"] for r in recs] == [0, 1, 2]
    assert cipher_suite_algs(recs[0]) == "none/none/none"
    assert cipher_suite_algs(recs[1]) == "sha1/none/none"
    assert cipher_suite_algs(recs[2]) == "sha1/sha1-96/none"


def test_stub_regression_no_raw_marker_bytes():
    # the OLD stub returned [0,64,128,192,...]; the fix must never surface a
    # record/type marker (0xC0/0x40/0x80) as a suite ID.
    ids = parse_cipher_list(bytes([0x01]) + REAL_CHUNK)   # +leading channel byte
    assert ids == [0, 1, 2]
    assert 192 not in ids and 64 not in ids and 128 not in ids


def test_full_suite_set_with_aes_and_sha256():
    data = bytes([
        0xC0, 0, 0x00, 0x40, 0x80,      # 0: none/none/none
        0xC0, 3, 0x01, 0x41, 0x81,      # 3: sha1/sha1-96/aes-cbc-128
        0xC0, 17, 0x03, 0x44, 0x81,     # 17: sha256/sha256-128/aes-cbc-128
    ])
    recs = parse_cipher_suite_records(data)
    assert [r["id"] for r in recs] == [0, 3, 17]
    assert cipher_suite_algs(recs[1]) == "sha1/sha1-96/aes-cbc-128"
    assert cipher_suite_algs(recs[2]) == "sha256/sha256-128/aes-cbc-128"


def test_oem_record_carries_iana():
    # C1 <iana LS,mid,MS> <id> <alg...>  — IANA 0x000539 (Nvidia example)
    data = bytes([0xC1, 0x39, 0x05, 0x00, 0x80, 0x03, 0x44, 0x81])
    recs = parse_cipher_suite_records(data)
    assert recs[0]["id"] == 0x80
    assert recs[0]["oem_iana"] == 0x000539


# ── multi-chunk fetch: records spanning two 16-byte fetches ──────────────────
class _Msg:
    def __init__(self, data):
        self.data = data


class _Resp:
    comp_code = 0x00


class _ChunkTransport:
    """Returns a 16-byte chunk on index 0, a short chunk on index 1 (end)."""
    def __init__(self, chunks):
        self.chunks = chunks

    def sessionless_request(self, netfn, cmd, req, rq_seq=0):
        idx = req.list_index & 0x3F
        chunk = self.chunks[idx] if idx < len(self.chunks) else b""
        return _Msg(bytes([0x00, 0x01]) + chunk), _Resp()


def test_probe_multichunk_accumulates_across_boundary():
    # split suite 17's record across the 16-byte boundary
    full = bytes([0xC0, 0, 0x00, 0x40, 0x80,
                  0xC0, 3, 0x01, 0x41, 0x81,
                  0xC0, 17, 0x03, 0x44, 0x81, 0xC0])   # 16B; last 0xC0 starts a rec
    tail = bytes([9, 0x01, 0x40, 0x80])                # id 9 completes in chunk 2
    t = _ChunkTransport([full, tail])
    out = probe_cipher_suites(t)
    assert out["cipher_list"] == [0, 3, 17, 9]
    assert out["cipher0"] is True


# ── verb wiring + display ────────────────────────────────────────────────────
def _args():
    return argparse.Namespace(host="10.0.0.1", port=623, timeout=1.0,
                              verbose=False, debug=False, no_color=True, palette=None)


class _DummyTransport:
    def __init__(self, *a, **k): pass
    def close(self): pass


def test_scan_cipher_suites_parses():
    ns = z.parse_cli(["scan", "cipher-suites"])
    assert ns.func.__name__ == "cmd_scan_cipher_suites"


def test_scan_all_includes_cipher_suites():
    assert "cmd_scan_cipher_suites" in inspect.getsource(z.cmd_scan_all)


def test_cipher_suites_display_uses_records(monkeypatch, capsys):
    monkeypatch.setattr(z, "Transport", _DummyTransport)
    monkeypatch.setattr(z, "_apply_trace", lambda *a, **k: None)
    monkeypatch.setattr(bmc_id, "probe_cipher_suites", lambda t: {
        "cipher_list": [0, 3],
        "cipher0": True,
        "cipher_details": [
            {"id": 0, "auth": 0, "integ": 0, "conf": 0, "oem_iana": None},
            {"id": 3, "auth": 1, "integ": 1, "conf": 1, "oem_iana": None},
        ],
    })
    rc = z.cmd_scan_cipher_suites(_args())
    cap = capsys.readouterr()
    out = cap.out
    assert rc == 0
    assert "[0, 3]" in out
    assert " 0: none/none/none" in out
    assert " 3: sha1/sha1-96/aes-cbc-128" in out
    assert "CVE-2013-4783" in out
    # the suite-0 warning is a diagnostic → stderr, not stdout
    assert "cipher suite 0 advertised" in cap.err
