"""test_cipher_suites.py — the RC4/MD5 cipher suites (4,5,9,10,11,12,13,14) that
zipmi implements and ipmitool/FreeIPMI do not.

MD5-128 integrity (alg 3) is oracle-verified against a real Supermicro X10 (the
`vbmc x10` box) AND matches the symbol `MD5_128` in Supermicro's own libipmicrypt.
xRC4 (conf 2/3) is spec-faithful per IPMI 2.0 §13.30 but hardware-unvalidated (no
reachable BMC negotiates it — the X10 advertises the suites but its crypto lib has
no RC4). These tests pin the constructions and mutation-prove them.
"""
from __future__ import annotations

import hashlib
import pytest

from zipmi.scapy_ipmi.crypto import (
    CIPHER_SUITES, CipherSuite,
    integrity_md5_128, xrc4_encrypt, xrc4_decrypt, _xrc4_key,
)


# === suite registration ====================================================

def test_all_standard_suites_0_through_14_plus_17_registered():
    for sid in list(range(0, 15)) + [17]:
        assert sid in CIPHER_SUITES, f"suite {sid} missing"


@pytest.mark.parametrize("sid,triple", {
    4:  (1, 1, 2), 5:  (1, 1, 3), 9:  (2, 2, 2), 10: (2, 2, 3),
    11: (2, 3, 0), 12: (2, 3, 1), 13: (2, 3, 2), 14: (2, 3, 3),
}.items())
def test_new_suite_algorithm_triples(sid, triple):
    cs = CIPHER_SUITES[sid]
    assert (cs.auth_alg, cs.integrity_alg, cs.conf_alg) == triple


def test_integrity_alg3_truncate_is_full_16():
    assert CipherSuite(11, 2, 3, 0).integrity_truncate == 16


# === MD5-128 integrity (alg 3) — FreeIPMI/spec reference ===================

def test_md5_128_matches_freeipmi_construction():
    # AuthCode = MD5(PW20 || data || PW20), password zero-padded to 20 bytes.
    pw, data = "ADMIN", b"\x06\x11\x00the-integrity-covered-bytes\x07"
    kuid = b"ADMIN".ljust(20, b"\x00")
    expected = hashlib.md5(kuid + data + kuid).digest()
    assert integrity_md5_128(pw, data) == expected
    assert len(integrity_md5_128(pw, data)) == 16


def test_md5_128_str_and_bytes_password_equivalent():
    assert integrity_md5_128("ADMIN", b"x") == integrity_md5_128(b"ADMIN", b"x")


def test_md5_128_mutation_data_changes_mac():
    assert integrity_md5_128("ADMIN", b"aaa") != integrity_md5_128("ADMIN", b"aab")


def test_md5_128_mutation_password_changes_mac():
    assert integrity_md5_128("ADMIN", b"x") != integrity_md5_128("admin", b"x")


def test_md5_128_padding_is_20_not_16():
    # A 16-byte-padded construction would differ — pin that we use 20.
    data = b"payload"
    pad16 = hashlib.md5(b"ADMIN".ljust(16, b"\x00") + data + b"ADMIN".ljust(16, b"\x00")).digest()
    assert integrity_md5_128("ADMIN", data) != pad16


# === xRC4 confidentiality (conf 2/3) — §13.30 ==============================

def test_xrc4_key_is_md5_of_k2_and_iv():
    k2, iv = bytes(range(20)), bytes(range(100, 116))
    krc = hashlib.md5(k2[:16] + iv).digest()
    assert _xrc4_key(k2, iv, 2) == krc            # xRC4-128: full 16
    assert _xrc4_key(k2, iv, 3) == krc[:5]        # xRC4-40: top 40 bits


@pytest.mark.parametrize("alg", [2, 3])
def test_xrc4_round_trip(alg):
    k2 = bytes(range(20, 40))
    pt = b"in-session IPMI payload \x00\x01\x02\xff"
    body = xrc4_encrypt(k2, pt, alg)
    assert xrc4_decrypt(k2, body, alg) == pt


@pytest.mark.parametrize("alg", [2, 3])
def test_xrc4_framing_offset0_plus_iv_no_trailer(alg):
    k2, pt = bytes(range(20)), b"abcdef"
    body = xrc4_encrypt(k2, pt, alg)
    assert body[:4] == b"\x00\x00\x00\x00"        # data offset 0
    assert len(body) == 4 + 16 + len(pt)          # offset + IV + ciphertext, no pad trailer


def test_xrc4_fixed_iv_is_deterministic_and_reproducible():
    k2, pt, iv = bytes(range(20)), b"hello", bytes(range(16))
    body = xrc4_encrypt(k2, pt, 2, iv=iv)
    assert body[4:20] == iv
    # decrypt independent of encrypt internals: recompute from KRC
    from zipmi.scapy_ipmi.crypto import _rc4_crypt
    assert _rc4_crypt(_xrc4_key(k2, iv, 2), body[20:]) == pt


def test_xrc4_wrong_key_fails_to_recover():
    k2, pt = bytes(range(20)), b"secret"
    body = xrc4_encrypt(k2, pt, 2)
    assert xrc4_decrypt(b"\x00" * 20, body, 2) != pt


def test_xrc4_128_and_40_produce_different_ciphertext_same_iv():
    k2, pt, iv = bytes(range(20)), b"same-plaintext", bytes(range(16))
    b128 = xrc4_encrypt(k2, pt, 2, iv=iv)[20:]
    b40 = xrc4_encrypt(k2, pt, 3, iv=iv)[20:]
    assert b128 != b40                            # different key length -> different keystream
