"""
zipmi.scapy_ipmi.crypto — IPMI authentication and (Phase 3) confidentiality.

WHAT     Auth-code helpers for IPMI 1.5 LAN sessions (MD2, MD5, Straight
         Password Key) and the cipher-suite table for IPMI 2.0 RMCP+
         (RAKP/HMAC/AES — Phase 3).

WHY      Centralise the crypto so both the client `Session` and the
         (Phase 5) virtual BMC consume the same primitives. Spec quirks
         (1.5 §13.16.6 byte order, 2.0 §13.28 cipher suite numbering,
         IPMI 2.0 errata 4 byte-order for RAKP HMAC inputs) all live in
         exactly one place.

SUCCESS  `md5_auth_code(b"calvin" + b"\\x00"*10, 0x02000700, ipmb_bytes, 0)`
         matches the AuthCode in a tcpdump capture of `ipmitool -A MD5`
         to Dell iDRAC6 — verified live (oracle pcap, 2026-05-01).

TARGET   IPMI 1.5 §13.16.6 (auth code), IPMI 2.0 §13.28 (cipher suites).

RELATED  /Users/zen/phd/dox/specs/IPMI-1.5.pdf §13.16
         /Users/zen/phd/dox/specs/IPMI2.0-markup.pdf §13.28
"""

from __future__ import annotations

import hashlib


def pad_password(password: str | bytes) -> bytes:
    """Pad an IPMI password to 16 bytes with NULs (IPMI 1.5 §13.16.1)."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if len(password) > 16:
        raise ValueError("IPMI passwords are at most 16 bytes")
    return password.ljust(16, b"\x00")


def md5_auth_code(
    password: bytes | str,
    session_id: int,
    ipmb_message: bytes,
    session_seq: int,
) -> bytes:
    """Compute the IPMI 1.5 MD5 AuthCode (IPMI 1.5 §13.16.6, type 2).

    Formula:
        MD5(password || session_id_LE32 || ipmb_message || session_seq_LE32 || password)

    `ipmb_message` is the full IPMB message bytes (rsAddr through chk2,
    inclusive, 7 + len(data) bytes total). The chk2 byte must already be
    computed; the AuthCode covers it.

    `session_id` is the session ID assigned by the BMC (or the temporary
    one returned by Get Session Challenge for the Activate Session
    request). `session_seq` is 0 for Activate Session and increments
    thereafter.

    Verified against `ipmitool -I lan -A MD5` capture vs Dell iDRAC6.
    """
    pw = pad_password(password)
    sid = (session_id & 0xFFFFFFFF).to_bytes(4, "little")
    seq = (session_seq & 0xFFFFFFFF).to_bytes(4, "little")
    return hashlib.md5(pw + sid + ipmb_message + seq + pw).digest()


def md2_auth_code(
    password: bytes | str,
    session_id: int,
    ipmb_message: bytes,
    session_seq: int,
) -> bytes:
    """IPMI 1.5 MD2 AuthCode (auth type 1).

    Same formula as MD5 but with MD2. MD2 is broken and almost never seen
    in practice; included for completeness because Dell still advertises it.
    Requires `cryptography` (`hashlib` doesn't ship MD2).
    """
    from cryptography.hazmat.primitives import hashes
    pw = pad_password(password)
    sid = (session_id & 0xFFFFFFFF).to_bytes(4, "little")
    seq = (session_seq & 0xFFFFFFFF).to_bytes(4, "little")
    h = hashes.Hash(hashes.MD5())  # placeholder — see below
    # `cryptography` does not expose MD2. We could vendor a pure-python MD2
    # impl, but until we hit a BMC that requires it we'll raise loudly.
    raise NotImplementedError(
        "MD2 auth not implemented; rare in practice. Use MD5 (-A MD5)."
    )


def straight_pwd_auth_code(password: bytes | str, *_: object) -> bytes:
    """IPMI 1.5 Straight Password Key (auth type 4).

    The auth code IS the 16-byte NUL-padded password. The session_id,
    ipmb_message, and session_seq arguments are ignored (kept for a
    uniform call signature alongside the hashed variants).
    """
    return pad_password(password)


# -- IPMI 2.0 RMCP+ cipher suites (§13.28) --------------------------------
#
# Each cipher suite specifies (auth, integrity, confidentiality) algorithms.
# We only model the algorithms commonly seen on real hardware.

import hmac as _hmac
import hashlib as _hashlib
import os as _os

from dataclasses import dataclass


@dataclass(frozen=True)
class CipherSuite:
    """A complete (auth, integrity, conf) triple for RMCP+ §13.28."""

    id: int
    auth_alg: int               # 0=none, 1=HMAC-SHA1, 2=HMAC-MD5, 3=HMAC-SHA256
    integrity_alg: int          # 0=none, 1=HMAC-SHA1-96, 2=HMAC-MD5-128, 4=HMAC-SHA256-128
    conf_alg: int               # 0=none, 1=AES-CBC-128, 2=xRC4-128, 3=xRC4-40

    @property
    def auth_hash(self):
        if self.auth_alg == 0:
            return None
        if self.auth_alg == 1:
            return _hashlib.sha1
        if self.auth_alg == 2:
            return _hashlib.md5
        if self.auth_alg == 3:
            return _hashlib.sha256
        raise ValueError(f"unsupported auth_alg {self.auth_alg}")

    @property
    def integrity_hash(self):
        if self.integrity_alg == 0:
            return None
        if self.integrity_alg == 1:
            return _hashlib.sha1
        if self.integrity_alg == 2:
            return _hashlib.md5
        if self.integrity_alg == 4:
            return _hashlib.sha256
        raise ValueError(f"unsupported integrity_alg {self.integrity_alg}")

    @property
    def integrity_truncate(self) -> int:
        """Bytes of HMAC output kept as the AuthCode."""
        return {0: 0, 1: 12, 2: 16, 4: 16}[self.integrity_alg]


# Full table per IPMI 2.0 §13.28 Table 13-21. Values 0..14 standard;
# 15..63 reserved; 64..255 OEM. Only suites we care about are spelled out.
CIPHER_SUITES: dict[int, CipherSuite] = {
    0:  CipherSuite(0,  0, 0, 0),    # none/none/none — cipher zero!
    1:  CipherSuite(1,  1, 0, 0),    # HMAC-SHA1 / none / none
    2:  CipherSuite(2,  1, 1, 0),    # HMAC-SHA1 / HMAC-SHA1-96 / none
    3:  CipherSuite(3,  1, 1, 1),    # HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128
    6:  CipherSuite(6,  2, 0, 0),    # HMAC-MD5  / none / none
    7:  CipherSuite(7,  2, 2, 0),    # HMAC-MD5  / HMAC-MD5-128 / none
    8:  CipherSuite(8,  2, 2, 1),    # HMAC-MD5  / HMAC-MD5-128 / AES-CBC-128
    17: CipherSuite(17, 3, 4, 1),    # HMAC-SHA256 / HMAC-SHA256-128 / AES-CBC-128
}


# -- RAKP HMAC computations (§13.20–13.22) --------------------------------
#
# Verified byte-for-byte against ipmitool -I lanplus -C 3 oracle pcap vs
# Dell iDRAC6, 2026-05-01.

def rakp2_authcode(
    cipher: CipherSuite,
    password: bytes | str,
    sid_c: int,
    sid_m: int,
    rc: bytes,
    rm: bytes,
    guid_m: bytes,
    role: int,
    user_name: bytes,
) -> bytes:
    """Expected RAKP2 auth code from the BMC: client recomputes and compares."""
    h = cipher.auth_hash
    if h is None:
        return b""
    msg = (
        sid_c.to_bytes(4, "little")
        + sid_m.to_bytes(4, "little")
        + rc + rm + guid_m
        + bytes([role, len(user_name)])
        + user_name
    )
    return _hmac.new(pad_password(password), msg, h).digest()


def rakp3_authcode(
    cipher: CipherSuite,
    password: bytes | str,
    sid_c: int,
    rm: bytes,
    role: int,
    user_name: bytes,
) -> bytes:
    """Auth code we send in RAKP3."""
    h = cipher.auth_hash
    if h is None:
        return b""
    msg = (
        rm
        + sid_c.to_bytes(4, "little")
        + bytes([role, len(user_name)])
        + user_name
    )
    return _hmac.new(pad_password(password), msg, h).digest()


def derive_sik(
    cipher: CipherSuite,
    password: bytes | str,
    rc: bytes,
    rm: bytes,
    role: int,
    user_name: bytes,
) -> bytes:
    """Session Integrity Key (§13.32)."""
    h = cipher.auth_hash
    if h is None:
        return b""
    msg = rc + rm + bytes([role, len(user_name)]) + user_name
    return _hmac.new(pad_password(password), msg, h).digest()


def rakp4_icv(
    cipher: CipherSuite,
    sik: bytes,
    rc: bytes,
    sid_m: int,
    guid_m: bytes,
) -> bytes:
    """Integrity check value the BMC sends in RAKP4 (truncated)."""
    h = cipher.auth_hash
    if h is None:
        return b""
    msg = rc + sid_m.to_bytes(4, "little") + guid_m
    full = _hmac.new(sik, msg, h).digest()
    return full[: cipher.integrity_truncate]


# IPMI 2.0 §13.32 key-derivation constants. Const_n is a FIXED 20-byte
# run of the byte value n (Const1 = 0x01*20, Const2 = 0x02*20) regardless
# of the negotiated auth hash. This is NOT len(SIK): for HMAC-SHA256
# (cipher suite 17) the SIK is 32 bytes, but the constant stays 20.
# Verified against the target BMC's own source — phosphor-net-ipmid
# rmcp.hpp defines `Const_n` as a 20-element array — and against ipmitool
# (lanplus LANPLUS_HMAC_CONST_* are 20 bytes). Using len(SIK) here silently
# breaks cipher 17: K1/K2 come out wrong, so the integrity HMAC and AES key
# mismatch and the BMC drops every encrypted in-session message. Cipher 3
# (SHA1, SIK=20) was unaffected only because 20 == len(SIK) there.
_KEY_DERIV_CONST_LEN = 20


def derive_k1(cipher: CipherSuite, sik: bytes) -> bytes:
    """K1 = HMAC(SIK, 0x01 * 20). Used for integrity HMAC of in-session messages."""
    h = cipher.auth_hash
    if h is None:
        return b""
    return _hmac.new(sik, b"\x01" * _KEY_DERIV_CONST_LEN, h).digest()


def derive_k2(cipher: CipherSuite, sik: bytes) -> bytes:
    """K2 = HMAC(SIK, 0x02 * 20). First 16 bytes used as AES-128 key."""
    h = cipher.auth_hash
    if h is None:
        return b""
    return _hmac.new(sik, b"\x02" * _KEY_DERIV_CONST_LEN, h).digest()


# -- AES-CBC-128 confidentiality (§13.29) ---------------------------------

def aes_encrypt(k2: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    """AES-128-CBC encrypt with IPMI 2.0 self-describing pad. Returns IV || ciphertext."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if iv is None:
        iv = _os.urandom(16)
    pad_len = (-len(plaintext) - 1) % 16
    pad = bytes(range(1, pad_len + 1)) + bytes([pad_len])
    padded = plaintext + pad
    cipher = Cipher(algorithms.AES(k2[:16]), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct


def aes_decrypt(k2: bytes, body: bytes) -> bytes:
    """Reverse of `aes_encrypt`. Strips the IPMI confidentiality trailer."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = body[:16]
    ct = body[16:]
    cipher = Cipher(algorithms.AES(k2[:16]), modes.CBC(iv))
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad_len = pt[-1]
    return pt[: -1 - pad_len]


# -- Integrity HMAC for in-session messages (§13.30) ----------------------

def integrity_hmac(cipher: CipherSuite, k1: bytes, covered_bytes: bytes) -> bytes:
    """Truncated HMAC over the session header through the next-header byte."""
    h = cipher.integrity_hash
    if h is None:
        return b""
    full = _hmac.new(k1, covered_bytes, h).digest()
    return full[: cipher.integrity_truncate]

