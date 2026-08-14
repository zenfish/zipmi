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

RELATED  IPMI v1.5 specification §13.16
         IPMI v2.0 specification §13.28
"""

from __future__ import annotations

import hashlib


class RawKey(bytes):
    """Marker for raw RAKP key material used verbatim as the HMAC Kuid.

    A normal password becomes the Kuid via NUL-pad-to-16 (`pad_password`).
    A RawKey skips that: it *is* the key bytes already, used as-is with no
    padding and no 16-byte cap. This models authenticating with a
    compromised / externally-derived key instead of knowing the password —
    e.g. Dell iDRAC's 32-byte IPMIKey = SHA256(password‖salt), or an
    OpenBMC `/etc/ipmi_pass` plaintext recovered with the device key_file.

    RAKP never transmits the password; both sides HMAC with the Kuid. So
    whoever holds the Kuid bytes can complete RAKP3 — that's the whole PoC.
    Exposed on the CLI as `zipmi ... -K <hex>`.
    """

    __slots__ = ()


def pad_password(password: str | bytes) -> bytes:
    """Pad an IPMI password to 16 bytes with NULs (IPMI 1.5 §13.16.1).

    A RawKey is returned verbatim — it is already Kuid HMAC-key bytes, not a
    password to pad/truncate.
    """
    if isinstance(password, RawKey):
        return bytes(password)
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
        """Bytes of AuthCode kept. alg 3 (MD5-128) keeps the full 16-byte MD5."""
        return {0: 0, 1: 12, 2: 16, 3: 16, 4: 16}[self.integrity_alg]


# Full standard table per IPMI 2.0 §22.15.2 (Table 22-20). Suites 0..19 are all
# standard: 15-19 are the SHA256 family added by Errata 4 (SHA256/SHA256-128 in
# place of SHA1/SHA1-96). 20..63 reserved; 64..255 OEM.
CIPHER_SUITES: dict[int, CipherSuite] = {
    0:  CipherSuite(0,  0, 0, 0),    # none/none/none — cipher zero!
    1:  CipherSuite(1,  1, 0, 0),    # HMAC-SHA1 / none / none
    2:  CipherSuite(2,  1, 1, 0),    # HMAC-SHA1 / HMAC-SHA1-96 / none
    3:  CipherSuite(3,  1, 1, 1),    # HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128
    4:  CipherSuite(4,  1, 1, 2),    # HMAC-SHA1 / HMAC-SHA1-96 / xRC4-128
    5:  CipherSuite(5,  1, 1, 3),    # HMAC-SHA1 / HMAC-SHA1-96 / xRC4-40
    6:  CipherSuite(6,  2, 0, 0),    # HMAC-MD5  / none / none
    7:  CipherSuite(7,  2, 2, 0),    # HMAC-MD5  / HMAC-MD5-128 / none
    8:  CipherSuite(8,  2, 2, 1),    # HMAC-MD5  / HMAC-MD5-128 / AES-CBC-128
    9:  CipherSuite(9,  2, 2, 2),    # HMAC-MD5  / HMAC-MD5-128 / xRC4-128
    10: CipherSuite(10, 2, 2, 3),    # HMAC-MD5  / HMAC-MD5-128 / xRC4-40
    11: CipherSuite(11, 2, 3, 0),    # HMAC-MD5  / MD5-128 / none
    12: CipherSuite(12, 2, 3, 1),    # HMAC-MD5  / MD5-128 / AES-CBC-128
    13: CipherSuite(13, 2, 3, 2),    # HMAC-MD5  / MD5-128 / xRC4-128
    14: CipherSuite(14, 2, 3, 3),    # HMAC-MD5  / MD5-128 / xRC4-40
    15: CipherSuite(15, 3, 0, 0),    # HMAC-SHA256 / none / none
    16: CipherSuite(16, 3, 4, 0),    # HMAC-SHA256 / HMAC-SHA256-128 / none
    17: CipherSuite(17, 3, 4, 1),    # HMAC-SHA256 / HMAC-SHA256-128 / AES-CBC-128
    18: CipherSuite(18, 3, 4, 2),    # HMAC-SHA256 / HMAC-SHA256-128 / xRC4-128
    19: CipherSuite(19, 3, 4, 3),    # HMAC-SHA256 / HMAC-SHA256-128 / xRC4-40
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


# -- xRC4 confidentiality (§13.30, conf alg 2/3) --------------------------
# THE FIRST OPEN-SOURCE xRC4 IMPLEMENTATION. ipmitool skips it; FreeIPMI lists it
# TODO; no BMC-side stack in the reference trees implements it. Construction is
# per IPMI 2.0 §13.30 + §13.30.2:
#
#   KRC = MD5(K2 || IV)             K2 = derived confidentiality key (same as AES)
#   xRC4-128: RC4 key = KRC (full 16 bytes)
#   xRC4-40 : RC4 key = KRC[:5]     (most-significant 40 bits)
#   Confidentiality header = 4-byte data-offset  + 16-byte IV (IV present only
#                            when offset == 0, i.e. on (re)initialization).
#   No confidentiality trailer (unlike AES-CBC's pad + pad-length).
#
# The spec models a CONTINUOUS per-direction keystream that the 4-byte offset
# resynchronizes past dropped UDP packets. We take the spec's re-initialization
# path every message (offset = 0 + fresh IV), which is self-contained and avoids
# per-session RC4 state — valid for the offset==0 case the spec defines.
#
# Not yet validated against real hardware — still hunting a BMC that actually
# NEGOTIATES xRC4 (every stack examined skips it: ipmitool asserts AES-only,
# FreeIPMI has it TODO, Supermicro's libipmicrypt advertises the suites with no
# rc4 symbol and 0x11-rejects). Got one? Test with:
#     zipmi -C 4 -H <bmc> -U <u> -P <p> mc info   # explicit -> pure xRC4-128 test
# If it prints the BMC's info, encrypt+decrypt round-tripped over xRC4 for real.
# Residual spec ambiguity (RC4 warm-up/discard-N; continuous-offset alignment) can
# only be pinned against such a box. See docs/ipmi20-rakp.md.

def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Plain RC4 (KSA + PRGA). Symmetric — same call encrypts and decrypts."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def _xrc4_key(k2: bytes, iv: bytes, conf_alg: int) -> bytes:
    """KRC = MD5(K2 || IV); xRC4-128 uses all 16 bytes, xRC4-40 the top 5."""
    krc = _hashlib.md5(k2[:16] + iv).digest()
    return krc if conf_alg == 2 else krc[:5]


def xrc4_encrypt(k2: bytes, plaintext: bytes, conf_alg: int,
                 iv: bytes | None = None) -> bytes:
    """Returns  offset(4B=0) || IV(16B) || RC4(KRC, plaintext).
    Offset 0 => this packet (re)initializes the keystream, so the IV is carried."""
    if iv is None:
        iv = _os.urandom(16)
    key = _xrc4_key(k2, iv, conf_alg)
    return b"\x00\x00\x00\x00" + iv + _rc4_crypt(key, plaintext)


def xrc4_decrypt(k2: bytes, body: bytes, conf_alg: int) -> bytes:
    """Reverse: read the 4-byte offset; at offset 0 the 16-byte IV follows and
    KRC = MD5(K2 || IV). (Non-zero offset = mid-stream continuation, which our
    re-init-per-message send path never produces.)"""
    offset = int.from_bytes(body[:4], "little")
    if offset == 0:
        iv, ct = body[4:20], body[20:]
    else:
        iv, ct = b"\x00" * 16, body[4:]
    return _rc4_crypt(_xrc4_key(k2, iv, conf_alg), ct)


# -- Integrity HMAC for in-session messages (§13.30) ----------------------

def integrity_hmac(cipher: CipherSuite, k1: bytes, covered_bytes: bytes) -> bytes:
    """Truncated HMAC over the session header through the next-header byte."""
    h = cipher.integrity_hash
    if h is None:
        return b""
    full = _hmac.new(k1, covered_bytes, h).digest()
    return full[: cipher.integrity_truncate]


def integrity_md5_128(password: str | bytes, covered_bytes: bytes) -> bytes:
    """MD5-128 integrity (§13.28.4, integrity algorithm 03h) — used by cipher
    suites 11-14. Unlike the HMAC integrity algorithms (keyed with the SIK-derived
    K1), MD5-128 is a plain keyed MD5 over the user password (Kuid):

        AuthCode = MD5(Kuid || <integrity-covered data> || Kuid)

    Kuid = the session password, zero-padded to 20 bytes. The full 16-byte MD5
    digest is the AuthCode. ipmitool never implemented this; verified against a
    real Supermicro X10 (the vbmc x10 oracle)."""
    if isinstance(password, str):
        password = password.encode("latin-1")
    kuid = password.ljust(20, b"\x00")[:20]
    return _hashlib.md5(kuid + covered_bytes + kuid).digest()

