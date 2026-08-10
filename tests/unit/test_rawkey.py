"""
test_rawkey.py — RawKey (-K / raw Kuid) RAKP PoC.

WHAT   Proves that authenticating with raw key material (RawKey) instead of a
       password yields byte-identical RAKP HMACs, and that an over-length key
       (Dell iDRAC's 32-byte IPMIKey) is accepted verbatim where a password
       would be rejected.

WHY    RAKP authenticates with the Kuid HMAC key, never the password itself.
       So whoever holds the Kuid bytes can complete the handshake without
       knowing/inverting the password. The `-K` flag exposes this; these
       asserts pin the behaviour so a refactor can't silently break the PoC
       or, worse, start padding/truncating a raw key.

RELATED  zipmi/scapy_ipmi/crypto.py (RawKey, pad_password),
         zipmi/cli/zipmi.py (-K/--key), tests/unit/test_rakp.py (oracle).
"""

from __future__ import annotations

import pytest

import zipmi  # noqa: F401  (registers layers)
from zipmi.scapy_ipmi.crypto import (
    CIPHER_SUITES, RawKey, pad_password,
    derive_sik, rakp2_authcode, rakp3_authcode,
)

# Same oracle fixtures as test_rakp.py (Dell iDRAC6, cipher 3).
PW = b"calvin"
SID_C = 0xa0a2a3a4
SID_M = 0x02002600
RC = bytes.fromhex("13dd765a462cac254002aef6e6ba6ec9")
RM = bytes.fromhex("f027ffcf96be8ce7a8e9d88ad175f557")
GUIDM = bytes.fromhex("44454c4c580010548033b5c04f475131")
ROLE = 0x14
UNAME = b"root"


def test_pad_password_passthrough():
    """RawKey is returned verbatim; a normal password is NUL-padded to 16."""
    assert pad_password(PW) == b"calvin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    k = RawKey(bytes.fromhex("00" * 32))
    assert pad_password(k) == bytes(k)        # no padding, no truncation
    assert len(pad_password(k)) == 32


def test_rawkey_over_16_bytes_allowed():
    """A 32-byte key (Dell IPMIKey size) is rejected as a password but fine
    as a RawKey — that's the whole point."""
    big = bytes.fromhex("915F32F49A97456D0D6D66EEE5ED84C8"
                        "94B414AFEB69DADFF891AF14F4B98964")
    with pytest.raises(ValueError):
        pad_password(big)                     # plain bytes > 16 → rejected
    assert pad_password(RawKey(big)) == big   # RawKey → verbatim


def test_rawkey_equivalent_to_password():
    """Holding the Kuid bytes == holding the password, cryptographically.

    Kuid for a password is pad_password(pw). Feeding that exact 16-byte
    value as a RawKey must reproduce the password's RAKP2/RAKP3/SIK codes
    bit-for-bit — i.e. an attacker who exfiltrated the Kuid authenticates
    without ever knowing 'calvin'.
    """
    cs = CIPHER_SUITES[3]
    kuid = RawKey(pad_password(PW))

    # Oracle values from the real Dell iDRAC6 capture (see test_rakp.py).
    assert rakp2_authcode(cs, kuid, SID_C, SID_M, RC, RM, GUIDM, ROLE, UNAME) \
        == bytes.fromhex("bad04a77402721e42a930d574300e195ea42853f")
    assert rakp3_authcode(cs, kuid, SID_C, RM, ROLE, UNAME) \
        == bytes.fromhex("d5d7624b1bab807db28c520f9df3d006d4518c31")
    assert derive_sik(cs, kuid, RC, RM, ROLE, UNAME) \
        == bytes.fromhex("52392ca8e6a9660c23a7f9845cec2b30fd62ce4d")

    # And it equals computing straight from the password.
    assert rakp3_authcode(cs, kuid, SID_C, RM, ROLE, UNAME) \
        == rakp3_authcode(cs, PW, SID_C, RM, ROLE, UNAME)


def test_dell_ipmikey_used_as_sha256_kuid():
    """A 32-byte Dell IPMIKey drives the HMAC-SHA256 suite (17) verbatim:
    no exception, 32-byte auth code, and distinct from the password path."""
    cs = CIPHER_SUITES[17]
    ipmikey = RawKey(bytes.fromhex(
        "915F32F49A97456D0D6D66EEE5ED84C8"
        "94B414AFEB69DADFF891AF14F4B98964"))
    code = rakp3_authcode(cs, ipmikey, SID_C, RM, ROLE, UNAME)
    assert len(code) == 32                                     # SHA-256
    assert code != rakp3_authcode(cs, PW, SID_C, RM, ROLE, UNAME)
    # Regression vector — the RAKP3 message construction is validated by the
    # real-capture SHA1 oracle in test_rawkey_equivalent_to_password; this pins
    # the SHA256 (cipher 17) output so a silently-wrong-but-32-byte HMAC fails,
    # not just a length change.
    assert code == bytes.fromhex(
        "44765895a9624e1e26ceb154e77856707c6d046905d968151396f17416adb561")
