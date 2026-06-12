"""
test_openbmc.py — OpenBMC OEM plugin + RMCP+ cipher-17 regression tests.

WHAT     Covers the OpenBMC vendor plugin modules (intel/google/ampere/
         facebook/openpower/inspur/foxconn/wistron/nvidia + the umbrella),
         and the four fixes found while bringing zipmi up against a live
         OpenBMC (romulus) target:
           1. cipher-17 key derivation const length (the K1/K2 bug that
              silently broke every authenticated command on OpenBMC).
           2. ASF presence-pong OEM IANA little-endian decode.
           3. cipher-zero probe requires cipher_suite=0 (no silent
              false-positive path).
           4. OEM registry tolerating iana=None.

RELATED  scapy_ipmi/oem/openbmc.py, scapy_ipmi/crypto.py,
         /Users/zen/phd/bmc/openbmc/LIVE-QEMU-romulus.md (live evidence)
"""

from __future__ import annotations

import pytest


# --- 1. cipher-17 key derivation (the headline bug) ----------------------

def test_key_deriv_const_is_20_bytes():
    """K1/K2 constants are a FIXED 20 bytes, not len(SIK).

    With a 32-byte SHA-256 SIK the old `b"\\x01" * len(sik)` produced a
    32-byte constant and silently wrong K1/K2 — every cipher-17 in-session
    message then failed the BMC integrity check. Lock the length at 20.
    """
    from zipmi.scapy_ipmi.crypto import _KEY_DERIV_CONST_LEN
    assert _KEY_DERIV_CONST_LEN == 20


def test_cipher17_k1_k2_match_ipmitool_vectors():
    """Known-answer: derive_k1/k2 reproduce ipmitool's K1/K2 for a real
    cipher-17 SIK captured from `ipmitool -vvv -C 17` against OpenBMC.
    """
    from zipmi.scapy_ipmi.crypto import CIPHER_SUITES, derive_k1, derive_k2
    sik = bytes.fromhex(
        "7a59b64a65e4d67132bf519036c61f8fcd204a3c10ed10edbabb6466cfe829e5")
    k1 = bytes.fromhex(
        "10d1f3b8d3be0e9ab2dccf396f289e02c950f0d21959340f06177851 23dbcac4"
        .replace(" ", ""))
    k2 = bytes.fromhex(
        "a1149e6eef8d4b4eac7c74d9faae8c86be6bf470762d4d0f24e34169a6a29847")
    cs = CIPHER_SUITES[17]
    assert derive_k1(cs, sik) == k1
    assert derive_k2(cs, sik) == k2


def test_cipher3_k1_unchanged_by_const_fix():
    """SHA-1 cipher 3 (SIK=20) must be unaffected: 20 == len(SIK) there."""
    from zipmi.scapy_ipmi.crypto import CIPHER_SUITES, derive_k1
    import hmac, hashlib
    sik = bytes(range(20))
    cs = CIPHER_SUITES[3]
    assert derive_k1(cs, sik) == hmac.new(sik, b"\x01" * 20, hashlib.sha1).digest()


# --- 2. ASF presence-pong OEM IANA endianness ----------------------------

def test_asf_pong_oem_iana_little_endian():
    """OpenBMC emits ASF's own IANA 4542 as `be 11 00 00` (LSB-first);
    decoding it big-endian yields 3188785152. The pong field must be LE.
    """
    from zipmi.scapy_ipmi.asf import ASFPresencePong
    # 4542 = 0x000011BE; on the wire LSB-first = be 11 00 00.
    body = bytes.fromhex("be110000") + bytes(12)
    pong = ASFPresencePong(body)
    assert pong.oem_iana == 4542


# --- 3. cipher-zero probe guards -----------------------------------------

def test_probe_cipher_zero_requires_cipher0():
    """probe_cipher_zero must refuse a non-zero cipher suite rather than
    pretend to test cipher 0."""
    from zipmi.core import Session, IPMIError
    s = Session(host="192.0.2.1", username=None, password=None,
                lanplus=True, cipher_suite=3, timeout=0.1)
    with pytest.raises(IPMIError):
        s.probe_cipher_zero()


def test_probe_cipher_zero_dead_host_not_vulnerable():
    """A dead/unroutable host must report NOT vulnerable (never the old
    silent false-positive)."""
    from zipmi.core import Session
    # 192.0.2.0/24 (TEST-NET-1) is unroutable; the probe must time out and
    # conclude not-vulnerable, not short-circuit to VULNERABLE.
    s = Session(host="192.0.2.123", username=None, password=None,
                lanplus=True, cipher_suite=0, timeout=0.3)
    s.transport.retries = 0  # keep the test quick
    vulnerable, _ = s.probe_cipher_zero()
    assert vulnerable is False


# --- 4. registry tolerates iana=None -------------------------------------

def test_registry_accepts_none_iana():
    """A vendor with no on-wire IANA registers its cmds but claims no
    integer enterprise-id slot (so a Get Device ID manuf-id of 0 can't
    resolve to it)."""
    import zipmi
    zipmi.load_vendor("facebook")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    assert OEM_CMD_NAMES.get((0x38, 0x01)) == "Facebook BIC Info"
    assert None not in ENTERPRISE_IDS
    assert 0 not in ENTERPRISE_IDS  # manuf-id 0 ("Unknown") stays unclaimed


# --- 5. OpenBMC vendor plugin modules ------------------------------------

@pytest.mark.parametrize("vendor,iana,key,name", [
    ("intel", 343, (0x30, 0x5F), "Intel Set Special User Password"),
    ("intel", 343, (0x08, 0x2C), "Intel FW Image Write Data"),
    ("ampere", 40981, (0x3C, 0x18), "Ampere SCP Write Register Map"),
    ("openpower", 2, (0x3A, 0x11), "OpenPower BMC Factory Reset"),
    ("inspur", 37945, (0x3C, 0x01), "Inspur OEM Asset Info"),
])
def test_openbmc_oem_cmds_registered(vendor, iana, key, name):
    import zipmi
    zipmi.load_vendor(vendor)
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    assert OEM_CMD_NAMES.get(key) == name
    assert ENTERPRISE_IDS.get(iana) == vendor


def test_openpower_alias_ibm():
    """`ibm` is an alias for the openpower module."""
    import zipmi
    zipmi.load_vendor("ibm")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES
    assert OEM_CMD_NAMES.get((0x32, 0x10)) == "OpenPower Prep FW Update"


def test_google_oem_envelope_and_subcmds():
    """Google rides the real NetFn 0x2E + IANA wire form; the sub-command
    table carries the operations and the IANA encodes LSB-first."""
    import zipmi
    zipmi.load_vendor("google")
    from zipmi.scapy_ipmi.oem.google import (
        GOOGLE_SUBCMDS, GoogleSysCommandReq, GOOGLE_IANA,
    )
    assert GOOGLE_SUBCMDS[7] == "Sys Machine Name"
    assert GOOGLE_SUBCMDS[14] == "Accel OOB Write"
    # IANA 11129 = 0x2B79 → LSB-first 79 2b 00, then sub-cmd 7.
    assert bytes(GoogleSysCommandReq(subcmd=7)).hex() == "792b0007"
    assert GOOGLE_IANA == 11129


def test_nvidia_registers_in_group_namespace():
    """Nvidia is a group extension (group 0x3C under NetFn 0x2C), so it
    populates the GROUP registry, not the OEM registry."""
    import zipmi
    zipmi.load_vendor("nvidia")
    from zipmi.scapy_ipmi.groups._registry import GROUP_CMD_NAMES
    assert GROUP_CMD_NAMES.get((0x3C, 0x36)) == "Nvidia Set BIOS Password"


def test_sbmr_group_autoloaded():
    """SBMR (group 0xAE) auto-registers on package import (like DCMI)."""
    import zipmi.scapy_ipmi.groups  # noqa: F401
    from zipmi.scapy_ipmi.groups._registry import GROUP_CMD_NAMES
    assert GROUP_CMD_NAMES.get((0xAE, 0x03)) == "SBMR Get Boot Progress Code"


def test_openbmc_umbrella_loads_all():
    """The openbmc umbrella loads every vendor table at once."""
    import zipmi
    zipmi.load_vendor("openbmc")
    from zipmi.scapy_ipmi.oem.openbmc import OPENBMC_VENDORS
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES
    assert set(OPENBMC_VENDORS) >= {"intel", "google", "ampere", "facebook"}
    # Representative NON-colliding cmds from different vendors are present.
    # (Raw vendor NetFns overlap across vendors — e.g. 0x30/0x01 is both
    # Intel and Wistron — so load_all is last-wins on the shared keys; pick
    # keys unique to one vendor to assert presence.)
    assert OEM_CMD_NAMES.get((0x30, 0x5F)) == "Intel Set Special User Password"
    assert OEM_CMD_NAMES.get((0x34, 0x03)) == "Foxconn Get System PCIe Info"
    assert OEM_CMD_NAMES.get((0x3C, 0x18)) == "Ampere SCP Write Register Map"
