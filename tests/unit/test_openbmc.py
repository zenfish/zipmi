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
         internal reverse-engineering notes (live QEMU romulus evidence)
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
    """A vendor with no on-wire IANA registers its cmds (resolvable by the
    real wire resolver) but claims no integer enterprise-id slot, so a Get
    Device ID manuf-id of 0 can't resolve to it.

    Assert BEHAVIOR: lookup_cmd_name resolves the Bridge-IC (0x38,0x01)
    slot to "Facebook BIC Info" — this is the (netfn,cmd) 2-tuple fallback
    that register() derives from the 5-tuple wire key
    (0x38,0x01,0x15,0xA0,0x00). A scramble of that key breaks this.
    """
    import zipmi
    zipmi.load_vendor("facebook")
    from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name
    from zipmi.scapy_ipmi.oem._registry import ENTERPRISE_IDS
    assert lookup_cmd_name(0x38, 0x01) == "Facebook BIC Info"
    # No integer enterprise-id slot: a manuf-id lookup (0 = "Unknown", or
    # Meta's own 40981) must NOT resolve back to "facebook".
    assert None not in ENTERPRISE_IDS
    assert ENTERPRISE_IDS.get(0) != "facebook"      # manuf-id 0 unclaimed
    assert ENTERPRISE_IDS.get(40981) != "facebook"  # not on the IANA→vendor map


# --- 5. OpenBMC vendor plugin modules ------------------------------------

@pytest.mark.parametrize("vendor,iana,key,name", [
    ("intel", 343, (0x30, 0x5F), "Intel Set Special User Password"),
    ("intel", 343, (0x08, 0x2C), "Intel FW Image Write Data"),
    # Ampere defines no IANA in source (raw NetFn 0x3C) — iana=None.
    ("ampere", None, (0x3C, 0x18), "Ampere SCP Write Register Map"),
    ("openpower", 2, (0x3A, 0x11), "OpenPower BMC Factory Reset"),
    ("inspur", 37945, (0x3C, 0x01), "Inspur OEM Asset Info"),
])
def test_openbmc_oem_cmds_registered(vendor, iana, key, name):
    """After load_vendor, the REAL wire resolver resolves the (netfn,cmd)
    to the exact command name, and (when the vendor puts an IANA on the
    map) that IANA resolves to the vendor key.

    Asserts resolution, not dict membership: lookup_cmd_name is the
    function label_from_wire/_cmd_label call to name a live packet, and
    ENTERPRISE_IDS[iana] is the IANA→vendor path used by mc-info /
    Get-Device-ID manuf-id resolution. A scrambled name or key fails.
    """
    import zipmi
    zipmi.load_vendor(vendor)
    from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name
    from zipmi.scapy_ipmi.oem._registry import ENTERPRISE_IDS
    assert lookup_cmd_name(key[0], key[1]) == name
    # Reverse: the resolved name round-trips back to the same wire bytes
    # through the CLI name→(netfn,cmd) resolver.
    from zipmi.cli.oem_cmds import _vendor_listing, _find_cmd
    display_name = name[len(vendor):].strip() if name.lower().startswith(
        vendor.lower()) else name
    hits = _find_cmd(_vendor_listing(vendor), display_name)
    assert (key[0], key[1]) in {(h[0], h[1]) for h, _ in hits}
    if iana is not None:
        assert ENTERPRISE_IDS.get(iana) == vendor


def test_wistron_netfn_0x32():
    """Wistron rides NetFn 0x32 (NETFUN_OEM, phosphor api.h:98), not 0x30.

    Resolve BOTH ways: the wire resolver names (0x32,0x02), and the wrong
    NetFn 0x30 does NOT resolve to any Wistron command (0x30 belongs to
    Intel/others). A scramble that moved Wistron onto 0x30 breaks this.
    """
    import zipmi
    zipmi.load_vendor("wistron")
    from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name
    assert lookup_cmd_name(0x32, 0x02) == "Wistron Switch Bittware Image"
    # Nothing Wistron lives on NetFn 0x30 cmd 0x02.
    assert not lookup_cmd_name(0x30, 0x02).startswith("Wistron")


def test_facebook_iana_40981_is_payload_prefix_not_selector():
    """Meta's IANA is 40981 (commandutils.hpp {0x15,0xA0,0x0}, LSB-first
    0x15 0xA0 0x00), not 4337 — and it rides as a PAYLOAD PREFIX on the
    0x38 Bridge-IC commands, never as a NetFn-0x2E enterprise selector.

    Assert the wire consequence, not the constant: the 40981 → 3-byte
    LSB-first encoding is exactly the prefix baked onto the BIC commands
    (auto-supplied by the CLI), and 40981 is NOT on the IANA→vendor map.
    """
    import zipmi
    zipmi.load_vendor("facebook")
    from zipmi.scapy_ipmi.oem.facebook import FACEBOOK_IANA
    from zipmi.scapy_ipmi.oem._registry import ENTERPRISE_IDS
    from zipmi.cli.oem_cmds import _vendor_listing, _find_cmd
    assert FACEBOOK_IANA == 40981
    # 40981 = 0xA015 → LSB-first three bytes 15 a0 00.
    assert FACEBOOK_IANA.to_bytes(3, "little") == bytes.fromhex("15a000")
    # That exact triple is the auto-prepended prefix on "BIC Info".
    (key, info), = _find_cmd(_vendor_listing("facebook"), "BIC Info")
    assert key == (0x38, 0x01, 0x15, 0xA0, 0x00)
    assert info["prefix"] == bytes.fromhex("15a000")
    # Metadata only: it must not sit on the IANA→vendor resolution map.
    assert ENTERPRISE_IDS.get(40981) != "facebook"


def test_openpower_alias_ibm():
    """`ibm` is an alias for the openpower module: loading "ibm" must make
    the openpower wire resolutions live (proves the alias routes to the
    right module, not just that some dict has a key)."""
    import zipmi
    zipmi.load_vendor("ibm")
    from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name
    from zipmi.scapy_ipmi.oem._registry import ENTERPRISE_IDS
    assert lookup_cmd_name(0x32, 0x10) == "OpenPower Prep FW Update"
    # The alias also brought in openpower's IANA (2) → openpower mapping.
    assert ENTERPRISE_IDS.get(2) == "openpower"


def test_google_oem_envelope_and_subcmds():
    """Google rides the real NetFn 0x2E + IANA wire form; the sub-command
    table carries the operations and the IANA encodes LSB-first."""
    import zipmi
    zipmi.load_vendor("google")
    from zipmi.scapy_ipmi.oem.google import (
        GOOGLE_SUBCMDS, GoogleSysCommandReq, GOOGLE_IANA,
    )
    assert GOOGLE_IANA == 11129
    # IANA 11129 = 0x2B79 → LSB-first 79 2b 00, then the sub-cmd byte.
    # Assert the envelope carries the sub-cmd whose name is "Sys Machine
    # Name": resolve the name → its enum byte, then serialize and check the
    # last wire byte IS that byte. Ties the name table to the wire form so a
    # scramble of either the enum or the packet builder fails.
    def _sub(name):
        (b,) = [k for k, v in GOOGLE_SUBCMDS.items() if v == name]
        return b
    for name, expect_last in (("Sys Machine Name", 7), ("Accel OOB Write", 14)):
        b = _sub(name)
        assert b == expect_last  # pinned from commands.hpp enum SysOEMCommands
        frame = bytes(GoogleSysCommandReq(subcmd=b))
        assert frame[:3] == bytes.fromhex("792b00")  # IANA LSB-first
        assert frame[3] == b                          # sub-cmd byte is last
    assert bytes(GoogleSysCommandReq(subcmd=7)).hex() == "792b0007"


def test_nvidia_registers_raw_netfn_3c():
    """Nvidia uses registerHandler(groupNvidia=0x3C, ...) — groupNvidia is in
    the NetFn position, so these are RAW NetFn 0x3C OEM commands, not a 0x2C
    group extension. (Corrected from an earlier mis-modeling.)"""
    import zipmi
    zipmi.load_vendor("nvidia")
    from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name, _cmd_label
    assert lookup_cmd_name(0x3C, 0x36) == "Nvidia Set BIOS Password"
    # NetFn 0x3C is an OEM NetFn: the wire-label resolver tags it [OEM].
    assert _cmd_label(0x3C, 0x36) == "[OEM] Nvidia Set BIOS Password"


def test_sbmr_group_autoloaded():
    """SBMR (group 0xAE) auto-registers on package import (like DCMI).

    Assert the WIRE resolver: a NetFn 0x2C group-extension request whose
    first data byte is the SBMR group code 0xAE and cmd 0x03 must resolve
    to "SBMR Get Boot Progress Code". _cmd_label is what label_from_wire
    calls to name a live group packet — the group code disambiguates
    (0x2C alone is ambiguous). A scramble of the SBMR table breaks this.
    """
    import zipmi.scapy_ipmi.groups  # noqa: F401
    from zipmi.scapy_ipmi.cmd_names import _cmd_label
    # netfn=0x2C (Group Extension), cmd=0x03, first_data=0xAE (SBMR group).
    assert _cmd_label(0x2C, 0x03, first_data=0xAE) == "SBMR Get Boot Progress Code"
    # Same cmd byte under the WRONG group code must NOT resolve to SBMR.
    assert _cmd_label(0x2C, 0x03, first_data=0xDC) != "SBMR Get Boot Progress Code"


def test_openbmc_umbrella_loads_all():
    """The openbmc umbrella loads every vendor table at once."""
    import zipmi
    zipmi.load_vendor("openbmc")
    from zipmi.scapy_ipmi.oem.openbmc import OPENBMC_VENDORS
    from zipmi.scapy_ipmi.cmd_names import lookup_cmd_name
    assert set(OPENBMC_VENDORS) >= {"intel", "google", "ampere", "facebook"}
    # After the umbrella load, the wire resolver names cmds from THREE
    # different vendor modules — proving every table was merged, not just
    # one. Keys are unique to one vendor (raw vendor NetFns overlap — e.g.
    # 0x30/0x01 is both Intel and Wistron — so load_all is last-wins on the
    # shared keys; pick per-vendor-unique keys).
    assert lookup_cmd_name(0x30, 0x5F) == "Intel Set Special User Password"
    assert lookup_cmd_name(0x34, 0x03) == "Foxconn Get System PCIe Info"
    assert lookup_cmd_name(0x3C, 0x18) == "Ampere SCP Write Register Map"
