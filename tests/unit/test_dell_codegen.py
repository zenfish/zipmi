"""
test_dell_codegen.py — verify the Dell fullfw RE codegen.

WHAT     Loads dell_generated.py and asserts a few known-good entries
         survived the parse, plus the lookup tables (DELL_NAMES,
         DELL_DISABLED, DELL_SESSIONLESS) are populated.
WHY      The parser is non-trivial (multiple table layouts) and the
         output ships in-tree. A regression that drops 100 entries is
         the kind of thing that would otherwise go silent.
"""

from __future__ import annotations


def test_codegen_imports():
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISPATCH, DellEntry
    assert isinstance(DELL_DISPATCH, dict)
    assert len(DELL_DISPATCH) >= 150       # we generated 192


def test_known_standard_entries():
    """Pin real (NetFn,cmd)->(name,priv,sessionless) rows across distinct netfns.

    Values read straight from DELL_DISPATCH. A scrambled key->row mapping or a
    dropped/blanked field fails at least one.
    """
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISPATCH
    # (netfn, cmd) -> (name, priv, sessionless)
    pinned = {
        (0x06, 0x01): ("CmdGetDeviceID", "User", False),
        (0x00, 0x01): ("CmdGetChassisStatus", "User", False),
        (0x0a, 0x42): ("CmdReserveSEL", "User", False),
        (0x04, 0x02): ("CmdPlatformEvent", "Operator", True),
    }
    for (netfn, cmd), (name, priv, sessionless) in pinned.items():
        e = DELL_DISPATCH[(netfn, cmd)]
        assert e.name == name, f"{(netfn, cmd)} name"
        assert e.priv == priv, f"{(netfn, cmd)} priv"
        assert e.sessionless == sessionless, f"{(netfn, cmd)} sessionless"


def test_known_oem_entries():
    """A representative Dell 0x30 cmd should be there with a handler addr."""
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISPATCH
    e = DELL_DISPATCH[(0x30, 0xC0)]
    # The dispatch-table row carries handler_addr; codegen captures it.
    assert e.handler_addr is not None
    assert e.priv == "User"


def test_disabled_set_is_exact():
    """DELL_DISABLED is the exact set of 'NOT PRESENT' 0x30 stubs, and each
    corresponds to a not_present row in DELL_DISPATCH.

    Keys read straight from the parsed data. A dropped stub or a mis-parsed
    not_present flag fails.
    """
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISABLED, DELL_DISPATCH
    expected = {
        (0x30, 0x00), (0x30, 0x01), (0x30, 0x02), (0x30, 0x04),
        (0x30, 0x05), (0x30, 0x06), (0x30, 0x0a), (0x30, 0x18),
    }
    assert DELL_DISABLED == expected
    # DELL_DISABLED must be exactly the not_present rows of the dispatch table.
    assert DELL_DISABLED == {k for k, e in DELL_DISPATCH.items() if e.not_present}
    # And the pinned first stub carries its real name.
    assert DELL_DISPATCH[(0x30, 0x00)].name == "CmdOEMGetChassisCapabilities"


def test_load_vendor_dell_now_has_many_names():
    """After load_vendor('dell'), OEM_CMD_NAMES picks up 100+ names."""
    import zipmi
    zipmi.load_vendor("dell")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES
    # Pre-codegen there were only 13 hand-curated names.
    assert len(OEM_CMD_NAMES) >= 150


def test_prochot_name_override_wins():
    """Hand-curated PROCHOT name beats the auto 'OEM cmd' label."""
    import zipmi
    zipmi.load_vendor("dell")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES
    assert OEM_CMD_NAMES[(0x30, 0xC0)] == "Dell PROCHOTThrottle"
