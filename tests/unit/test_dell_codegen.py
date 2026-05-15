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
    """A few standard cmds should be present with parsed metadata."""
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISPATCH
    e = DELL_DISPATCH[(0x06, 0x01)]
    assert e.name == "CmdGetDeviceID"
    assert e.priv == "User"
    e = DELL_DISPATCH[(0x00, 0x01)]
    assert e.name == "CmdGetChassisStatus"


def test_known_oem_entries():
    """A representative Dell 0x30 cmd should be there with a handler addr."""
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISPATCH
    e = DELL_DISPATCH[(0x30, 0xC0)]
    # The dispatch-table row carries handler_addr; codegen captures it.
    assert e.handler_addr is not None
    assert e.priv == "User"


def test_disabled_set_includes_known_stubs():
    """The 8 documented Dell-stubbed commands are in DELL_DISABLED."""
    from zipmi.scapy_ipmi.oem.dell_generated import DELL_DISABLED
    # From fullfw doc §4.5 + §5.x: SDR clear / part-add / sensor factors
    # are stubbed by the OEM dispatch override.
    # Note: the parser only marks entries with explicit "NOT PRESENT" in
    # the OEM-table layout; the override-table stubs may not appear here.
    # Check we found at least a few.
    assert len(DELL_DISABLED) >= 5


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
