"""
test_idrac9_commands.py — verify the iDRAC9 rich-command catalog codegen.

WHAT     Loads idrac9_commands_generated.py + the idrac9.py consumer and
         asserts the catalog imports, has all 276 entries, that
         load_vendor("idrac9") still registers, and spot-checks specific
         commands round-trip with correct NetFn/cmd/subcmd/priv.
WHY      The catalog is generated from idrac9-commands.json (276 RE'd +
         adversarially verified commands). A regression that drops entries
         or mis-parses hex NetFn/cmd/subcmd should fail loudly. 43 entries
         are honestly incomplete PLT-shim handlers (request/response=
         "undetermined", confidence contains "unverified") — that is valid,
         intentional data (a non-empty marker), NOT a doc hole, and the
         well-formed test treats it as such. Mirror of
         test_idrac10_commands.py.
"""
from __future__ import annotations

import pytest

from zipmi.scapy_ipmi.oem.idrac9_commands_generated import IDRAC9_COMMANDS

# Named privilege tokens as they appear in the RE doc. iDRAC9 also records
# bare numeric levels ("2", "4") straight off the dispatch byte, so a lone
# digit is a valid priv too.
_PRIVS = ("Admin", "Operator", "User", "Callback", "OEM", "undetermined")


@pytest.mark.parametrize("c", IDRAC9_COMMANDS, ids=lambda c: c.name)
def test_every_command_wellformed(c):
    """One case per catalog entry — a dropped/fabricated/malformed command fails loudly."""
    assert c.name and c.name.strip(), "empty name"
    # netfn/cmd: int in byte range or None (RE couldn't pin it).
    for f in (c.netfn, c.cmd):
        assert f is None or (isinstance(f, int) and 0 <= f <= 0xFF)
    # subcmd: int (multi-byte folded, may exceed 0xff) or None.
    assert c.subcmd is None or isinstance(c.subcmd, int)
    assert isinstance(c.in_band_only, bool)
    # priv is either a named level or a bare numeric dispatch byte.
    priv = c.priv.lower()
    named = any(p.lower() in priv for p in _PRIVS)
    numeric = any(ch.isdigit() for ch in priv)
    assert named or numeric, f"unknown priv {c.priv!r}"
    # These fields were RE'd per command. "undetermined" / "unverified" is a
    # deliberate, non-empty marker for the 42 PLT-shim handlers — valid data,
    # not a hole. Blank IS a hole.
    for field in ("purpose", "request", "response", "confidence", "lib"):
        assert getattr(c, field).strip(), f"empty {field}"


def test_catalog_keys_unique():
    """(name, netfn, cmd, subcmd) is the identity — no dupes survived."""
    keys = [(c.name, c.netfn, c.cmd, c.subcmd) for c in IDRAC9_COMMANDS]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate command keys: {dupes}"


def test_catalog_imports_all():
    from zipmi.scapy_ipmi.oem.idrac9_commands_generated import (
        IDRAC9_COMMANDS, IDrac9Command,
    )
    assert isinstance(IDRAC9_COMMANDS, list)
    assert len(IDRAC9_COMMANDS) == 276
    assert all(isinstance(c, IDrac9Command) for c in IDRAC9_COMMANDS)


def test_hex_fields_parsed_to_int():
    """NetFn/cmd/subcmd land as ints (or None), not the raw '0x..' strings."""
    from zipmi.scapy_ipmi.oem.idrac9_commands_generated import IDRAC9_COMMANDS
    for c in IDRAC9_COMMANDS:
        assert c.netfn is None or isinstance(c.netfn, int)
        assert c.cmd is None or isinstance(c.cmd, int)
        assert c.subcmd is None or isinstance(c.subcmd, int)
        assert isinstance(c.in_band_only, bool)
    # Every iDRAC9 entry has a pinned NetFn/cmd (unlike iDRAC10).
    assert sum(1 for c in IDRAC9_COMMANDS if c.netfn is None) == 0


def test_undetermined_shim_entries_present():
    """The 43 PLT-shim handlers keep their honest 'undetermined' markers."""
    undetermined = [c for c in IDRAC9_COMMANDS if c.request == "undetermined"]
    assert len(undetermined) == 43
    # They are non-empty (so the well-formed test accepts them) and flagged
    # unverified in confidence.
    for c in undetermined:
        assert c.response == "undetermined"
        assert "unverified" in c.confidence.lower()


def test_load_vendor_idrac9_registers():
    """load_vendor('idrac9') populates the OEM registry with catalog names."""
    import zipmi
    zipmi.load_vendor("idrac9")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    # Dell / iDRAC9 / iDRAC10 all reuse 674; first-loaded wins the slot.
    assert ENTERPRISE_IDS.get(674) in ("idrac10", "idrac9", "dell")
    assert len(OEM_CMD_NAMES) > 0


def test_lookup_helper():
    """idrac9.lookup(netfn, cmd[, subcmd]) returns the full-doc command(s)."""
    import zipmi
    zipmi.load_vendor("idrac9")
    from zipmi.scapy_ipmi.oem.idrac9 import lookup

    # Bodied entry: DellCmdBladeVirtualMAC/SetVirtualMAC — 0x30 cmd 0xc9 sub 0x00.
    hits = lookup(0x30, 0xc9, 0x00)
    mac = next(c for c in hits if "SetVirtualMAC" in c.name)
    assert mac.netfn == 0x30 and mac.cmd == 0xc9 and mac.subcmd == 0x00
    assert "Admin" in mac.priv
    assert mac.lib == "liboemcmds"
    assert mac.request != "undetermined"  # this one has a real body

    # Undetermined leaf: POSTMASER AttachPartition — 0x30 cmd 0xa1 sub 0x02.
    hits = lookup(0x30, 0xa1, 0x02)
    att = next(c for c in hits if "AttachPartition" in c.name)
    assert att.subcmd == 0x02
    assert att.request == "undetermined"
    assert "unverified" in att.confidence.lower()

    # subcmd-less lookup returns every command at that (NetFn, cmd).
    all_a1 = lookup(0x30, 0xa1)
    assert len(all_a1) >= 2


def test_dispatch_still_loads():
    """The pre-existing dispatch-tuple registration is untouched."""
    from zipmi.scapy_ipmi.oem.idrac9 import IDRAC9_DISPATCH, IDRAC9_CMD_NAMES
    assert len(IDRAC9_DISPATCH) >= 200
    assert len(IDRAC9_CMD_NAMES) >= 40
