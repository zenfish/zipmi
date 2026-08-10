"""
test_idrac10_commands.py — verify the iDRAC10 rich-command catalog codegen.

WHAT     Loads idrac10_commands_generated.py + the idrac10.py consumer and
         asserts the catalog imports, has all 446 entries, that
         load_vendor("idrac10") still registers, and spot-checks specific
         commands round-trip with correct NetFn/cmd/subcmd/priv.
WHY      The catalog is generated from idrac10-commands.json (446 RE'd +
         adversarially verified commands). A regression that drops entries
         or mis-parses hex NetFn/cmd/subcmd should fail loudly. Mirror of
         test_idrac9_dispatch.py.
"""
from __future__ import annotations

import pytest

from zipmi.scapy_ipmi.oem.idrac10_commands_generated import IDRAC10_COMMANDS

_PRIVS = ("Admin", "Operator", "User", "Callback", "OEM", "undetermined")


@pytest.mark.parametrize("c", IDRAC10_COMMANDS, ids=lambda c: c.name)
def test_every_command_wellformed(c):
    """One case per catalog entry — a dropped/fabricated/malformed command fails loudly."""
    assert c.name and c.name.strip(), "empty name"
    # netfn/cmd: int in byte range or None (the single undetermined entry).
    for f in (c.netfn, c.cmd):
        assert f is None or (isinstance(f, int) and 0 <= f <= 0xFF)
    # subcmd: int (multi-byte folded, may exceed 0xff) or None.
    assert c.subcmd is None or isinstance(c.subcmd, int)
    assert isinstance(c.in_band_only, bool)
    assert any(p.lower() in c.priv.lower() for p in _PRIVS), f"unknown priv {c.priv!r}"
    # These fields were RE'd per command — blank means a doc hole, not valid data.
    for field in ("purpose", "request", "response", "confidence", "lib"):
        assert getattr(c, field).strip(), f"empty {field}"


def test_catalog_keys_unique():
    """(name, netfn, cmd, subcmd) is the identity — no dupes survived the merge/dedup."""
    keys = [(c.name, c.netfn, c.cmd, c.subcmd) for c in IDRAC10_COMMANDS]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate command keys: {dupes}"


def test_catalog_imports_all():
    from zipmi.scapy_ipmi.oem.idrac10_commands_generated import (
        IDRAC10_COMMANDS, IDrac10Command,
    )
    assert isinstance(IDRAC10_COMMANDS, list)
    assert len(IDRAC10_COMMANDS) == 446
    assert all(isinstance(c, IDrac10Command) for c in IDRAC10_COMMANDS)


def test_hex_fields_parsed_to_int():
    """NetFn/cmd/subcmd land as ints (or None), not the raw '0x..' strings."""
    from zipmi.scapy_ipmi.oem.idrac10_commands_generated import IDRAC10_COMMANDS
    for c in IDRAC10_COMMANDS:
        assert c.netfn is None or isinstance(c.netfn, int)
        assert c.cmd is None or isinstance(c.cmd, int)
        assert c.subcmd is None or isinstance(c.subcmd, int)
        assert isinstance(c.in_band_only, bool)
    # Exactly one entry had an undetermined NetFn/cmd in the source doc.
    assert sum(1 for c in IDRAC10_COMMANDS if c.netfn is None) == 1


def test_load_vendor_idrac10_registers():
    """load_vendor('idrac10') populates the OEM registry with catalog names."""
    import zipmi
    zipmi.load_vendor("idrac10")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    # Dell / iDRAC9 / iDRAC10 all reuse 674; first-loaded wins the slot.
    assert ENTERPRISE_IDS.get(674) in ("idrac10", "idrac9", "dell")
    assert (0x2c, 0x02) in OEM_CMD_NAMES


def test_lookup_helper():
    """idrac10.lookup(netfn, cmd[, subcmd]) returns the full-doc command(s)."""
    import zipmi
    zipmi.load_vendor("idrac10")
    from zipmi.scapy_ipmi.oem.idrac10 import lookup

    # Bootstrap credentials — netfn 0x2c cmd 0x02, no sub-command byte.
    hits = lookup(0x2c, 0x02)
    names = {c.name for c in hits}
    assert "DellCmdGetBootstrapCredentials" in names
    boot = next(c for c in hits if c.name == "DellCmdGetBootstrapCredentials")
    assert boot.subcmd is None
    assert "Admin" in boot.priv
    assert boot.lib == "libmisccmd"

    # SecureDefaultPassword — netfn 0x30 cmd 0xa5 sub-command 0x04.
    hits = lookup(0x30, 0xa5, 0x04)
    sec = next(c for c in hits
               if "SecureDefaultPassword" in c.name)
    assert sec.netfn == 0x30 and sec.cmd == 0xa5 and sec.subcmd == 0x04

    # AttachPartitions — netfn 0x30 cmd 0xa2 sub-command 0x05.
    hits = lookup(0x30, 0xa2, 0x05)
    att = next(c for c in hits if "AttachPartitions" in c.name)
    assert att.subcmd == 0x05


def test_dispatch_still_loads():
    """The pre-existing dispatch-tuple registration is untouched."""
    from zipmi.scapy_ipmi.oem.idrac10 import IDRAC10_DISPATCH, IDRAC10_CMD_NAMES
    assert len(IDRAC10_DISPATCH) >= 300
    assert len(IDRAC10_CMD_NAMES) >= 100
