"""
test_idrac9_dispatch.py — verify the iDRAC9 dispatch-table codegen.

WHAT     Loads idrac9_dispatch_generated.py + idrac9.py consumer and
         asserts a few known-good (NetFn, cmd) entries with their
         resolved handler names + privilege.
WHY      Parser walks a markdown table produced by static .so dispatch
         extraction (293 raw rows → 271 unique keys after dedup).
         A regression that drops 100 entries should fail loudly.
"""
from __future__ import annotations


def test_dispatch_module_imports():
    from zipmi.scapy_ipmi.oem.idrac9_dispatch_generated import (
        IDRAC9_DISPATCH, IDrac9DispatchEntry,
    )
    assert isinstance(IDRAC9_DISPATCH, dict)
    assert len(IDRAC9_DISPATCH) >= 250   # 271 expected


def test_known_oem_entries():
    """A few cmds with confirmed handler symbols round-trip cleanly."""
    from zipmi.scapy_ipmi.oem.idrac9_dispatch_generated import IDRAC9_DISPATCH
    e = IDRAC9_DISPATCH[(0x06, 0x52)]
    assert e.handler_symbol == "CmdI2CWriteRead_OEM"
    e = IDRAC9_DISPATCH[(0x04, 0x12)]
    assert e.handler_symbol == "DellOEMCmdSetPEF"
    assert e.priv == 4   # Admin


def test_load_vendor_idrac9_registers():
    """load_vendor('idrac9') populates the OEM registry."""
    import zipmi
    zipmi.load_vendor("idrac9")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    assert ENTERPRISE_IDS.get(674) in ("idrac9", "dell")  # both reuse 674
    assert (0x06, 0x52) in OEM_CMD_NAMES
    assert "I2C" in OEM_CMD_NAMES[(0x06, 0x52)]


def test_handler_humanization():
    """Cross-ref with handler catalog yields readable names."""
    import zipmi
    zipmi.load_vendor("idrac9")
    from zipmi.scapy_ipmi.oem.idrac9 import IDRAC9_CMD_NAMES
    name = IDRAC9_CMD_NAMES[(0x06, 0x05)]
    assert "Manufacturing Test" in name
    assert name.startswith("iDRAC9 ")


def test_priv_levels_recovered():
    """Every dispatch entry has a privilege level from 0..5."""
    from zipmi.scapy_ipmi.oem.idrac9 import IDRAC9_PRIV
    assert all(0 <= p <= 5 for p in IDRAC9_PRIV.values())
    assert len(IDRAC9_PRIV) >= 250
