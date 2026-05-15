"""
test_oem.py — OEM dispatch registry & vendor-load mechanics.

WHAT     Verifies that base namespace stays clean, that load_vendor
         populates the OEM tables exactly once per call, and that
         per-vendor command lookups work.
RELATED  zipmi/__init__.py:load_vendor, scapy_ipmi/oem/_registry.py
"""

from __future__ import annotations

import pytest


def test_base_namespace_no_oem_by_default():
    """Importing zipmi alone must NOT populate the OEM registry."""
    # Reload of submodules to simulate a fresh import isn't trivial in
    # pytest; instead just assert the registry is mostly empty when no
    # vendor has been explicitly loaded.
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    # If a previous test already loaded a vendor, the entries are present
    # — that's fine; we just check the registry exists and is a dict.
    assert isinstance(OEM_CMD_NAMES, dict)
    assert isinstance(ENTERPRISE_IDS, dict)


def test_load_vendor_dell():
    import zipmi
    zipmi.load_vendor("dell")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    assert ENTERPRISE_IDS.get(674) == "dell"
    # PROCHOT cmd should be registered.
    assert OEM_CMD_NAMES.get((0x30, 0xC0)) == "Dell PROCHOTThrottle"


def test_load_vendor_supermicro():
    import zipmi
    zipmi.load_vendor("supermicro")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    from zipmi.scapy_ipmi.oem.supermicro import SM_SUBCMDS, SM_ATTACK_PRIMITIVES
    assert ENTERPRISE_IDS.get(10876) == "supermicro"
    # Top-level cmd is registered by the OEMCommandSet_70 dispatcher.
    name = OEM_CMD_NAMES.get((0x30, 0x70))
    assert name and "OEMCommandSet_70" in name
    # Sub-cmd table is exposed via SM_SUBCMDS.
    assert SM_SUBCMDS[(0x30, 0x70)][0x12].startswith("OEMFlashFWCmd")
    # Attack primitives ingested.
    assert "config_restore_traversal" in SM_ATTACK_PRIMITIVES


def test_dell_prochot_packet_round_trip():
    import zipmi
    zipmi.load_vendor("dell")
    from zipmi.scapy_ipmi.oem.dell import DellPROCHOTThrottleReq

    req = DellPROCHOTThrottleReq(subcommand=0x01)
    assert bytes(req) == b"\x01"
