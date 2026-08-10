"""
test_oem.py — OEM dispatch registry & vendor-load mechanics.

WHAT     Verifies that base namespace stays clean, that load_vendor
         populates the OEM tables exactly once per call, and that
         per-vendor command lookups work.
RELATED  zipmi/__init__.py:load_vendor, scapy_ipmi/oem/_registry.py
"""

from __future__ import annotations

import subprocess
import sys

import pytest


def test_base_namespace_no_oem_by_default():
    """Importing zipmi alone must NOT populate the OEM registry.

    Must run in a FRESH interpreter — in-process the registry is polluted by
    other tests that load vendors, which is exactly why the old version gave up
    and asserted nothing meaningful."""
    code = (
        "import zipmi;"
        "from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS;"
        "assert len(OEM_CMD_NAMES) == 0, OEM_CMD_NAMES;"
        "assert len(ENTERPRISE_IDS) == 0, ENTERPRISE_IDS"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, f"bare import populated the OEM registry:\n{r.stderr}"


def test_load_vendor_dell():
    import zipmi
    zipmi.load_vendor("dell")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    # IANA 674 is shared across the Dell family (dell/idrac9/idrac10) and the
    # registry is first-writer-wins, so whichever loaded first owns the label —
    # asserting exactly "dell" is order-dependent (fails when idrac9 loaded
    # first). What load_vendor("dell") guarantees is dell's OWN commands:
    assert ENTERPRISE_IDS.get(674) in ("dell", "idrac9", "idrac10")
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
