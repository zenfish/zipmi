"""
test_idrac9_catalog.py — per-entry validation of the iDRAC9 catalogs.

WHAT     One parametrized case per entry across both iDRAC9 catalogs:
         IDRAC9_DISPATCH (271 recovered (NetFn,cmd) dispatch tuples) and
         IDRAC9_HANDLERS (313 handler-name catalog rows). Asserts each entry
         is well-formed and that identity keys are unique.
WHY      test_idrac9_dispatch.py only spot-checks a handful of entries; a
         regression that drops rows, blanks a field, or mis-parses a NetFn/cmd
         would slip past it. This runs once per command so a single bad entry
         fails loudly with its own id. Mirror of test_idrac10_commands.py.
"""
from __future__ import annotations

import pytest

from zipmi.scapy_ipmi.oem.idrac9_dispatch_generated import IDRAC9_DISPATCH
from zipmi.scapy_ipmi.oem.idrac9_generated import IDRAC9_HANDLERS

_DISPATCH = list(IDRAC9_DISPATCH.values())


@pytest.mark.parametrize(
    "e", _DISPATCH, ids=lambda e: f"{e.handler_symbol}@{e.netfn:#x}.{e.cmd:#x}")
def test_dispatch_entry_wellformed(e):
    """Each recovered dispatch tuple has sane NetFn/cmd, a priv in 0..5, a symbol and a table."""
    assert isinstance(e.netfn, int) and 0 <= e.netfn <= 0xFF
    assert isinstance(e.cmd, int) and 0 <= e.cmd <= 0xFF
    assert isinstance(e.priv, int) and 0 <= e.priv <= 5   # 0 = unresolved gate
    assert e.handler_symbol and e.handler_symbol.strip()
    assert e.table and e.table.strip()
    # When this row is one we pinned, the loop must also see the real content —
    # so a scramble that keeps shape but moves values fails here too.
    pin = _PINNED_DISPATCH.get((e.netfn, e.cmd))
    if pin:
        assert (e.handler_symbol, e.priv, e.table) == pin


def test_dispatch_keys_unique():
    """(handler_symbol, NetFn, cmd) identifies an entry — no dupes survived extraction."""
    keys = [(e.handler_symbol, e.netfn, e.cmd) for e in _DISPATCH]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate dispatch keys: {dupes}"


@pytest.mark.parametrize(
    "h", IDRAC9_HANDLERS, ids=lambda h: f"{h.library or 'oem'}:{h.handler}")
def test_handler_entry_wellformed(h):
    """Each row's identity fields (section, cmd_name, handler) are present.

    `library` is intentionally best-effort: the OEM sections were catalogued
    from RE docs without a .so attribution, so many OEM rows carry library=''.
    Forcing it would fabricate data — cmd_name/handler are the real identity.
    """
    for field in ("section", "cmd_name", "handler"):
        assert getattr(h, field).strip(), f"empty {field}"
    pin = _PINNED_HANDLERS.get(h.handler)
    if pin:
        assert (h.section, h.cmd_name, h.library) == pin


def test_handler_symbols_unique():
    """No duplicate (library, handler) rows in the name catalog."""
    keys = [(h.library, h.handler) for h in IDRAC9_HANDLERS]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate handler rows: {dupes}"


# (NetFn, cmd) -> (handler_symbol, priv, table). Read straight from
# IDRAC9_DISPATCH. Distinct netfns and both named tables so an offset/scramble
# or table swap breaks at least one row.
_PINNED_DISPATCH = {
    (0x00, 0x05): ("CmdOEMSetChassisCapabilities", 4, "G_asOEMIPMIReqeustHandleTable"),
    (0x00, 0x04): ("CmdOEMChassisIdentify", 3, "G_asOEMIPMIReqeustHandleTable"),
    (0x00, 0x08): ("OEMCmdSetSystemBootOptions", 3, "G_asOEMIPMIReqeustHandleTable"),
    (0x06, 0x42): ("CmdGetBMCSA", 4, "G_asOSAOEMHandleTable"),
    (0x06, 0x52): ("CmdI2CWriteRead_OEM", 3, "G_asOEMIPMIReqeustHandleTable"),
    (0x04, 0x12): ("DellOEMCmdSetPEF", 4, "G_asOEMIPMIReqeustHandleTable"),
    (0x04, 0x13): ("DellOEMCmdGetPEF", 2, "G_asOEMIPMIReqeustHandleTable"),
}

# handler -> (section, cmd_name, library). One per distinct .so so a wholesale
# content swap in the handler catalog fails.
_PINNED_HANDLERS = {
    "CmdChassisControl": ("Chassis", "Chassis Control", "libchassiscmds.so"),
    "CmdColdReset": ("App / Global", "Cold Reset", "libglobalcmds.so"),
    "CmdClearMsgFlags": ("Messaging", "Clear Msg Flags", "libmessage.so"),
    "CmdActivatePayload": ("Session / Payload", "Activate Payload", "libpayloadcmds.so"),
    "CmdClrSDR": ("SDR Repository", "Clear SDR", "libsdr.so"),
    "CmdAddSELEntry": ("SEL", "Add SEL Entry", "libselcmds.so"),
    "CmdGetFWID": ("Firmware Update", "Get FW ID", "libosa.so"),
    "CmdSetPowerRestorePolicy": ("OEM Extended Configure",
                                 "Set Power Restore Policy", "liboemcmds.so"),
}


def test_known_rows_pinned():
    """Pin real (NetFn,cmd)->symbol/priv/table so a scrambled catalog fails.

    Values read straight from IDRAC9_DISPATCH.
    """
    for (netfn, cmd), (sym, priv, table) in _PINNED_DISPATCH.items():
        e = IDRAC9_DISPATCH[(netfn, cmd)]
        # key must actually index the row it claims to
        assert e.netfn == netfn and e.cmd == cmd, f"{(netfn, cmd)} mis-keyed"
        assert e.handler_symbol == sym, f"{(netfn, cmd)} symbol"
        assert e.priv == priv, f"{(netfn, cmd)} priv"
        assert e.table == table, f"{(netfn, cmd)} table"


def test_known_handler_rows_pinned():
    """Pin handler -> (section, cmd_name, library) across every distinct .so.

    Values read straight from IDRAC9_HANDLERS. A per-row content swap fails.
    """
    for handler, (section, cmd_name, library) in _PINNED_HANDLERS.items():
        row = next(h for h in IDRAC9_HANDLERS if h.handler == handler)
        assert row.section == section, f"{handler} section"
        assert row.cmd_name == cmd_name, f"{handler} cmd_name"
        assert row.library == library, f"{handler} library"
