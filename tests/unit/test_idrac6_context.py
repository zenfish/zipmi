"""
test_idrac6_context.py — per-entry validation of the iDRAC6 known-context map.

WHAT     One parametrized case per entry of KNOWN_CONTEXT (211 (NetFn,cmd) ->
         context rows recovered from iDRAC6 RE). Asserts each key is a valid
         (NetFn,cmd) byte pair and each value honours the map's real contract:
         either a documented command (summary + source, usually a name) or a
         pure reservation-pointer stub (reservation_from).
WHY      KNOWN_CONTEXT had no dedicated test; a blanked field or a malformed
         key would go unnoticed. Runs once per command so one bad row fails
         with its own id. Mirror of test_idrac10_commands.py.
"""
from __future__ import annotations

import pytest

from zipmi.scapy_ipmi.oem.idrac6_known_context import KNOWN_CONTEXT

_ITEMS = sorted(KNOWN_CONTEXT.items())
_PLACEHOLDERS = {"", "unknown", "tbd", "n/a"}


@pytest.mark.parametrize("item", _ITEMS, ids=lambda it: ".".join(f"{b:#x}" for b in it[0]))
def test_context_entry_wellformed(item):
    """Key is a (NetFn,cmd[,+subcmd bytes]) tuple; value is a documented cmd or a reservation pointer.

    Keys are variable-length: most are (NetFn,cmd), but 18 carry extra
    sub-command/data bytes that disambiguate a shared (NetFn,cmd) slot.
    """
    key, val = item
    assert isinstance(key, tuple) and len(key) >= 2, f"bad key {key!r}"
    assert all(isinstance(b, int) and 0 <= b <= 0xFF for b in key), f"non-byte in key {key!r}"

    documented = "summary" in val
    pointer = "reservation_from" in val
    assert documented or pointer, f"{key}: neither a summary nor a reservation pointer"

    if documented:
        # a real command row: summary + source are the contract, name is optional
        assert val["summary"].strip(), f"empty summary for {key}"
        assert val.get("source", "").strip(), f"empty source for {key}"
    if "name" in val:
        assert val["name"].strip().lower() not in _PLACEHOLDERS, f"placeholder name for {key}"


def test_context_keys_unique():
    """Dict keys are inherently unique — guard against accidental value-merge shape drift."""
    assert len(KNOWN_CONTEXT) == len(set(KNOWN_CONTEXT)) == 211


def test_known_rows_pinned():
    """Pin real (NetFn,cmd)->name rows so a content swap / scrambled mapping fails.

    Values below were read straight from idrac6_known_context.KNOWN_CONTEXT.
    """
    assert KNOWN_CONTEXT[(0x00, 0x02)]["name"] == "ChassisControl"
    assert "Chassis Control" in KNOWN_CONTEXT[(0x00, 0x02)]["summary"]
    assert KNOWN_CONTEXT[(0x00, 0x08)]["name"] == "SetSystemBootOptions"
