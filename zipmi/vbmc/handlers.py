"""
zipmi.vbmc.handlers — IPMI message dispatch for the virtual BMC.

WHAT     Maps `(NetFn, cmd)` to a function that builds the response IPMB
         payload. Called by server.py once it has parsed and (if RMCP+)
         decrypted an incoming message.

WHY      Keeps the per-command response logic isolated from the wire
         framing. Lets us add new commands by appending one entry to
         the dispatch table.

RELATED  state.py (Persona + Session state), server.py.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable

from .state import Persona, State


# --- response builders ----------------------------------------------------
#
# Each handler receives (state, request_data_bytes) and returns the
# response data bytes (NOT including comp_code; that's prepended by the
# caller). To return an explicit comp_code != 0, raise IPMIErr.

class IPMIErr(Exception):
    def __init__(self, cc: int):
        self.cc = cc


# App / Get Device ID (NetFn 0x06 cmd 0x01)
def get_device_id(state: State, _: bytes) -> bytes:
    p = state.persona
    return bytes([
        p.device_id,
        p.device_revision,
        p.fw_revision_1,
        p.fw_revision_2,
        p.ipmi_version,
        p.additional_dev_support,
    ]) + p.manufacturer_id.to_bytes(3, "little") + \
        p.product_id.to_bytes(2, "little") + p.aux_fw_rev


def get_self_test_results(state: State, _: bytes) -> bytes:
    p = state.persona
    return bytes([p.self_test_result, p.self_test_info])


def get_device_guid(state: State, _: bytes) -> bytes:
    return state.persona.device_guid


def get_system_guid(state: State, _: bytes) -> bytes:
    return state.persona.system_guid


def get_channel_auth_caps(state: State, data: bytes) -> bytes:
    p = state.persona
    if len(data) < 2:
        raise IPMIErr(0xC7)
    return bytes([
        0x01,               # channel returned
        p.auth_type_support,
        0x14,               # status: null-username + per-msg-auth-disabled
        0x03,               # ext caps: 1.5 + 2.0
    ]) + b"\x00\x00\x00\x00"  # OEM IANA + aux


def chassis_status(state: State, _: bytes) -> bytes:
    p = state.persona
    # 4 bytes: current_power_state, last_power_event, misc_chassis_state,
    # front_panel_button_caps. ipmitool / zipmi tolerate the 4th byte being
    # absent, but its inclusion keeps the response decoder Packet happy.
    return bytes([p.chassis_power, p.last_power_event, p.misc_chassis_state, 0x00])


def chassis_control(state: State, data: bytes) -> bytes:
    """Accept chassis control without actually changing power state."""
    if len(data) < 1:
        raise IPMIErr(0xC7)
    # Track action for testability (actual power doesn't change).
    return b""


def get_sel_info(state: State, _: bytes) -> bytes:
    p = state.persona
    n = len(p.sel_entries)
    free = max(0, 8000 - n * 16)
    return bytes([p.sel_version]) + n.to_bytes(2, "little") \
        + free.to_bytes(2, "little") + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" + bytes([p.sel_op_support])


def reserve_sel(state: State, _: bytes) -> bytes:
    return b"\x01\x00"      # reservation id 1


def get_sel_entry(state: State, data: bytes) -> bytes:
    """Return SEL record by record_id (low-effort linear lookup)."""
    if len(data) < 6:
        raise IPMIErr(0xC7)
    rid = int.from_bytes(data[2:4], "little")
    entries = state.persona.sel_entries
    if not entries:
        raise IPMIErr(0xCB)
    # Pick by record id; if rid==0 return first.
    for i, rec in enumerate(entries):
        rec_id = int.from_bytes(rec[0:2], "little")
        if (rid == 0 and i == 0) or rec_id == rid:
            next_id = (int.from_bytes(entries[i + 1][0:2], "little")
                       if i + 1 < len(entries) else 0xFFFF)
            return next_id.to_bytes(2, "little") + rec
    raise IPMIErr(0xCB)


# Reduced lookup table; the server.py extends this for session-mgmt cmds
# which need access to the session table (set/close session, set priv).
DISPATCH: dict[tuple[int, int], Callable[[State, bytes], bytes]] = {
    (0x06, 0x01): get_device_id,
    (0x06, 0x04): get_self_test_results,
    (0x06, 0x08): get_device_guid,
    (0x06, 0x37): get_system_guid,
    (0x06, 0x38): get_channel_auth_caps,
    (0x00, 0x01): chassis_status,
    (0x00, 0x02): chassis_control,
    (0x0A, 0x40): get_sel_info,
    (0x0A, 0x42): reserve_sel,
    (0x0A, 0x43): get_sel_entry,
}
