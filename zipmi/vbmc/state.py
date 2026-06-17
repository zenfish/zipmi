"""
zipmi.vbmc.state — virtual BMC session state and canned data.

WHAT     Per-source-address session table for the vbmc and the
         persona-supplied response data (manufacturer / GUID / sensors /
         SEL / etc).

WHY      Keeps the asyncio listener (server.py) free of business logic.
         New personas just provide a `Persona` instance; the dispatcher
         in handlers.py reads canned values out of it.

RELATED  zipmi/vbmc/server.py, zipmi/vbmc/handlers.py, personas/
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field


@dataclass
class Persona:
    """The static portion of a virtual BMC's identity."""

    name: str = "generic"

    # Get Device ID response fields
    device_id: int = 0x20
    device_revision: int = 0x80          # bit 7 = SDR support
    fw_revision_1: int = 0x01            # major in low 7 bits
    fw_revision_2: int = 0x10            # minor BCD
    ipmi_version: int = 0x02             # 0x02 = 2.0
    additional_dev_support: int = 0xDF   # sensor + SDR + SEL + FRU + bridge
    manufacturer_id: int = 0              # IANA (LE in wire)
    product_id: int = 0
    aux_fw_rev: bytes = b"\x00\x00\x00\x00"

    # Get Self Test Results
    self_test_result: int = 0x55         # Passed
    self_test_info: int = 0x00

    # GUIDs (16 bytes each)
    device_guid: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    system_guid: bytes = field(default_factory=lambda: secrets.token_bytes(16))

    # Chassis status
    chassis_power: int = 0x21            # power on, restore policy = always-off
    last_power_event: int = 0x00
    misc_chassis_state: int = 0x40       # chassis intrusion sensor present

    # SEL (canned)
    sel_version: int = 0x51
    sel_entries: list[bytes] = field(default_factory=list)
    sel_op_support: int = 0x02

    # Get Channel Auth Caps response (channel 1)
    auth_type_support: int = 0x86        # MD2 + MD5 + IPMI 2.0
    cipher_support: list[int] = field(default_factory=lambda: [0, 1, 2, 3])

    # Auth credentials. user_name = bytes (16 padded). password = bytes.
    user_name: bytes = b"root\x00" * 1 + b"\x00" * 11    # auto-padded below
    password: bytes = b"calvin"

    # Synthetic OEM responses: (netfn, cmd) -> (completion_code, response_data).
    # Consulted by server._dispatch when no built-in handler matches, so a
    # JSON fixture (e.g. captured by scripts/oem_sweep.py) can make the vbmc
    # replay faux-real vendor OEM answers with no live BMC. See vbmc/fixtures.py.
    oem_responses: dict[tuple[int, int], tuple[int, bytes]] = field(
        default_factory=dict)


@dataclass
class Session1_5:
    """In-flight or active IPMI 1.5 LAN session."""
    session_id: int = 0
    auth_type: int = 0
    challenge: bytes = b""
    inbound_seq: int = 0
    granted_priv: int = 0


@dataclass
class Session2_0:
    """In-flight or active IPMI 2.0 RMCP+ session."""
    remote_session_id: int = 0
    managed_session_id: int = 0
    cipher_id: int = 0
    rc: bytes = b""
    rm: bytes = b""
    role: int = 0
    user_name: bytes = b""
    sik: bytes = b""
    k1: bytes = b""
    k2: bytes = b""
    inbound_seq: int = 0


@dataclass
class State:
    """Top-level state for a vbmc instance: persona + session table."""
    persona: Persona
    sessions_15: dict[tuple[str, int], Session1_5] = field(default_factory=dict)
    sessions_20: dict[int, Session2_0]            = field(default_factory=dict)

    def next_session_id(self) -> int:
        sid = secrets.randbits(32) | 1
        # Avoid collisions; tiny chance.
        while sid in self.sessions_20:
            sid = secrets.randbits(32) | 1
        return sid


def default_sel_entries() -> list[bytes]:
    """A small set of plausible SEL records for read-side smoke testing."""
    out = []
    for i, (sensor, ev_data) in enumerate([
        (0x10, b"\x02\xff\xff"),        # power supply event
        (0x12, b"\x01\xff\xff"),        # voltage threshold
        (0x16, b"\x00\xff\xff"),        # temperature threshold
    ]):
        rid = (i + 1).to_bytes(2, "little")
        rec_type = b"\x02"               # standard event
        ts = b"\x00\x00\x00\x00"         # epoch
        gen_id = b"\x20\x00"
        evm_rev = b"\x04"
        sensor_type = bytes([sensor])
        sensor_num = bytes([i + 1])
        ev_byte = b"\x6f"                # generic discrete + asserted
        out.append(rid + rec_type + ts + gen_id + evm_rev + sensor_type
                   + sensor_num + ev_byte + ev_data)
    return out
