"""
zipmi.scapy_ipmi.groups._registry — NetFn 0x2C group-extension registry.

WHAT     Per-group-code dispatch tables. Mirrors oem/_registry.py but
         keys are (group_code, cmd) instead of (netfn, cmd) — every
         group cmd lives under NetFn 0x2C, so the cmd byte alone is
         not enough to identify it; the group code (first data byte
         of every request) is the disambiguator.

WHY      Keeps groups (DCMI/PICMG/HPM/VITA) cleanly separated from
         vendor-IANA OEM cmds. Wire trace and CLI lookups can ask
         "what is (group=0xDC, cmd=0x01)?" without colliding with the
         OEM_CMD_NAMES namespace.

USAGE    Body modules call `register("dcmi", 0xDC, names, payloads)`
         at import time. Consumers read `GROUP_CMD_NAMES[(0xDC, 0x01)]`.
"""

from __future__ import annotations

from scapy.packet import Packet


# (group_code, cmd) → human-readable name.
GROUP_CMD_NAMES: dict[tuple[int, int], str] = {}

# (group_code, cmd) → (RequestPacket | None, ResponsePacket | None).
GROUP_PAYLOADS: dict[tuple[int, int], tuple[type[Packet] | None, type[Packet] | None]] = {}

# Group-key (e.g. "dcmi") → group_code (e.g. 0xDC). Set on register().
GROUP_BODIES: dict[str, int] = {}

# group_code → group-key (reverse map for wire-trace lookup).
GROUP_CODE_TO_NAME: dict[int, str] = {}


def register(
    group_key: str,
    group_code: int,
    cmds: dict[tuple[int, int], str],
    payloads: dict[tuple[int, int], tuple[type[Packet] | None, type[Packet] | None]] | None = None,
) -> None:
    """Register a group body's cmd names + optional decoded payloads.

    `cmds` keys are (group_code, cmd) for symmetry with oem/_registry;
    callers pass the full tuple even though `group_code` is also the
    second arg, so a registration error is detectable here.
    """
    GROUP_BODIES[group_key] = group_code
    GROUP_CODE_TO_NAME[group_code] = group_key
    for (gc, cmd), name in cmds.items():
        if gc != group_code:
            raise ValueError(
                f"group {group_key!r}: cmd 0x{cmd:02x} registered under "
                f"group_code 0x{gc:02x} but body is 0x{group_code:02x}")
    GROUP_CMD_NAMES.update(cmds)
    if payloads:
        GROUP_PAYLOADS.update(payloads)


__all__ = [
    "GROUP_CMD_NAMES",
    "GROUP_PAYLOADS",
    "GROUP_BODIES",
    "GROUP_CODE_TO_NAME",
    "register",
]
