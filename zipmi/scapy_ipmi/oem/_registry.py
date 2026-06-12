"""
zipmi.scapy_ipmi.oem._registry — OEM command name + payload registry.

WHAT     A small set of dictionaries that vendor modules populate when
         imported (via `zipmi.load_vendor("dell")` or
         `zipmi.load_vendor("supermicro")`).

WHY      OEM commands are vendor-specific. Mixing Dell and Supermicro
         decoders into the base namespace would mean a Dell capture
         could be mis-decoded as a Supermicro packet (and vice versa).
         Keeping them out of the global CMD_PAYLOADS until explicitly
         loaded preserves clean semantics.

USAGE    Used by the fuzz / scan output formatters and by future Session
         convenience wrappers (e.g. `session.dell_prochot_throttle()`).

RELATED  zipmi/__init__.py:load_vendor, zipmi/scapy_ipmi/oem/dell.py
"""

from __future__ import annotations

from scapy.packet import Packet

# (netfn_request, cmd) → human-readable name.
OEM_CMD_NAMES: dict[tuple[int, int], str] = {}

# (netfn_request, cmd) → (RequestPacket | None, ResponsePacket | None).
OEM_PAYLOADS: dict[tuple[int, int], tuple[type[Packet] | None, type[Packet] | None]] = {}

# IANA Enterprise Number → human-readable vendor key registered.
ENTERPRISE_IDS: dict[int, str] = {}


def register(
    vendor: str,
    iana: int | None,
    cmds: dict[tuple[int, int], str],
    payloads: dict[tuple[int, int], tuple[type[Packet] | None, type[Packet] | None]] | None = None,
) -> None:
    """Add a vendor's commands to the registry. Idempotent on re-import.

    For IANA collisions (Dell + iDRAC9 both reuse 674), first-loaded wins
    on the ENTERPRISE_IDS lookup so existing consumer code continues to
    see a stable vendor key.

    `iana` may be None for vendors that ride raw vendor NetFns (0x30..0x3E)
    and never put an enterprise number on the wire — several OpenBMC OEM
    layers do this (Facebook, Foxconn, Wistron). In that case the vendor
    is still registered in OEM_CMD_NAMES but does not claim an integer
    enterprise-id slot, so a Get Device ID manufacturer-id lookup of 0
    ("Unknown") can never be mis-resolved to such a vendor.
    """
    if iana is not None and iana not in ENTERPRISE_IDS:
        ENTERPRISE_IDS[iana] = vendor
    OEM_CMD_NAMES.update(cmds)
    if payloads:
        OEM_PAYLOADS.update(payloads)
