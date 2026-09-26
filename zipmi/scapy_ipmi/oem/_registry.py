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

import re

from scapy.fields import ByteField, LEIntField, LEShortField, ShortField, StrFixedLenField
from scapy.packet import Packet

# (netfn_request, cmd) → human-readable name.
OEM_CMD_NAMES: dict[tuple[int, int], str] = {}

# (netfn_request, cmd) → (RequestPacket | None, ResponsePacket | None).
PayloadPair = tuple[type[Packet] | None, type[Packet] | None]
OEM_PAYLOADS: dict[tuple[int, ...], PayloadPair] = {}

# Vendor-scoped payloads are authoritative.  OEM_PAYLOADS remains as a
# compatibility view for callers that loaded exactly one vendor.
OEM_PAYLOADS_BY_VENDOR: dict[str, dict[tuple[int, ...], PayloadPair]] = {}
OEM_PAYLOAD_SELECTORS_BY_VENDOR: dict[
    str, list[tuple[int, int, int, bytes, PayloadPair]]
] = {}

# IANA Enterprise Number → human-readable vendor key registered.
ENTERPRISE_IDS: dict[int, str] = {}


def build_fixed_packet_class(
    name: str,
    fields: list[dict],
    *,
    require_fields: bool = False,
) -> type[Packet]:
    """Build a fixed-width OEM packet class from contract field descriptors."""
    field_types = {
        "u8": lambda field: ByteField(field["name"], field.get("constant")),
        "u16le": lambda field: LEShortField(field["name"], field.get("constant")),
        "u16be": lambda field: ShortField(field["name"], field.get("constant")),
        "u32le": lambda field: LEIntField(field["name"], field.get("constant")),
        "bytes": lambda field: StrFixedLenField(
            field["name"], b"\x00" * field["length"], field["length"]),
    }
    class_name = re.sub(r"\W+", "_", name).strip("_")
    required = tuple(field["name"] for field in fields if "constant" not in field)
    constants = {field["name"]: field["constant"] for field in fields if "constant" in field}

    def post_build(self, packet, payload):
        missing = [field for field in required if field not in self.fields]
        if require_fields and missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        changed = [field for field, value in constants.items() if getattr(self, field) != value]
        if changed:
            raise ValueError(f"constant fields changed: {', '.join(changed)}")
        return packet + payload

    return type(class_name, (Packet,), {
        "name": name,
        "fields_desc": [field_types[field["kind"]](field) for field in fields],
        "post_build": post_build,
        "extract_padding": lambda self, data: (b"", data),
    })


def register(
    vendor: str,
    iana: int | None,
    cmds: dict[tuple[int, int], str],
    payloads: dict[tuple[int, ...], PayloadPair] | None = None,
    selector_payloads: list[tuple[int, int, int, bytes, PayloadPair]] | None = None,
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
    # Some vendor tables key by (netfn, cmd, <selector bytes…>) for precise
    # sub-command naming (e.g. nvidia (0x3C,0x36,0x01) Set BIOS Password,
    # facebook (0x38,0x01,0x15,0xA0,0x00) BIC Info). lookup_cmd_name() only
    # knows (netfn, cmd), so also register a 2-tuple fallback → the same name,
    # else those commands are unreachable by NetFn+Cmd. First selector wins the
    # 2-tuple slot on any (netfn,cmd) shared by several.
    for key, name in cmds.items():
        if len(key) > 2:
            OEM_CMD_NAMES.setdefault((key[0], key[1]), name)
    if payloads:
        OEM_PAYLOADS.update(payloads)
        OEM_PAYLOADS_BY_VENDOR.setdefault(vendor, {}).update(payloads)
    if selector_payloads:
        OEM_PAYLOAD_SELECTORS_BY_VENDOR[vendor] = list(selector_payloads)


def lookup_payload(
    vendor: str, netfn: int, cmd: int, data: bytes = b"",
) -> PayloadPair | None:
    """Return the most-specific vendor payload codec for a wire request."""
    selector_matches = (
        (selector, pair)
        for candidate_netfn, candidate_cmd, offset, selector, pair
        in OEM_PAYLOAD_SELECTORS_BY_VENDOR.get(vendor, [])
        if candidate_netfn == (netfn & 0xFE)
        and candidate_cmd == cmd
        and data[offset:offset + len(selector)] == selector
    )
    selected = next((pair for _, pair in sorted(
        selector_matches, key=lambda item: len(item[0]), reverse=True,
    )), None)
    if selected is not None:
        return selected
    payloads = OEM_PAYLOADS_BY_VENDOR.get(vendor, {})
    matches = (
        (key, value) for key, value in payloads.items()
        if key[:2] == (netfn & 0xFE, cmd) and data.startswith(bytes(key[2:]))
    )
    return next((value for _, value in sorted(matches, key=lambda item: len(item[0]), reverse=True)), None)


def decode_payload_response(
    vendor: str, netfn: int, cmd: int, request_data: bytes, cc: int, data: bytes,
) -> Packet | None:
    """Decode an OEM response while tolerating completion-code-only errors."""
    entry = lookup_payload(vendor, netfn, cmd, request_data)
    if entry is None or entry[1] is None:
        return None
    response_type = entry[1]
    raw = bytes([cc]) + data
    try:
        return response_type(raw)
    except Exception:
        response = response_type()
        if hasattr(response, "completion_code"):
            response.completion_code = cc
        return response
