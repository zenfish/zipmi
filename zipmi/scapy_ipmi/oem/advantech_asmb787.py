"""Advantech ASMB-787 OEM command catalog recovered from its firmware."""

from __future__ import annotations

import re

from scapy.fields import ByteField, LEIntField, LEShortField, StrFixedLenField
from scapy.packet import Packet

from ._registry import register
from .advantech_asmb787_generated import (
    ASMB787_COMMANDS,
    ASMB787_CMD_NAMES,
    ASMB787_OPERATIONS,
)


ASMB787_IANA = 10297


def _packet_class(name: str, fields: list[dict], require_fields: bool = False) -> type[Packet]:
    field_types = {
        "u8": lambda field: ByteField(field["name"], field.get("constant")),
        "u16le": lambda field: LEShortField(field["name"], field.get("constant")),
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


ASMB787_PAYLOADS = {}
_unprefixed = {}
for _operation in ASMB787_OPERATIONS:
    if _operation["codec_state"] != "verified":
        continue
    _prefix = _operation.get("prefix")
    _key = tuple(_operation["command"] + (_prefix or []))
    if _prefix is None:
        _pair = tuple(_operation["command"])
        _unprefixed[_pair] = _unprefixed.get(_pair, 0) + 1
    _req = _packet_class(
        f"{_operation['id']} Request", _operation["request"]["fields"], require_fields=True)
    _resp = _packet_class(
        f"{_operation['id']} Response", _operation["response"]["fields"])
    ASMB787_PAYLOADS[_key] = (_req, _resp)
for _pair, _count in _unprefixed.items():
    if _count > 1:
        ASMB787_PAYLOADS.pop(_pair, None)

register("advantech-asmb787", ASMB787_IANA, ASMB787_CMD_NAMES, ASMB787_PAYLOADS)

__all__ = [
    "ASMB787_IANA", "ASMB787_COMMANDS", "ASMB787_CMD_NAMES",
    "ASMB787_OPERATIONS", "ASMB787_PAYLOADS",
]
