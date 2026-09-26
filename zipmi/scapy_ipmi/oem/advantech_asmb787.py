"""Advantech ASMB-787 OEM command catalog recovered from its firmware."""

from __future__ import annotations

from ._registry import build_fixed_packet_class, register
from .advantech_asmb787_generated import (
    ASMB787_COMMANDS,
    ASMB787_CMD_NAMES,
    ASMB787_OPERATIONS,
)


ASMB787_IANA = 10297


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
    _req = build_fixed_packet_class(
        f"{_operation['id']} Request", _operation["request"]["fields"], require_fields=True)
    _resp = build_fixed_packet_class(
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
