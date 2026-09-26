"""Lenovo IMM/XCC proprietary OEM IPMI command registration."""
from __future__ import annotations

from ._registry import build_fixed_packet_class, register
from .lenovo_commands_generated import (
    LENOVO_COMMANDS, LENOVO_CONTRACTS, LenovoCommand, LenovoContract, LenovoOperation,
)

LENOVO_DEVICE_IANA = 2
LENOVO_GROUP_IANA = 0x4A66

LENOVO_COMMANDS_BY_KEY: dict[tuple[int, ...], LenovoCommand] = {
    (c.netfn, c.cmd, *c.prefix): c for c in LENOVO_COMMANDS
}
LENOVO_CMD_NAMES: dict[tuple[int, ...], str] = {
    key: c.name for key, c in LENOVO_COMMANDS_BY_KEY.items() if c.runnable
}

LENOVO_CONTRACTS_BY_NAME = {contract.name: contract for contract in LENOVO_CONTRACTS}
LENOVO_PAYLOADS = {}
LENOVO_SELECTOR_PAYLOADS = []
for _contract in LENOVO_CONTRACTS:
    if not (_contract.request_codec or _contract.response_codec):
        continue
    _request = (build_fixed_packet_class(
        f"{_contract.name} Request", _contract.request_fields, require_fields=True,
    ) if _contract.request_codec else None)
    _response_fields = ([{"name": "completion_code", "kind": "u8"}]
                        + _contract.response_fields)
    _response = (build_fixed_packet_class(
        f"{_contract.name} Response", _response_fields,
    ) if _contract.response_codec else None)
    _pair = (_request, _response)
    if _contract.selector and _contract.selector_offset not in (None, 0):
        LENOVO_SELECTOR_PAYLOADS.append((
            _contract.netfn, _contract.cmd, _contract.selector_offset,
            _contract.selector, _pair,
        ))
    else:
        LENOVO_PAYLOADS[(_contract.netfn, _contract.cmd, *_contract.prefix)] = _pair

register(
    "lenovo", LENOVO_DEVICE_IANA, LENOVO_CMD_NAMES, LENOVO_PAYLOADS,
    LENOVO_SELECTOR_PAYLOADS,
)


def lookup(netfn: int, cmd: int, prefix: bytes = b"") -> LenovoCommand | None:
    """Return one catalog record by exact request identity."""
    return LENOVO_COMMANDS_BY_KEY.get((netfn, cmd, *prefix))


__all__ = [
    "LENOVO_DEVICE_IANA", "LENOVO_GROUP_IANA", "LENOVO_COMMANDS", "LENOVO_COMMANDS_BY_KEY",
    "LENOVO_CMD_NAMES", "LENOVO_CONTRACTS", "LENOVO_CONTRACTS_BY_NAME",
    "LENOVO_PAYLOADS", "LENOVO_SELECTOR_PAYLOADS", "LenovoCommand",
    "LenovoContract", "LenovoOperation", "lookup",
]
