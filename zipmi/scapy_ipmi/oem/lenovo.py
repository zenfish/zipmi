"""Lenovo IMM/XCC proprietary OEM IPMI command registration."""
from __future__ import annotations

from ._registry import register
from .lenovo_commands_generated import LENOVO_COMMANDS, LenovoCommand

LENOVO_DEVICE_IANA = 2
LENOVO_GROUP_IANA = 0x4A66

LENOVO_COMMANDS_BY_KEY: dict[tuple[int, ...], LenovoCommand] = {
    (c.netfn, c.cmd, *c.prefix): c for c in LENOVO_COMMANDS
}
LENOVO_CMD_NAMES: dict[tuple[int, ...], str] = {
    key: c.name for key, c in LENOVO_COMMANDS_BY_KEY.items() if c.runnable
}

register("lenovo", LENOVO_DEVICE_IANA, LENOVO_CMD_NAMES)


def lookup(netfn: int, cmd: int, prefix: bytes = b"") -> LenovoCommand | None:
    """Return one catalog record by exact request identity."""
    return LENOVO_COMMANDS_BY_KEY.get((netfn, cmd, *prefix))


__all__ = [
    "LENOVO_DEVICE_IANA", "LENOVO_GROUP_IANA", "LENOVO_COMMANDS", "LENOVO_COMMANDS_BY_KEY",
    "LENOVO_CMD_NAMES", "LenovoCommand", "lookup",
]
