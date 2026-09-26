"""Advantech ASMB-787 OEM command catalog recovered from its firmware."""

from __future__ import annotations

from ._registry import register
from .advantech_asmb787_generated import ASMB787_COMMANDS, ASMB787_CMD_NAMES


ASMB787_IANA = 10297

register("advantech-asmb787", ASMB787_IANA, ASMB787_CMD_NAMES)

__all__ = ["ASMB787_IANA", "ASMB787_COMMANDS", "ASMB787_CMD_NAMES"]
