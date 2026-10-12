# z-artifact: 566851c8-9fbe-4086-aec5-fde0aa5ba046
"""Firmware-bound OEM IPMI catalog for HPE Cray XD670 BMC v1.27."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from ._registry import register


FIRMWARE_SHA256 = "4e85590c2d5f18caf670b916522555347173ac277b098713c889303a7630cb76"
ROOTFS_SHA256 = "dd1d664f34ec5a2883fdcb1a10616154b266982a0997e59b3ce385f5f511afe5"
REGISTRATION_SHA256 = "c2ed76b6595617ef64370de3295ba055b88d280fa9e8ac416b40f65f10c737cc"
_SOURCE = Path(__file__).parents[2] / "data/sources/hpe-xd670-oem-registrations.csv"
_CONTRACT_SOURCE = Path(__file__).parents[2] / "data/sources/hpe-xd670-reviewed-contracts.json"

if hashlib.sha256(_SOURCE.read_bytes()).hexdigest() != REGISTRATION_SHA256:
    raise RuntimeError("HPE XD670 registration catalog does not match the reviewed image")

with _SOURCE.open(newline="") as _stream:
    HPE_XD670_REGISTRATIONS = tuple(csv.DictReader(_stream))
_reviewed = json.loads(_CONTRACT_SOURCE.read_text())
if (_reviewed["firmware_sha256"], _reviewed["rootfs_sha256"],
        _reviewed["registration_csv_sha256"]) != (
        FIRMWARE_SHA256, ROOTFS_SHA256, REGISTRATION_SHA256):
    raise RuntimeError("HPE XD670 reviewed contracts do not match the pinned catalog")


def _number(value: str) -> int:
    return int(value, 0)


_contracts = {
    (_number(row["netfn"]), _number(row["command"])): row
    for row in _reviewed["operations"]
}
_address_owners = {
    (_number(row["wire_netfn"]), _number(row["command"])): row
    for row in HPE_XD670_REGISTRATIONS
    if not row["duplicate_status"].startswith("loser")
}
_effective = {
    key: row for key, row in _address_owners.items()
    if not row["active_if_enabled"].startswith("no")
}
_duplicates = [row for row in HPE_XD670_REGISTRATIONS
               if (_number(row["wire_netfn"]), _number(row["command"])) == (0x32, 0x2C)]
if (len(HPE_XD670_REGISTRATIONS), len(_address_owners), len(_effective)) != (143, 142, 141):
    raise RuntimeError(
        "expected 143 HPE XD670 registrations / 142 unique addresses / 141 effective commands"
    )
if sum(row["duplicate_status"] == "unique" for row in HPE_XD670_REGISTRATIONS) != 141:
    raise RuntimeError("expected 141 unique HPE XD670 registration rows")
if {(row["handler"], row["duplicate_status"]) for row in _duplicates} != {
    ("AMIYAFUStateless", "winner (core tier precedes extension tier)"),
    ("AMIOemSetRedisDB", "loser to built-in AMIYAFUStateless"),
}:
    raise RuntimeError("HPE XD670 0x32/0x2c precedence is not closed")


def _command(key: tuple[int, int], row: dict[str, str]) -> dict:
    contract = _contracts.get(key)
    request = contract["request"] if contract else None
    prefix = bytes(contract["prefix"]) if contract and contract["prefix"] else None
    return {
        "name": contract["name"] if contract else row["handler"],
        "handler": row["handler"],
        "privilege": row["privilege_decoded"],
        "request_length": (
            request["minimum_bytes"], request["maximum_bytes"]
        ) if request else (None, None),
        "request": request,
        "response": contract["response"] if contract else None,
        "purpose": contract["purpose"] if contract else "Handler semantics not reviewed.",
        "side_effects": contract["side_effects"] if contract else "Unknown.",
        "safety": contract["safety"] if contract else "unknown",
        "confidence": contract["confidence"] if contract else "Dispatch registration only.",
        "live": contract.get("live") if contract else None,
        "prefix": prefix,
        "runnable": contract is not None,
        "blocked_reason": None if contract else "handler semantics were not reviewed",
        "requires_unsafe": contract is None or contract["safety"] != "read-only",
        "registration": row,
    }


HPE_XD670_COMMANDS = {key: _command(key, row) for key, row in _effective.items()}
HPE_XD670_CMD_NAMES = {key: row["name"] for key, row in HPE_XD670_COMMANDS.items()}

register("hpe-xd670", None, HPE_XD670_CMD_NAMES)

__all__ = [
    "FIRMWARE_SHA256", "ROOTFS_SHA256", "REGISTRATION_SHA256",
    "HPE_XD670_REGISTRATIONS", "HPE_XD670_COMMANDS", "HPE_XD670_CMD_NAMES",
]
