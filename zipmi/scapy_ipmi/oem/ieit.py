# z-artifact: 51e82f4f-64f9-4c7c-a035-428e9f367948
"""IEIT NF5468M6 BMC 7.26.05 firmware-bound OEM registration catalog.

This target is AMI MegaRAC SP-X plus IEIT platform libraries, not the unrelated
OpenBMC ``inspur-ipmi-oem`` provider.  The packaged dispatch ledger is generated
directly from the pinned firmware's ELF registration tables.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from ._registry import register


IEIT_FIRMWARE_SHA256 = "b7915aa4be2661d47d78cca6265dc11d8d06c23cc199e0ff80a2adc3ccd7c7d1"
IEIT_PDK_SHA256 = "250ccbd0943a4a5d07f679c99254fb7677b91efb526530df609aab995a27c2ab"
_SOURCE = Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-dispatch.json"
_PLATFORM_SOURCE = (
    Path(__file__).parents[2] / "data/sources/ieit-nf5468m6-netfn30-34-38.json"
)
_CATALOG = json.loads(_SOURCE.read_text())
_PLATFORM_CATALOG = json.loads(_PLATFORM_SOURCE.read_text())

if _CATALOG["firmware_sha256"] != IEIT_FIRMWARE_SHA256:
    raise RuntimeError("IEIT dispatch source does not match the pinned firmware")

IEIT_REGISTRATIONS: tuple[dict, ...] = tuple(_CATALOG["rows"])
_BY_ADDRESS: dict[tuple[int, int], list[dict]] = defaultdict(list)
for _registration in IEIT_REGISTRATIONS:
    _BY_ADDRESS[(_registration["netfn"], _registration["cmd"])].append(_registration)


def _contract(registrations: list[dict]) -> dict:
    handlers = [registration["handler"] for registration in registrations]
    lengths = {registration["declared_request_length"] for registration in registrations}
    exact = lengths.pop() if len(lengths) == 1 else None
    privilege = " / ".join(dict.fromkeys(
        registration["privilege"] for registration in registrations
    ))
    return {
        "name": " / ".join(handlers),
        "privilege": privilege,
        "purpose": "Firmware registration for " + " / ".join(handlers) + ".",
        "request": (
            f"Exactly {exact} payload bytes per dispatcher registration."
            if exact is not None else "Variable-length payload; handler contract required."
        ),
        "response": "Handler-specific response.",
        "request_length": (exact, exact) if exact is not None else (None, None),
        "request_fields": [],
        "response_fields": [],
        "completion_codes": [],
        "activation": "Statically registered in the pinned firmware.",
        "side_effects": "Not inferred from the handler name.",
        "safety": "unknown",
        "confidence": "Registration high; payload semantics not supplied by the dispatch table.",
        "registrations": registrations,
    }


IEIT_COMMANDS: dict[tuple[int, ...], dict] = {
    address: _contract(registrations)
    for address, registrations in sorted(_BY_ADDRESS.items())
}


def _update(address: tuple[int, int], **contract) -> None:
    IEIT_COMMANDS[address].update(contract)


def _leaf(address: tuple[int, int], prefix: bytes, **contract) -> None:
    base = IEIT_COMMANDS[address]
    IEIT_COMMANDS[(*address, *prefix)] = {**base, **contract}


_update(
    (0x30, 0x01),
    purpose="Return the rollback-flash status byte (this build always returns zero).",
    request="No request data.", response="One status byte, fixed to 0x00 in this build.",
    request_length=(0, 0), safety="read-only", side_effects="None.", confidence="high",
)
_update(
    (0x30, 0xA2),
    purpose="Enable, disable, or query protocol 0x1e using an ASCII control token.",
    request="Exactly one 10-byte ASCII token: 00SECURITY, 11SECURITY, or ??SECURITY.",
    response="Set: no data. Query: two duplicate ASCII state bytes (00 or 11).",
    request_length=(10, 10), safety="security-sensitive",
    side_effects="Enable/disable changes the BMC protocol policy.", confidence="high",
)
for _token, _operation, _safety, _effect in (
    (b"00SECURITY", "Disable protocol 0x1e", "state-changing", "Disables protocol 0x1e."),
    (b"11SECURITY", "Enable protocol 0x1e", "state-changing", "Enables protocol 0x1e."),
    (b"??SECURITY", "Query protocol 0x1e", "read-only", "None."),
):
    _leaf(
        (0x30, 0xA2), _token, name=f"Chip security: {_operation}", purpose=_operation + ".",
        request=f"Fixed ASCII token {_token.decode()} (supplied by the named route).",
        request_length=(10, 10), safety=_safety, side_effects=_effect,
        completion_codes=["0x00 success", "0xc7 invalid length", "0xc9 invalid token"],
        confidence="high",
    )

_update(
    (0x30, 0xE2),
    purpose="Colliding IEIT common-interface and Intel PNM reading providers.",
    request="Provider-dependent sequence of 3-byte reading descriptors.",
    response="Provider-dependent 4-byte reading records; an empty live request produced no reply.",
    request_length=(None, None), safety="disruptive",
    side_effects="Can suppress the reply and leave the emulated IPMI service unhealthy.",
    confidence="high collision; runtime winner unresolved",
)

_update(
    (0x34, 0x1A),
    purpose="Change PCIe/I2C device scanning and route the I2C mux to SmartNIC.",
    request="Exactly one selector byte: 0x09 disables scans; 0x0a enables scans.",
    response="No response data.", request_length=(1, 1), safety="disruptive",
    side_effects="Mutates live device scanning and I2C routing.", confidence="high",
)
for _selector, _operation, _effect in (
    (0x09, "Disable PCIe/I2C scans and switch to SmartNIC", "Hides scanned devices and changes the live I2C mux."),
    (0x0A, "Enable PCIe/I2C scans", "Re-enables scans but does not restore the I2C mux."),
):
    _leaf(
        (0x34, 0x1A), bytes([_selector]), name=_operation, purpose=_operation + ".",
        request=f"Fixed selector 0x{_selector:02x} (supplied by the named route).",
        request_length=(1, 1), safety="disruptive", side_effects=_effect,
        completion_codes=["0x00 success", "0xc7 invalid length", "0xcc invalid selector"],
        confidence="high",
    )

_update(
    (0x38, 0x11),
    purpose="Read current BIOS configuration states through the runtime translation map.",
    request="Exactly group and item bytes; item 0xff returns every present item in the group.",
    response="Reserved 0x00, count, then count state bytes (maximum 33).",
    request_length=(2, 2), safety="read-only", side_effects="None.", confidence="high",
)
_update(
    (0x38, 0x12),
    purpose="Write a pending BIOS state or invoke a mapped live BMC setter.",
    request="At least group, item, and state bytes; trailing bytes are ignored.",
    response="No response data.", request_length=(3, None), safety="state-changing",
    side_effects="Writes pending BIOS settings; selected records change live power, network, or SOL state.",
    confidence="high",
)

_records = _PLATFORM_CATALOG["bios_translation"]["records"]
_attributes: dict[tuple[int, int], str] = {}
for _record in _records:
    _attributes[(_record["group"], _record["item"])] = _record["attribute"]
    _leaf(
        (0x38, 0x12),
        bytes([_record["group"], _record["item"], _record["state"]]),
        name=f"Set BIOS {_record['attribute']} = {_record['meaning']}",
        purpose=(
            f"Set {_record['attribute']} to {_record['meaning']} using embedded build-default "
            "translation data; the deployed runtime JSON can replace this mapping."
        ),
        request="Fixed group, item, and state tuple supplied by the named route.",
        request_length=(3, 3), safety="state-changing",
        side_effects="Changes a pending BIOS setting or a mapped live BMC setting.",
        completion_codes=[
            "0x00 success", "0xc7 request too short", "0xc9 unknown tuple",
            "0xd3 runtime translation/settings JSON unavailable",
        ],
        confidence="high build-default mapping; runtime data-driven",
    )
for (_group, _item), _attribute in sorted(_attributes.items()):
    _leaf(
        (0x38, 0x11), bytes([_group, _item]), name=f"Read BIOS {_attribute}",
        purpose=(
            f"Read the current state for {_attribute}; the deployed runtime JSON can replace "
            "the embedded build-default mapping."
        ),
        request="Fixed group and item tuple supplied by the named route.",
        request_length=(2, 2), safety="read-only", side_effects="None.",
        completion_codes=[
            "0x00 success", "0xc7 invalid length", "0xc9 unknown tuple",
            "0xd3 runtime settings JSON unavailable",
        ],
        confidence="high build-default mapping; runtime data-driven",
    )
for _group in sorted({_record["group"] for _record in _records}):
    _leaf(
        (0x38, 0x11), bytes([_group, 0xFF]), name=f"Read all BIOS settings in group {_group}",
        purpose=f"Read every present BIOS setting state in group {_group} (maximum 33).",
        request="Fixed group and item 0xff tuple supplied by the named route.",
        request_length=(2, 2), safety="read-only", side_effects="None.", confidence="high",
    )

IEIT_CMD_NAMES: dict[tuple[int, ...], str] = {
    address: f"IEIT {contract['name']}"
    for address, contract in IEIT_COMMANDS.items()
}

register("ieit", None, IEIT_CMD_NAMES)


__all__ = [
    "IEIT_COMMANDS",
    "IEIT_CMD_NAMES",
    "IEIT_FIRMWARE_SHA256",
    "IEIT_PDK_SHA256",
    "IEIT_REGISTRATIONS",
]
