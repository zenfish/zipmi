"""Firmware-bound Supermicro X14SBSC-RoT / E601MS OEM IPMI support.

The source catalog closes the five provider ELFs in BMC firmware 01.01.06.07.
This module exposes Supermicro raw, selector, group-extension, and RAS
operations.  The 11 bundled Intel Node Manager commands remain owned by
``intel.py``; standard overrides stay in ``X14_REGISTRATIONS`` for inventory
and documentation rather than being duplicated as OEM commands.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ._registry import build_fixed_packet_class, register


X14_FIRMWARE_SHA256 = "8af1ba767ed0363653537ee6e2fab3fabd66d838e397903cb99e9cd00caaa792"
X14_ROOTFS_SHA256 = "d9767ced6fc5301ae02d1fb918314bc1c182c6de4baac2376b3914a0a1eb8afa"
X14_PRIMARY_PROVIDER_SHA256 = "980527b4d95e8fdf07ae7f4afc0f9680017e9d3ccaeca59c877e0de9c335a1ad"
X14_PRIMARY_PROVIDER_BUILD_ID = "6f0189859aa536e9c2e1684915d57608dee9f150"

_SOURCE = Path(__file__).parents[2] / "data/sources/supermicro-x14-contracts.json"
X14_CATALOG = json.loads(_SOURCE.read_text())
if X14_CATALOG["firmware"]["image_sha256"] != X14_FIRMWARE_SHA256:
    raise RuntimeError("Supermicro X14 catalog does not match the pinned firmware")

_PRIMARY = X14_CATALOG["primary"]
_AUXILIARY = X14_CATALOG["auxiliary"]
_PRIVILEGE = {0: "None", 1: "Callback", 2: "User", 3: "Operator", 4: "Administrator"}
_PARENT_DISPATCHERS = {(0x30, command) for command in (0x51, 0x68, 0x70, 0xA0, 0xAD)}


def _number(value: int | str) -> int:
    return value if isinstance(value, int) else int(value, 0)


def _fields(fields: list[dict] | list[str] | None) -> list[dict] | None:
    if fields is None:
        return None
    normalized = []
    for index, field in enumerate(fields):
        if isinstance(field, str):
            normalized.append({
                "offset": "var" if index else "0", "name": f"field{index}",
                "type": "see meaning", "meaning": field,
            })
            continue
        meaning = field.get("meaning")
        if meaning is None and "value" in field:
            meaning = f"fixed {field['value']}"
        normalized.append({
            "offset": str(field.get("offset", index)),
            "name": field.get("name", f"field{index}"),
            "type": field.get("type", "bytes"),
            "meaning": meaning or "Recovered typed field",
        })
    return normalized


def _codes(value: list[str] | dict[str, str] | str | None) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "; ".join(f"0x{code} {meaning}" for code, meaning in value.items())
    return "; ".join(value or ()) or "No handler-specific code recovered"


def _primary_safety(handler: str, status: str, effects: str) -> str:
    if status == "authenticated-read-query":
        return "read-only"
    text = f"{handler} {effects}".lower()
    if any(word in text for word in ("password", "credential", "secret", "hash key", "certificate")):
        return "sensitive"
    if any(word in text for word in ("factory default", "restorefru", "restoresdr", "erase", "delete file")):
        return "destructive"
    if any(word in text for word in ("power cycle", "power off", "reboot", "reset bmc")):
        return "disruptive"
    return "state-changing"


def _evidence(entry: dict) -> str:
    evidence = entry.get("evidence", {})
    body = entry.get("body_analysis", {})
    parts = []
    for name in ("constructor_callsite", "register_call", "selector_store", "map_builder_raw"):
        if evidence.get(name):
            parts.append(f"{name} {evidence[name]}")
    if body.get("address"):
        parts.append(f"target handler body {body['address']}")
    return "; ".join(parts) or "Pinned target provider decompilation"


def _primary_operation(entry: dict) -> tuple[tuple[int, ...], dict]:
    netfn, command = _number(entry["netfn"]), _number(entry["command"])
    selector = _number(entry["selector"])
    request, response = entry["request"], entry["response"]
    status = entry["runnable_status"]
    return (netfn, command, selector), {
        "name": entry["handler"], "handler": entry["handler"],
        "purpose": entry["effects"], "privilege": _PRIVILEGE[entry["privilege"]],
        "request_length": (request["minimum_bytes_including_selector"], request["maximum_bytes_including_selector"]),
        "response_length": (response["minimum_bytes"], response["maximum_bytes"]),
        "request_fields": _fields(request["fields"]),
        "response_fields": _fields(response["fields"]),
        "completion_codes": _codes(entry["completion_codes"]),
        "activation": entry["activation"], "side_effects": entry["effects"],
        "safety": _primary_safety(entry["handler"], status, entry["effects"]),
        "confidence": entry["confidence"], "evidence": _evidence(entry),
        "prefix": bytes([selector]), "selector": bytes([selector]),
        "selector_offset": entry["selector_offset"],
        "owner": "Supermicro primary provider", "runnable": True, "live": None,
    }


def _primary_direct(entry: dict) -> tuple[tuple[int, int], dict] | None:
    netfn, command = _number(entry["netfn"]), _number(entry["command"])
    if entry["classification"] != "raw" or (netfn, command) in _PARENT_DISPATCHERS:
        return None
    request, response = entry["request"], entry["response"]
    status = entry["runnable_status"]
    return (netfn, command), {
        "name": entry["handler"], "handler": entry["handler"],
        "purpose": entry["effects"], "privilege": entry["privilege_name"],
        "request_length": (request["wire_minimum_bytes"], request["wire_maximum_bytes"]),
        "response_length": (response["minimum_bytes"], response["maximum_bytes"]),
        "request_fields": _fields(request["fields"]),
        "response_fields": _fields(response["fields"]),
        "completion_codes": _codes(entry["completion_codes"]),
        "activation": entry["activation"], "side_effects": entry["effects"],
        "safety": _primary_safety(entry["handler"], status, entry["effects"]),
        "confidence": entry["confidence"], "evidence": _evidence(entry),
        "owner": "Supermicro primary provider", "runnable": True, "live": None,
    }


def _manual_command(
    key: tuple[int, ...], *, name: str, handler: str, purpose: str,
    privilege: str, request_length: tuple[int | None, int | None],
    response_length: tuple[int | None, int | None], request_fields: list,
    response_fields: list, completion_codes: object, activation: str,
    safety: str, owner: str, evidence: str, runnable: bool = True,
) -> tuple[tuple[int, ...], dict]:
    return key, {
        "name": name, "handler": handler, "purpose": purpose,
        "privilege": privilege, "request_length": request_length,
        "response_length": response_length,
        "request_fields": _fields(request_fields), "response_fields": _fields(response_fields),
        "completion_codes": _codes(completion_codes), "activation": activation,
        "side_effects": purpose, "safety": safety,
        "confidence": "Exact target-body contract", "evidence": evidence,
        "prefix": bytes(key[2:]) if len(key) > 2 else None,
        "owner": owner, "runnable": runnable, "live": None,
    }


def _auxiliary_commands() -> list[tuple[tuple[int, ...], dict]]:
    rows = []
    for source in _AUXILIARY["ras"]["contracts"]:
        command = _number(source["command"])
        request_length = source["request"]["length"]
        request_bounds = (0, None) if isinstance(request_length, str) else (request_length, request_length)
        response_length = source["response"]["length"]
        response_bounds = (0, None) if isinstance(response_length, str) else (response_length, response_length)
        rows.append(_manual_command(
            (0x32, command), name=source["handler"], handler=source["handler"],
            purpose=source["effects"], privilege="Administrator",
            request_length=request_bounds, response_length=response_bounds,
            request_fields=source["request"].get("fields", []),
            response_fields=source["response"].get("fields", []),
            completion_codes=source["completion_codes"], activation=_AUXILIARY["ras"]["activation"],
            safety="read-only" if command == 0x22 else "state-changing",
            owner="Supermicro X14 RAS provider", evidence=source["evidence"],
        ))

    groups = {(source["group"], source["command"]): source
              for source in _AUXILIARY["primary_group_handlers"]}
    for group, command, name, safety, runnable in (
        (0x52, 0x01, "Get Manager Certificate Fingerprint", "read-only", False),
        (0x52, 0x02, "Get Bootstrap Account Credentials", "sensitive", False),
        (0xDC, 0x07, "Get Sensor Information", "read-only", True),
        (0xDC, 0x10, "Get Temperature Readings", "read-only", True),
        (0xDC, 0x06, "Get Asset Tag", "read-only", True),
        (0xDC, 0x08, "Set Asset Tag", "state-changing", True),
    ):
        source = groups[(f"0x{group:02x}", f"0x{command:02x}")]
        length = source["request"]["length"]
        bounds = (length + 1, length + 1) if isinstance(length, int) else (3, 19)
        response_length = source["response"].get("length")
        response_bounds = ((response_length, response_length)
                           if isinstance(response_length, int) else {
                               (0x52, 0x01): (33, 33),
                               (0xDC, 0x07): (2, 18),
                               (0xDC, 0x10): (2, None),
                               (0xDC, 0x06): (1, 17),
                           }[(group, command)])
        rows.append(_manual_command(
            (0x2C, command, group), name=name, handler=source["handler"],
            purpose=source["effects"], privilege=source["privilege"],
            request_length=bounds, response_length=response_bounds,
            request_fields=[f"group identifier 0x{group:02x}", *source["request"].get("fields", [])],
            response_fields=source["response"].get("fields", []),
            completion_codes=source["completion_codes"], activation=source["activation"],
            safety=safety, owner="DMTF/DCMI group handler",
            evidence=source.get("evidence", source.get("spec", "")), runnable=runnable,
        ))

    dcmi = groups[("0xdc", "0x01")]
    for selector in range(1, 7):
        rows.append(_manual_command(
            (0x2C, 0x01, 0xDC, selector), name=f"Get DCMI Capabilities Parameter {selector}",
            handler=dcmi["handler"], purpose=f"{dcmi['effects']} Parameter selector {selector}.",
            privilege=dcmi["privilege"], request_length=(2, 2), response_length=(3, None),
            request_fields=["group identifier 0xdc", f"parameter selector {selector:02x}"],
            response_fields=dcmi["response"]["fields"], completion_codes=dcmi["completion_codes"],
            activation=dcmi["activation"], safety="read-only", owner="DCMI group handler",
            evidence=dcmi["spec"],
        ))

    private = groups[("0x52", "0x03")]
    actions = {
        0x04: ("Read Host-Interface Settings", "read-only"),
        0x05: ("Read Bootstrap Account File List", "sensitive"),
        0x06: ("Private Maintenance No-op 06", "read-only"),
        0x07: ("Private Maintenance No-op 07", "read-only"),
        0x08: ("Private Maintenance No-op 08", "read-only"),
        0x09: ("Reinitialize Host-Interface State", "disruptive"),
        0x0A: ("Private Maintenance No-op 0a", "read-only"),
        0x0B: ("Private Maintenance No-op 0b", "read-only"),
        0x0C: ("Clear Bootstrap Users", "destructive"),
    }
    for action, (name, safety) in actions.items():
        rows.append(_manual_command(
            (0x2C, 0x03, 0x52, action), name=name, handler=private["handler"],
            purpose=private["effects"], privilege=private["privilege"],
            request_length=(2, 2), response_length=(0, 1),
            request_fields=["group identifier 0x52", f"private action selector {action:02x}"],
            response_fields=private["response"]["fields"], completion_codes=private["completion_codes"],
            activation=private["activation"], safety=safety, owner="Supermicro private group handler",
            evidence=private["evidence"],
        ))
    return rows


SUPERMICRO_X14: dict[tuple[int, ...], dict] = {}
for _entry in _PRIMARY["registrations"]:
    _result = _primary_direct(_entry)
    if _result:
        SUPERMICRO_X14[_result[0]] = _result[1]
for _entry in _PRIMARY["operations"]:
    _key, _contract = _primary_operation(_entry)
    SUPERMICRO_X14[_key] = _contract
for _key, _contract in _auxiliary_commands():
    SUPERMICRO_X14[_key] = _contract
SUPERMICRO_X14[(0x2C, 0x08, 0xDC)]["validator"] = "x14-asset-tag"


def _codec_field(field: dict, *, constant: int | None = None) -> dict | None:
    kind = field["type"]
    if kind in {"u8", "bool8", "u8 bitset", "packed channel/options u8", "packed selector/revision u8"}:
        result = {"name": field["name"], "kind": "u8"}
    elif kind == "u16le":
        result = {"name": field["name"], "kind": "u16le"}
    elif kind == "u32le":
        result = {"name": field["name"], "kind": "u32le"}
    elif match := re.fullmatch(r"bytes\[(\d+)]", kind):
        result = {"name": field["name"], "kind": "bytes", "length": int(match.group(1))}
    else:
        return None
    if constant is not None:
        result["constant"] = constant
    return result


def _fixed_codec(name: str, fields: list[dict] | None, length: tuple[int | None, int | None], *, response: bool = False):
    if fields is None or length[0] is None or length[0] != length[1]:
        return None
    codec_fields = []
    if response:
        codec_fields.append({"name": "completion_code", "kind": "u8"})
    for field in fields:
        meaning = field.get("meaning", "")
        constant = int(meaning.removeprefix("fixed "), 0) if meaning.startswith("fixed 0x") else None
        codec = _codec_field(field, constant=constant)
        if codec is None:
            return None
        codec_fields.append(codec)
    return build_fixed_packet_class(name, codec_fields, require_fields=not response)


SUPERMICRO_X14_PAYLOADS = {}
for _key, _contract in SUPERMICRO_X14.items():
    _request = _fixed_codec(f"X14 {_contract['name']} Request", _contract["request_fields"], _contract["request_length"])
    _response = _fixed_codec(f"X14 {_contract['name']} Response", _contract["response_fields"], _contract["response_length"], response=True)
    if _request is not None or _response is not None:
        SUPERMICRO_X14_PAYLOADS[_key] = (_request, _response)


SUPERMICRO_X14_CMD_NAMES = {key: value["name"] for key, value in SUPERMICRO_X14.items()}
X14_REGISTRATIONS = tuple(
    {**entry, "provider": "libsupermicrooemcmds.so.0.0.1"}
    for entry in _PRIMARY["registrations"]
) + tuple(X14_CATALOG["auxiliary_registrations"])

register("supermicro-x14", None, SUPERMICRO_X14_CMD_NAMES, SUPERMICRO_X14_PAYLOADS)

__all__ = [
    "SUPERMICRO_X14", "SUPERMICRO_X14_CMD_NAMES", "SUPERMICRO_X14_PAYLOADS",
    "X14_CATALOG", "X14_REGISTRATIONS", "X14_FIRMWARE_SHA256", "X14_ROOTFS_SHA256",
    "X14_PRIMARY_PROVIDER_SHA256", "X14_PRIMARY_PROVIDER_BUILD_ID",
]
