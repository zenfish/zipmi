# z-artifact: 2488cd73-5226-48f0-ae3a-e9e40dbdc003
# z-artifact: pending
"""Firmware-bound Supermicro X10 AST2400 BMC 3.93 OEM IPMI support."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ._registry import build_fixed_packet_class, register


SM_IANA = 10876
X10_FIRMWARE_SHA256 = "9bd3fbe8ddb8ee8e0f7d96ee37c810cef99d6c9f9566ddd13dca7ea455204214"
X10_ROOTFS_SHA256 = "f414a4dc447a4bea09374398f47caca0112a35cd5f61030f19712634659c67fd"
X10_PROVIDER_SHA256 = "128d486c2de83d7e5dfddc0a25f74142f0c3fe265567ad4b1221c8defdbe3d07"

_SOURCE = Path(__file__).parents[2] / "data/sources/supermicro-x10-contracts.json"
X10_CATALOG = json.loads(_SOURCE.read_text())
if X10_CATALOG["firmware"]["image_sha256"] != X10_FIRMWARE_SHA256:
    raise RuntimeError("Supermicro X10 catalog does not match the pinned firmware")


def _number(value: int | str) -> int:
    return value if isinstance(value, int) else int(value, 0)


def _bounds(layout: dict) -> tuple[int | None, int | None]:
    return layout.get("minimum_bytes"), layout.get("maximum_bytes")


def _codes(value: list[str] | str) -> str:
    return value if isinstance(value, str) else "; ".join(value)


def _contract(row: dict) -> tuple[tuple[int, ...], dict]:
    key = (_number(row["netfn"]), _number(row["command"]))
    prefix = bytes(_number(value) for value in row.get("prefix", ()))
    if prefix:
        key += tuple(prefix)
    request_bounds = _bounds(row["request"])
    return key, {
        "name": row["name"],
        "handler": row["handler"],
        "purpose": row["purpose"],
        "privilege": row["privilege"],
        "request_length": request_bounds,
        "response_length": _bounds(row["response"]),
        "request_fields": row["request"].get("fields"),
        "response_fields": row["response"].get("fields"),
        "completion_codes": _codes(row["completion_codes"]),
        "activation": row["activation"],
        "side_effects": row["side_effects"],
        "safety": row["safety"],
        "safety_note": row["safety_note"],
        "confidence": row["confidence"],
        "evidence": row["evidence"],
        "prefix": prefix or None,
        "selector_offset": row.get("selector_offset"),
        "runnable": row.get("runnable", True),
        "live": row.get("live"),
        "requires_unsafe": (
            row["safety"] != "read-only"
            or request_bounds[1] is None
            or not row.get("target_bounded", False)
        ),
    }


SUPERMICRO_X10 = dict(_contract(row) for row in X10_CATALOG["operations"])


def _codec_field(field: dict, *, constant: int | None = None) -> dict | None:
    kind = field["type"]
    if kind in {"u8", "bool8", "u8 boolean", "u8 bitfield", "enum8"}:
        result = {"name": field["name"], "kind": "u8"}
    elif kind in {"u16le", "u16le bitfield"}:
        result = {"name": field["name"], "kind": "u16le"}
    elif kind == "u16be":
        result = {"name": field["name"], "kind": "u16be"}
    elif kind == "u32le":
        result = {"name": field["name"], "kind": "u32le"}
    elif match := re.fullmatch(r"bytes\[(\d+)]", kind):
        result = {"name": field["name"], "kind": "bytes", "length": int(match.group(1))}
    else:
        return None
    if constant is not None:
        result["constant"] = constant
    return result


def _fixed_codec(name: str, layout: dict, *, response: bool = False):
    low, high = _bounds(layout)
    fields = layout.get("fields")
    if fields is None or low is None or low != high:
        return None
    codec_fields = []
    if response:
        codec_fields.append({"name": "completion_code", "kind": "u8"})
    for field in fields:
        value = field.get("value")
        constant = int(value, 0) if isinstance(value, str) else value
        codec = _codec_field(field, constant=constant)
        if codec is None:
            return None
        codec_fields.append(codec)
    widths = {"u8": 1, "u16le": 2, "u16be": 2, "u32le": 4}
    payload_width = sum(
        field["length"] if field["kind"] == "bytes" else widths[field["kind"]]
        for field in codec_fields
        if field["name"] != "completion_code"
    )
    if payload_width != low:
        return None
    return build_fixed_packet_class(name, codec_fields, require_fields=not response)


SUPERMICRO_X10_PAYLOADS = {}
for _row in X10_CATALOG["operations"]:
    _key = (_number(_row["netfn"]), _number(_row["command"])) + tuple(
        _number(value) for value in _row.get("prefix", ())
    )
    _request = _fixed_codec(f"X10 {_row['name']} Request", _row["request"])
    _response = _fixed_codec(f"X10 {_row['name']} Response", _row["response"], response=True)
    if _request is not None or _response is not None:
        SUPERMICRO_X10_PAYLOADS[_key] = (_request, _response)

SUPERMICRO_X10_CMD_NAMES = {key: value["name"] for key, value in SUPERMICRO_X10.items()}
X10_REGISTRATIONS = tuple(X10_CATALOG["registrations"])

register("supermicro-x10", SM_IANA, SUPERMICRO_X10_CMD_NAMES, SUPERMICRO_X10_PAYLOADS)

__all__ = [
    "SUPERMICRO_X10", "SUPERMICRO_X10_CMD_NAMES", "SUPERMICRO_X10_PAYLOADS",
    "X10_CATALOG", "X10_REGISTRATIONS", "X10_FIRMWARE_SHA256", "X10_ROOTFS_SHA256",
    "X10_PROVIDER_SHA256",
]
