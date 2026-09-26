#!/usr/bin/env python3
"""Merge reviewed iDRAC10 contract metadata into the canonical catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _byte_string(value: str) -> bytes:
    value = (value or "").replace("0x", "").replace(" ", "")
    return bytes.fromhex(value) if value else b""


def _prefix(record: dict) -> bytes:
    if record.get("prefix"):
        return _byte_string(record["prefix"])
    subcmd = record.get("subcmd", "")
    if not subcmd:
        return b""
    value = 0
    for token in subcmd.split():
        value = (value << 8) | int(token, 16)
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _subcmd_value(value: str) -> int:
    result = 0
    for token in value.split():
        result = (result << 8) | int(token, 16)
    return result


def _key(record: dict) -> tuple[str, int, int, bytes]:
    return record["name"], int(record["netfn"], 16), int(record["cmd"], 16), _prefix(record)


def _length(value: dict | None, *, add: int = 0):
    value = value or {}
    if value.get("kind") == "exact":
        return value["bytes"] + add
    if value.get("kind") == "minimum":
        return {"min": value["bytes"] + add, "max": None}
    if value.get("kind") == "range":
        return {"min": value["bytes"][0] + add,
                "max": value["bytes"][1] + add}
    if value.get("kind") == "branch":
        numbers = [item for item in value["bytes"].values()
                   if isinstance(item, int)]
        dispatch = value.get("dispatch", {})
        minimum = dispatch.get("bytes")
        if minimum is None and numbers:
            minimum = min(numbers)
        maximum = max(numbers) if len(numbers) == len(value["bytes"]) else None
        return {"min": minimum + add if minimum is not None else None,
                "max": maximum + add if maximum is not None else None}
    minimum = value.get("min")
    maximum = value.get("max")
    minimum = minimum + add if minimum is not None else None
    maximum = maximum + add if maximum is not None else None
    if minimum is not None and minimum == maximum:
        return minimum
    return {"min": minimum, "max": maximum}


def _effect(value: str, name: str) -> str:
    if value == "read-with-side-effects":
        if name in {"CmdOEMGetChassisCapabilities", "CmdOEMGetSelfTestResults"}:
            return "safe"
        if name in {"DellCPLDAccessStatus", "SubCmdHandler/InBandMultiPlatformEventCmd"}:
            return "security-sensitive"
        return "mutates"
    return {
        "read-only": "safe",
        "mutating": "mutates",
        "mixed": "security-sensitive",
        "safe/read-only": "safe",
        "stateful/side-effecting": "mutates",
        "dangerous/state-changing": "mutates",
        "security-sensitive/read-only": "security-sensitive",
    }.get(value, value)


def _records(fragment: dict) -> list[dict]:
    if "records" in fragment:
        raw = fragment["records"]
        return list(raw.values()) if isinstance(raw, dict) else raw
    if "operations" not in fragment:
        raise ValueError("contract fragment has neither records nor operations")
    records = []
    for operation in fragment["operations"]:
        identity = operation["prefixDiscriminant"]
        subcmd = identity.get("subcmd")
        if isinstance(subcmd, int):
            subcmd = f"{subcmd:02x}"
        records.append({
            "name": operation["name"],
            "netfn": identity["netfn"],
            "cmd": identity["cmd"],
            "subcmd": subcmd or "",
            "effect": operation["safety"],
            "sideEffects": operation["sideEffects"],
            "requestLength": operation["requestLength"],
            "responseLengthIncludingCc": operation["responseLengthIncludingCc"],
            "completionCodes": operation["completionCodes"],
            "activation": operation["activation"],
            "evidence": operation["evidence"],
        })
    return records


def _selector_offset(contract: dict) -> int | None:
    subcmd = contract.get("subcmd")
    if not subcmd or _subcmd_value(subcmd) > 0xFF:
        return None
    selector = _subcmd_value(subcmd)
    hits = [field["offset"] for field in contract.get("requestFields", [])
            if field.get("constant") == selector]
    if len(hits) == 1:
        return hits[0]
    if contract.get("evidence", {}).get("selectorPrefix"):
        return 0
    return None


def _exact_length(value) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, dict):
        return None
    if value.get("kind") == "exact":
        return value["bytes"]
    if value.get("min") is not None and value.get("min") == value.get("max"):
        return value["min"]
    return None


def _codec_fields(fields: list[dict], total: int, *, drop_cc: bool = False,
                  prefix: bytes = b"") -> list[dict] | None:
    fields = [dict(field) for field in fields]
    if drop_cc:
        if (not fields or fields[0].get("offset") != 0
                or fields[0].get("length") != 1
                or "completion code" not in fields[0].get("description", "").lower()):
            return None
        fields = fields[1:]
        total -= 1
        for field in fields:
            field["offset"] -= 1
    position = 0
    normalized = []
    for field in sorted(fields, key=lambda item: item["offset"]):
        size = field.get("length")
        if field["offset"] != position or not isinstance(size, int) or size < 1:
            return None
        item = {
            "name": f"field_{position}",
            "kind": "u8" if size == 1 else "bytes",
            "description": field.get("description", ""),
        }
        if size != 1:
            item["length"] = size
        if size == 1 and position < len(prefix):
            item["constant"] = prefix[position]
        normalized.append(item)
        position += size
    return normalized if position == total else None


def _promote_codecs(record: dict, contract: dict) -> None:
    if contract.get("codecState") != "verified":
        return
    request_length = _exact_length(contract.get("requestLength"))
    request_fields = (_codec_fields(
        contract.get("requestFields", []), request_length, prefix=_prefix(record))
        if request_length is not None else None)
    response_includes_cc = "responseLengthIncludingCc" in contract
    response_length = _exact_length(contract.get(
        "responseLengthIncludingCc" if response_includes_cc else "responseLength"))
    response_fields = (_codec_fields(
        contract.get("responseFields", []), response_length,
        drop_cc=response_includes_cc)
        if response_length is not None else None)
    if request_fields is not None:
        record["requestCodec"] = True
        record["requestFields"] = request_fields
    if response_fields is not None:
        record["responseCodec"] = True
        record["responseFields"] = [
            {"name": "completion_code", "kind": "u8"}, *response_fields,
        ]
    if record.get("requestCodec") and record.get("responseCodec"):
        record["codecState"] = "verified"
    elif record.get("requestCodec"):
        record["codecState"] = "request-only"
    elif record.get("responseCodec"):
        record["codecState"] = "response-only"


def merge(catalog: dict, fragment: dict) -> dict:
    by_key = {_key(record): record for record in catalog["commands"]}
    records = _records(fragment)
    keys = [_key(record) for record in records]
    if len(keys) != len(set(keys)):
        raise ValueError("contract fragment has duplicate operation keys")
    missing = [key for key in keys if key not in by_key]
    if missing:
        raise ValueError(f"contract records absent from catalog: {missing[:3]}")

    for contract, key in zip(records, keys):
        record = by_key[key]
        response_length = contract.get("responseLengthIncludingCc")
        response_add = 0
        if response_length is None:
            response_length = contract.get("responseLength")
            response_add = 1
        record.update({
            "effect": _effect(contract["effect"], contract["name"]),
            "sideEffects": "; ".join(contract["sideEffects"]) or "none",
            "requestLength": _length(contract.get("requestLength")),
            "responseLengthIncludingCc": _length(response_length, add=response_add),
            "completionCodes": contract["completionCodes"],
            "activation": contract["activation"],
            "codecState": record.get("codecState", "raw-exact"),
            "evidence": contract["evidence"],
        })
        if contract.get("subcmd"):
            record["selectorOffset"] = _selector_offset(contract)
        _promote_codecs(record, contract)
    return catalog


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", type=Path)
    parser.add_argument("fragment", type=Path)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text())
    fragment = json.loads(args.fragment.read_text())
    merge(catalog, fragment)
    args.catalog.write_text(json.dumps(catalog, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
