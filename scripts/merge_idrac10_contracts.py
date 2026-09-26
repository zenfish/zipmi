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


def _key(record: dict) -> tuple[str, int, int, bytes]:
    return record["name"], int(record["netfn"], 16), int(record["cmd"], 16), _prefix(record)


def _length(value: dict | None, *, add: int = 0):
    value = value or {}
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
    }.get(value, value)


def _selector_offset(contract: dict) -> int | None:
    subcmd = contract.get("subcmd")
    if not subcmd or int(subcmd, 16) > 0xFF:
        return None
    selector = int(subcmd, 16)
    hits = [field["offset"] for field in contract.get("requestFields", [])
            if field.get("constant") == selector]
    if len(hits) == 1:
        return hits[0]
    if contract.get("evidence", {}).get("selectorPrefix"):
        return 0
    return None


def merge(catalog: dict, fragment: dict) -> dict:
    by_key = {_key(record): record for record in catalog["commands"]}
    raw_records = fragment["records"]
    records = list(raw_records.values()) if isinstance(raw_records, dict) else raw_records
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
            "codecState": "raw-exact",
            "evidence": contract["evidence"],
        })
        if contract.get("subcmd"):
            record["selectorOffset"] = _selector_offset(contract)
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
