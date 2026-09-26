#!/usr/bin/env python3
"""Distill the zBMC iRMC S6 selector evidence into zipmi's runtime catalog."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "zipmi/data/sources/fujitsu-irmc-s6-operations.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source: Path) -> dict:
    evidence = source / "boxes/irmc-fujitsu/evidence"
    files = {
        "f1": evidence / "f1-selector-contracts.json",
        "f5": evidence / "f5-selector-contracts.json",
        "scci": evidence / "scci-selector-contracts.json",
        "standard": evidence / "standard-overrides.json",
    }
    data = {key: load(path) for key, path in files.items()}
    with (evidence / "irmc-s6-command-tables.tsv").open(newline="") as stream:
        table = [row for row in csv.DictReader(stream, delimiter="\t")
                 if row["table"] and not row["table"].startswith("#")
                 and row["handler"] != "?" and row["scope"] != "MSMM callback"]
    privilege = {(int(row["netfn"], 0), int(row["cmd"], 0)): int(row["min_priv"], 0)
                 for row in table if row["scope"] != "wire LUN 3"}
    operations = []

    def add(cmd: int, selector: str, item: dict, origin: str) -> None:
        prefix = [0x80, 0x28, 0x00, int(selector, 16)]
        exact_safe = cmd == 0x01 and selector in {"15", "16", "18", "1d"}
        operations.append({
            "name": f"iRMC_{item.get('name') or item.get('notes') or 'Selector'}_{cmd:02X}_{selector.upper()}",
            "netfn": 0x2E, "cmd": cmd, "lun": 0, "prefix": prefix,
            "privilege": privilege[(0x2E, cmd)],
            "request": item.get("request"), "response": item.get("response"),
            "effect": item.get("effect", "unknown"),
            "status": item["status"], "activation": item.get("activation", "registered; platform-dependent"),
            "source": f"{files[origin].name}#{cmd:02x}/{selector}",
            "runnable": True, "requiresUnsafe": not exact_safe,
            "exactSafeLength": 4 if exact_safe else None,
        })

    for selector, item in data["f1"]["selector_contracts"].items():
        add(0xF1, selector, item, "f1")
    for selector, item in data["f5"]["selectors"].items():
        add(0xF5, selector, item, "f5")
    for command, info in data["scci"]["commands"].items():
        for selector, item in info["selectors"].items():
            add(int(command, 16), selector, item, "scci")
    assert len(operations) == 228

    for row in data["standard"]["records"]:
        if row["netfn"] != "2c":
            continue
        cmd = int(row["cmd"], 16)
        for branch in row["branches"]:
            group = int(branch["group"], 16)
            prefix = [group]
            if group == 0x52:
                prefix.append(0x01 if cmd == 0x01 else 0xA5)
            operations.append({
                "name": f"iRMC_{'DCMI' if group == 0xDC else 'RedfishBootstrap'}_{cmd:02X}",
                "netfn": 0x2C, "cmd": cmd, "lun": 0, "prefix": prefix,
                "privilege": 4 if group == 0x52 else privilege[(0x2C, cmd)],
                "request": branch.get("request"), "response": row.get("response"),
                "effect": branch.get("safety", row["side_effect"]),
                "status": "decoded" if group == 0x52 else "partial",
                "activation": branch.get("channel", "standard DCMI branch"),
                "source": f"{files['standard'].name}#2c/{cmd:02x}/{group:02x}",
                "runnable": group != 0x52,
                "requiresUnsafe": True, "exactSafeLength": None,
            })
    assert len(operations) == 232
    keys = {(op["netfn"], op["cmd"], *op["prefix"]) for op in operations}
    assert len(keys) == len(operations)
    return {
        "target": "PRIMERGY RX2540 M7 iRMC S6 02.63S / SDR 03.67",
        "librarySha256": "35839f7ab40993898666425d50e18654d68791c7dfe3bb5a3c3496e4daa23804",
        "tableSha256": digest(evidence / "irmc-s6-command-tables.tsv"),
        "sourceSha256": {path.name: digest(path) for path in files.values()},
        "operations": sorted(operations, key=lambda op: (op["netfn"], op["cmd"], op["prefix"])),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT.parent / "zbmc",
                        help="zBMC checkout containing retained Fujitsu evidence")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = json.dumps(build(args.source), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        assert OUTPUT.read_text() == document, "Fujitsu zipmi catalog is out of sync"
        print("Fujitsu catalog OK: 232 selector/group operations")
    else:
        OUTPUT.write_text(document)
        print("wrote Fujitsu catalog: 232 selector/group operations")


if __name__ == "__main__":
    main()
