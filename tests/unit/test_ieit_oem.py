# z-artifact: 4bf04105-b3f4-4aeb-99c7-c310c36dcea4
"""Closure checks for the firmware-bound IEIT NF5468M6 OEM catalog."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISPATCH = ROOT / "zipmi/data/sources/ieit-nf5468m6-dispatch.json"


def test_ieit_dispatch_denominator_and_collision_are_preserved() -> None:
    catalog = json.loads(DISPATCH.read_text())
    rows = catalog["rows"]

    assert catalog["registration_rows"] == len(rows) == 324
    assert catalog["unique_addresses"] == len({
        (row["netfn"], row["cmd"]) for row in rows
    }) == 323
    assert catalog["collisions"] == {
        "0x30/0xe2": ["CommerMEOEMGetReading", "PnmOemGetReading"],
    }
    assert Counter(row["provider"].split(":", 1)[0] for row in rows) == {
        "ami-core": 86,
        "ami-plugin": 97,
        "ieit-pdk": 137,
        "intel-pnm": 3,
        "ami-hpm-oem": 1,
    }
