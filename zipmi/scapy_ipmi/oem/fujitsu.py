"""Firmware-bound Fujitsu iRMC S6 IPMI dispatch inventory.

The table is a byte-for-byte copy of the recovered iRMC S6 02.63S
``libipmipdkcmds.so.1.53.20`` registration data.  It is not yet a wire
contract: selector leaves and rack applicability are tracked separately.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from importlib.resources import files

from ._registry import build_fixed_packet_class, register


@dataclass(frozen=True)
class FujitsuRecord:
    table: str
    netfn: int
    scope: str
    lun: int
    index: int
    cmd: int
    privilege: int
    request_length: int | None
    handler: str
    handler_address: int


@dataclass(frozen=True)
class FujitsuOperation:
    name: str
    netfn: int
    cmd: int
    lun: int
    prefix: bytes
    privilege: int
    request: object
    response: object
    effect: str
    status: str
    activation: str
    source: str
    runnable: bool
    requires_unsafe: bool
    exact_safe_length: int | None


def _load_records() -> tuple[FujitsuRecord, ...]:
    source = files("zipmi").joinpath(
        "data/sources/fujitsu-irmc-s6-command-tables.tsv"
    )
    with source.open(newline="") as stream:
        rows = csv.DictReader(stream, delimiter="\t")
        return tuple(
            FujitsuRecord(
                table=row["table"], netfn=int(row["netfn"], 0),
                scope=row["scope"], lun=3 if row["scope"] == "wire LUN 3" else 0,
                index=int(row["index"]), cmd=int(row["cmd"], 0),
                privilege=int(row["min_priv"], 0),
                request_length=(None if row["req_len"] == "variable"
                                else int(row["req_len"])),
                handler=row["handler"],
                handler_address=int(row["ghidra_handler"], 0),
            )
            for row in rows
            if row["table"] and not row["table"].startswith("#")
            and row["handler"] != "?"
        )


FUJITSU_RECORDS = _load_records()


def _load_operations() -> tuple[FujitsuOperation, ...]:
    source = files("zipmi").joinpath(
        "data/sources/fujitsu-irmc-s6-operations.json"
    )
    with source.open() as stream:
        rows = json.load(stream)["operations"]
    return tuple(FujitsuOperation(
        name=row["name"], netfn=row["netfn"], cmd=row["cmd"], lun=row["lun"],
        prefix=bytes(row["prefix"]), privilege=row["privilege"],
        request=row["request"], response=row["response"], effect=row["effect"],
        status=row["status"], activation=row["activation"], source=row["source"],
        runnable=row["runnable"], requires_unsafe=row["requiresUnsafe"],
        exact_safe_length=row["exactSafeLength"],
    ) for row in rows)


FUJITSU_OPERATIONS = _load_operations()
FUJITSU_CMD_NAMES = {
    (row.netfn, row.cmd): row.handler
    for row in FUJITSU_RECORDS
    if row.lun == 0 and row.scope != "MSMM callback"
}
FUJITSU_OPERATION_NAMES = {
    (op.netfn, op.cmd, *op.prefix): op.name for op in FUJITSU_OPERATIONS
}
FUJITSU_SELECTOR_PAYLOADS = []
_power_fields = {0x15: "reason", 0x16: "reason", 0x18: "runtime_power_field",
                 0x1D: "inhibit"}
for _operation in FUJITSU_OPERATIONS:
    if _operation.exact_safe_length != 4:
        continue
    _selector = _operation.prefix[-1]
    _request = build_fixed_packet_class(
        f"iRMC {_operation.cmd:02x}/{_selector:02x} Request",
        [{"name": "iana0", "kind": "u8", "constant": 0x80},
         {"name": "iana1", "kind": "u8", "constant": 0x28},
         {"name": "iana2", "kind": "u8", "constant": 0},
         {"name": "selector", "kind": "u8", "constant": _selector}],
        require_fields=True,
    )
    _response = None
    if _operation.cmd == 0x01:
        _response = build_fixed_packet_class(
            f"iRMC SCCI {_selector:02x} Response",
            [{"name": "completion_code", "kind": "u8"},
             {"name": "iana0", "kind": "u8", "constant": 0x80},
             {"name": "iana1", "kind": "u8", "constant": 0x28},
             {"name": "iana2", "kind": "u8", "constant": 0},
             {"name": "length", "kind": "u8", "constant": 4 if _selector == 0x18 else 1},
             {"name": _power_fields[_selector],
              "kind": "u32le" if _selector == 0x18 else "u8"}],
        )
    FUJITSU_SELECTOR_PAYLOADS.append((0x2E, _operation.cmd, 3, bytes([_selector]),
                                      (_request, _response)))
register("fujitsu", 10368, FUJITSU_CMD_NAMES | FUJITSU_OPERATION_NAMES,
         selector_payloads=FUJITSU_SELECTOR_PAYLOADS)


__all__ = [
    "FujitsuRecord", "FujitsuOperation", "FUJITSU_RECORDS", "FUJITSU_OPERATIONS",
    "FUJITSU_CMD_NAMES", "FUJITSU_OPERATION_NAMES",
    "FUJITSU_SELECTOR_PAYLOADS",
]
