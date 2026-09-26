"""Firmware-bound Fujitsu iRMC S6 IPMI dispatch inventory.

The table is a byte-for-byte copy of the recovered iRMC S6 02.63S
``libipmipdkcmds.so.1.53.20`` registration data.  It is not yet a wire
contract: selector leaves and rack applicability are tracked separately.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from importlib.resources import files

from ._registry import register


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
FUJITSU_CMD_NAMES = {
    (row.netfn, row.cmd): row.handler
    for row in FUJITSU_RECORDS
    if row.lun == 0 and row.scope != "MSMM callback"
}
register("fujitsu", 10368, FUJITSU_CMD_NAMES)


__all__ = ["FujitsuRecord", "FUJITSU_RECORDS", "FUJITSU_CMD_NAMES"]
