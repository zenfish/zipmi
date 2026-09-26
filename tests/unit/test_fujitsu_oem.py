"""Firmware-bound iRMC S6 dispatch-table invariants."""
from collections import Counter
from hashlib import sha256
from importlib.resources import files

from zipmi.scapy_ipmi.oem.fujitsu import FUJITSU_CMD_NAMES, FUJITSU_RECORDS


def test_pinned_irmc_s6_dispatch_table() -> None:
    source = files("zipmi").joinpath(
        "data/sources/fujitsu-irmc-s6-command-tables.tsv"
    )
    assert sha256(source.read_bytes()).hexdigest() == (
        "6c25538d508e398135855d59550148b3fd93cdcc045bc9556e4f79c335f72dfa"
    )
    assert len(FUJITSU_RECORDS) == 148
    assert len({(r.netfn, r.cmd) for r in FUJITSU_RECORDS}) == 135
    assert len({(r.netfn, r.cmd, r.lun) for r in FUJITSU_RECORDS}) == 138
    assert Counter(r.netfn for r in FUJITSU_RECORDS) == {
        0x00: 3, 0x04: 1, 0x06: 7, 0x0A: 10, 0x0C: 1,
        0x2C: 2, 0x2E: 20, 0x30: 58, 0x34: 46,
    }
    assert sum(r.lun == 3 for r in FUJITSU_RECORDS) == 3
    assert len(FUJITSU_CMD_NAMES) == 135
