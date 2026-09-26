"""Firmware-bound iRMC S6 dispatch-table invariants."""
from collections import Counter
from hashlib import sha256
from importlib.resources import files
from argparse import Namespace

from zipmi.cli.oem_cmds import _vendor_listing, cmd_oem_run
from zipmi.scapy_ipmi.oem.fujitsu import (
    FUJITSU_CMD_NAMES, FUJITSU_OPERATION_NAMES, FUJITSU_OPERATIONS, FUJITSU_RECORDS,
)


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
    assert len(FUJITSU_OPERATIONS) == len(FUJITSU_OPERATION_NAMES) == 232
    assert len({op.name for op in FUJITSU_OPERATIONS}) == 232
    assert sum(not op.requires_unsafe for op in FUJITSU_OPERATIONS) == 4
    assert sum(not op.runnable for op in FUJITSU_OPERATIONS) == 2


def test_irmc_named_execution_is_fail_closed_without_wire_contract(capsys) -> None:
    listing = _vendor_listing("fujitsu")
    assert len(listing) == 367
    assert listing[(0x2E, 0x01, 0x80, 0x28, 0x00, 0x15)]["requires_unsafe"] is False
    assert listing[(0x2E, 0xF1)]["runnable"] is False
    assert listing[(0x2C, 0x02, 0x52, 0xA5)]["runnable"] is False
    assert cmd_oem_run(Namespace(cmd_name=listing[(0x2E, 0xF1)]["name"], data=[], unsafe=True), "fujitsu") == 2
    assert "no supported LAN execution contract" in capsys.readouterr().err
    assert cmd_oem_run(Namespace(cmd_name=listing[(0x34, 0x39)]["name"], data=[], unsafe=False), "fujitsu") == 2
    assert "add --unsafe" in capsys.readouterr().err
