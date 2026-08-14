"""
test_scapy_bus.py — Scapy packet classes for the bus/mobo-component commands
(promoted ⚡→✓). Pins field-level encode/decode of the wire format so these
commands are usable programmatically (send_cmd) and fuzzable at the field level.

Grows as more bus commands are scapified (I2C, FRU, LAN/NIC, serial, sensor).
"""
from __future__ import annotations

from zipmi.scapy_ipmi.commands import (
    MasterWriteReadReq, MasterWriteReadResp, CMD_PAYLOADS,
)


# === Master Write-Read (0x06/0x52) — the I2C/SMBus master primitive ========

def test_mwr_req_packs_bus_and_slave_bytes():
    # channel 1, private bus 2, slave 0x50 (SPD EEPROM), read 8, write [0x00]:
    #   bus byte  = (1<<4)|(2<<1)|1 = 0x15
    #   slave byte= 0x50<<1         = 0xA0   (7-bit addr, LSB clear)
    req = MasterWriteReadReq(channel=1, priv_bus=2, private=1,
                             slave_addr=0x50, read_count=8, write_data=b"\x00")
    assert bytes(req) == bytes([0x15, 0xA0, 0x08, 0x00])


def test_mwr_req_public_bus_default():
    # public bus, channel 0, slave 0x2c, read 1, no write data -> 0x00 0x58 0x01
    req = MasterWriteReadReq(slave_addr=0x2C, read_count=1)
    assert bytes(req) == bytes([0x00, 0x58, 0x01])


def test_mwr_req_fields_are_mutable_for_fuzzing():
    # the whole point of scapifying: every wire field is a real, settable field
    req = MasterWriteReadReq(slave_addr=0x50)
    assert {f.name for f in req.fields_desc} >= {
        "channel", "priv_bus", "private", "slave_addr", "read_count", "write_data"}
    req.slave_addr = 0x7F
    assert bytes(req)[1] == 0xFE          # 0x7F << 1


def test_mwr_resp_decodes_read_data():
    r = MasterWriteReadResp(bytes([0x00]) + b"\xde\xad\xbe\xef")
    assert r.comp_code == 0x00
    assert bytes(r.read_data) == b"\xde\xad\xbe\xef"


def test_mwr_registered_in_cmd_payloads():
    assert CMD_PAYLOADS[(0x06, 0x52)] == (MasterWriteReadReq, MasterWriteReadResp)
