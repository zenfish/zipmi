"""
test_scapy_bus.py — Scapy packet classes for the bus/mobo-component commands
(promoted ⚡→✓). Pins field-level encode/decode of the wire format so these
commands are usable programmatically (send_cmd) and fuzzable at the field level.

Grows as more bus commands are scapified (I2C, FRU, LAN/NIC, serial, sensor).
"""
from __future__ import annotations

from zipmi.scapy_ipmi.commands import (
    MasterWriteReadReq, MasterWriteReadResp, CMD_PAYLOADS,
    ReadFRUDataReq, ReadFRUDataResp,
    WriteFRUDataReq, WriteFRUDataResp,
    SetLANConfigParamReq,
    GetIPUDPRMCPStatsReq, GetIPUDPRMCPStatsResp,
    GetSerialConfigReq, GetSerialConfigResp, SetSerialConfigReq,
    GetSensorThresholdReq, GetSensorThresholdResp,
    GetSensorReadingFactorsReq, GetSensorReadingFactorsResp,
    GetDeviceSDRReq, GetDeviceSDRResp,
    _BareCCResp,
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


# === Read FRU Data (0x0A/0x11) — I2C EEPROM window ==========================

def test_read_fru_req_packs_device_offset_count():
    # Old handler wire: [device_id, offset_lo, offset_hi, count]. offset is LE u16.
    req = ReadFRUDataReq(device_id=0, offset=0x0010, count=16)
    assert bytes(req) == bytes([0x00, 0x10, 0x00, 0x10])


def test_read_fru_req_offset_is_little_endian():
    req = ReadFRUDataReq(device_id=3, offset=0x0102, count=8)
    assert bytes(req) == bytes([0x03, 0x02, 0x01, 0x08])   # 0x0102 -> 02 01 LE


def test_read_fru_resp_decodes_count_and_data():
    r = ReadFRUDataResp(bytes([0x00, 0x04]) + b"ABCD")
    assert r.comp_code == 0x00 and r.count_returned == 4
    assert bytes(r.data) == b"ABCD"


def test_read_fru_registered():
    assert CMD_PAYLOADS[(0x0A, 0x11)] == (ReadFRUDataReq, ReadFRUDataResp)


# === Write FRU Data (0x0A/0x12) ============================================

def test_write_fru_req_packs_device_offset_data():
    # Old handler wire: [dev, off_lo, off_hi] + data.
    req = WriteFRUDataReq(device_id=1, offset=0x0102, data=b"\xaa\xbb")
    assert bytes(req) == bytes([0x01, 0x02, 0x01, 0xAA, 0xBB])


def test_write_fru_resp_decodes_count_written():
    r = WriteFRUDataResp(bytes([0x00, 0x07]))
    assert r.comp_code == 0x00 and r.count_written == 7


def test_write_fru_registered():
    assert CMD_PAYLOADS[(0x0A, 0x12)] == (WriteFRUDataReq, WriteFRUDataResp)


# === Set LAN Config Params (0x0C/0x01) — bare-CC response ==================

def test_set_lan_config_req_packs_channel_param_data():
    req = SetLANConfigParamReq(channel=1, parameter_selector=3,
                               data=b"\xc0\xa8\x01\x01")
    assert bytes(req) == bytes([0x01, 0x03, 0xC0, 0xA8, 0x01, 0x01])


def test_set_lan_config_registered_bare_cc():
    assert CMD_PAYLOADS[(0x0C, 0x01)] == (SetLANConfigParamReq, _BareCCResp)


# === Get IP/UDP/RMCP Statistics (0x0C/0x04) ================================

def test_lan_stats_req_packs_channel_and_clear():
    # Old handler wire: [channel, 0x00] (clear=0 => read-only).
    req = GetIPUDPRMCPStatsReq(channel=0x0E, clear=0)
    assert bytes(req) == bytes([0x0E, 0x00])


def test_lan_stats_resp_decodes_seven_le_counters():
    body = b"".join(x.to_bytes(2, "little") for x in [1, 2, 3, 4, 5, 6, 7])
    r = GetIPUDPRMCPStatsResp(bytes([0x00]) + body)
    assert (r.ip_hdr_errors, r.ip_addr_errors, r.fragments_rx, r.ip_pkts_tx,
            r.ip_pkts_rx, r.rx_pkts_dropped, r.rmcp_pkts_rx) == (1, 2, 3, 4, 5, 6, 7)


def test_lan_stats_registered():
    assert CMD_PAYLOADS[(0x0C, 0x04)] == (GetIPUDPRMCPStatsReq, GetIPUDPRMCPStatsResp)


# === Get/Set Serial/Modem Config (0x0C/0x11, 0x0C/0x10) ====================

def test_get_serial_config_req_packs_selectors():
    # Old serial_modem wire: [channel&0x0F, param, set_sel, block_sel].
    req = GetSerialConfigReq(channel=0x0E, parameter_selector=10,
                             set_selector=0, block_selector=0)
    assert bytes(req) == bytes([0x0E, 0x0A, 0x00, 0x00])


def test_get_serial_config_resp_decodes_rev_and_data():
    r = GetSerialConfigResp(bytes([0x00, 0x11]) + b"ATZ")
    assert r.comp_code == 0x00 and r.parameter_revision == 0x11
    assert bytes(r.data) == b"ATZ"


def test_set_serial_config_req_packs_channel_param_data():
    # Old serial_modem wire: [channel&0x0F, param] + data.
    req = SetSerialConfigReq(channel=0, parameter_selector=13, data=b"ATZ")
    assert bytes(req) == bytes([0x00, 0x0D]) + b"ATZ"


def test_serial_config_registered():
    assert CMD_PAYLOADS[(0x0C, 0x11)] == (GetSerialConfigReq, GetSerialConfigResp)
    assert CMD_PAYLOADS[(0x0C, 0x10)] == (SetSerialConfigReq, _BareCCResp)


# === Get Sensor Threshold (0x04/0x27) ======================================

def test_sensor_threshold_req_packs_sensor_num():
    assert bytes(GetSensorThresholdReq(sensor_num=5)) == bytes([0x05])


def test_sensor_threshold_resp_decodes_mask_and_six_values():
    r = GetSensorThresholdResp(bytes([0x00, 0x3F, 1, 2, 3, 4, 5, 6]))
    assert r.readable_mask == 0x3F
    assert (r.lnc, r.lc, r.lnr, r.unc, r.uc, r.unr) == (1, 2, 3, 4, 5, 6)


def test_sensor_threshold_registered():
    assert CMD_PAYLOADS[(0x04, 0x27)] == (GetSensorThresholdReq, GetSensorThresholdResp)


# === Get Sensor Reading Factors (0x04/0x23) — bit-packed §35.5 =============

def test_sensor_factors_req_packs_num_and_reading():
    # Old handler wire: [sensor_num, reading_byte(=0x00)].
    assert bytes(GetSensorReadingFactorsReq(sensor_num=9, reading_byte=0)) \
        == bytes([0x09, 0x00])


def test_sensor_factors_resp_roundtrips_and_unpacks_bitfields():
    # 7-byte factor payload (next + 6 packed bytes); prepend cc for the Packet.
    payload = bytes([0x10, 0x34, 0xC5, 0x78, 0x45, 0x9E, 0x2B])
    r = GetSensorReadingFactorsResp(bytes([0x00]) + payload)
    # Round-trip: the packed sub-byte fields re-encode to the exact wire bytes.
    assert bytes(r) == bytes([0x00]) + payload
    # M is split byte1(low 8) | byte2 high 2 bits; matches manual reconstruction.
    assert r.next_reading == 0x10
    assert (r.m_lo | (r.m_hi << 8)) == (payload[1] | ((payload[2] >> 6) & 0x03) << 8)
    assert r.tolerance == (payload[2] & 0x3F)
    assert (r.b_lo | (r.b_hi << 8)) == (payload[3] | ((payload[4] >> 6) & 0x03) << 8)
    assert (r.r_exp, r.b_exp) == ((payload[6] >> 4) & 0x0F, payload[6] & 0x0F)


def test_sensor_factors_registered():
    assert CMD_PAYLOADS[(0x04, 0x23)] == (GetSensorReadingFactorsReq,
                                          GetSensorReadingFactorsResp)


# === Get Device SDR (0x04/0x21) ============================================

def test_device_sdr_req_packs_reservation_record_offset_count():
    # Old handler wire: [rsv_lo, rsv_hi, rid_lo, rid_hi, offset, count].
    req = GetDeviceSDRReq(reservation=0x1234, record_id=0x00A0,
                          offset=0x00, bytes_to_read=0xFF)
    assert bytes(req) == bytes([0x34, 0x12, 0xA0, 0x00, 0x00, 0xFF])


def test_device_sdr_resp_decodes_next_id_and_record():
    r = GetDeviceSDRResp(bytes([0x00, 0xFF, 0xFF]) + b"\xde\xad")
    assert r.comp_code == 0x00 and r.next_record_id == 0xFFFF
    assert bytes(r.record_data) == b"\xde\xad"


def test_device_sdr_registered():
    assert CMD_PAYLOADS[(0x04, 0x21)] == (GetDeviceSDRReq, GetDeviceSDRResp)
