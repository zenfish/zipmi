"""Unit coverage for SDR + SEL decoders backing `zipmi sel elist`.

Pure-parser tests — build SDR/SEL byte records by hand, no BMC needed.
"""

from datetime import datetime, timezone

import pytest

from zipmi.sel_decode import (
    GENERIC_EVENT,
    SENSOR_SPECIFIC_EVENT,
    SENSOR_TYPE,
    SensorInfo,
    decode_sdr_record,
    format_sel_record_extended,
)


# -- ID string decode ------------------------------------------------------

def _build_sdr_type1(sensor_num: int, sensor_type: int, name: str) -> bytes:
    """Construct a synthetic 48-byte SDR Type 1 (Full Sensor) record."""
    body = bytearray(48)
    # header
    body[0:2] = (1).to_bytes(2, "little")     # record_id
    body[2] = 0x51                            # sdr_version
    body[3] = 0x01                            # record_type = Full Sensor
    body[4] = 48 - 5                          # record_length
    body[7] = sensor_num
    body[12] = sensor_type
    # id_string at offset 47: type=11 (8-bit ASCII), length=len(name)
    name_bytes = name.encode("ascii")
    body[47] = (0b11 << 6) | (len(name_bytes) & 0x1F)
    return bytes(body) + name_bytes


def _build_sdr_type2(sensor_num: int, sensor_type: int, name: str) -> bytes:
    """Construct a synthetic SDR Type 2 (Compact) record."""
    body = bytearray(32)
    body[0:2] = (2).to_bytes(2, "little")
    body[2] = 0x51
    body[3] = 0x02
    body[4] = 32 - 5
    body[7] = sensor_num
    body[12] = sensor_type
    name_bytes = name.encode("ascii")
    body[31] = (0b11 << 6) | (len(name_bytes) & 0x1F)
    return bytes(body) + name_bytes


def test_decode_sdr_type1_8bit_ascii():
    rec = _build_sdr_type1(sensor_num=0x51, sensor_type=0x08, name="PS Redundancy")
    info = decode_sdr_record(rec)
    assert info == SensorInfo(0x51, 0x08, "PS Redundancy")


def test_decode_sdr_type2_8bit_ascii():
    rec = _build_sdr_type2(sensor_num=0x10, sensor_type=0x01, name="CPU1 Temp")
    info = decode_sdr_record(rec)
    assert info == SensorInfo(0x10, 0x01, "CPU1 Temp")


def test_decode_sdr_unknown_record_type_returns_none():
    rec = b"\x00\x00\x51\x0B" + b"\x00" * 40   # type 0x0B (Entity Assoc)
    assert decode_sdr_record(rec) is None


def test_decode_sdr_short_record_returns_none():
    assert decode_sdr_record(b"\x00\x00\x51\x01") is None


def test_decode_sdr_name_strips_null_padding():
    rec = _build_sdr_type2(0x05, 0x04, "FAN1")
    # Append trailing NULs (BMCs sometimes pad)
    rec = rec + b"\x00\x00\x00"
    info = decode_sdr_record(rec)
    assert info is not None
    assert info.name == "FAN1"


def test_decode_sdr_6bit_packed_ascii():
    """Cover 6-bit packed ASCII path — rare but spec-required.

    Pack 'ABCD': 6-bit base is 0x20, so 'A'(0x41)..'D'(0x44) → offsets 0x21..0x24.
    3 bytes encode 4 chars.
    """
    chars = [ord(c) - 0x20 for c in "ABCD"]
    b0 = (chars[0] & 0x3F) | ((chars[1] & 0x03) << 6)
    b1 = ((chars[1] >> 2) & 0x0F) | ((chars[2] & 0x0F) << 4)
    b2 = ((chars[2] >> 4) & 0x03) | ((chars[3] & 0x3F) << 2)
    packed = bytes([b0, b1, b2])
    body = bytearray(32)
    body[3] = 0x02
    body[7] = 0x99
    body[12] = 0x01
    body[31] = (0b10 << 6) | len(packed)  # 6-bit packed
    rec = bytes(body) + packed
    info = decode_sdr_record(rec)
    assert info is not None
    assert info.name == "ABCD"


# -- SEL formatting -------------------------------------------------------

def _build_sel_record(
    record_id: int = 1,
    rec_type: int = 0x02,
    ts: int = 0,
    sensor_type: int = 0x08,
    sensor_num: int = 0x51,
    ev_byte: int = 0x6F,
    ev_data1: int = 0x01,
    ev_data2: int = 0x00,
    ev_data3: int = 0x00,
) -> bytes:
    """Synthesize a 16-byte SEL record per IPMI 2.0 §32.1."""
    out = bytearray(16)
    out[0:2] = record_id.to_bytes(2, "little")
    out[2] = rec_type
    out[3:7] = ts.to_bytes(4, "little")
    out[7:9] = (0x0020).to_bytes(2, "little")    # gen_id
    out[9] = 0x04                                # ev_msg_rev
    out[10] = sensor_type
    out[11] = sensor_num
    out[12] = ev_byte
    out[13] = ev_data1
    out[14] = ev_data2
    out[15] = ev_data3
    return bytes(out)


def test_format_sel_with_sdr_name_and_sensor_specific_event():
    """Power Supply Failure detected, sensor named via SDR map.

    Date check is TZ-agnostic (ts may land on prior/next day in non-UTC zones).
    """
    import re
    ts = int(datetime(2024, 4, 12, 10, 30, 45, tzinfo=timezone.utc).timestamp())
    rec = _build_sel_record(
        record_id=1, ts=ts,
        sensor_type=0x08, sensor_num=0x51,
        ev_byte=0x6F,
        ev_data1=0x01,
    )
    sdr_map = {0x51: SensorInfo(0x51, 0x08, "PS Redundancy")}
    line = format_sel_record_extended(rec, sdr_map)
    assert re.search(r"\d{2}/\d{2}/2024", line)
    assert re.search(r"\d{2}:\d{2}:\d{2}", line)
    assert "Power Supply PS Redundancy" in line
    assert "Power Supply Failure detected" in line
    assert line.endswith("Asserted")


def test_format_sel_falls_back_to_hex_sensor_when_not_in_sdr():
    ts = int(datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
    rec = _build_sel_record(
        ts=ts, sensor_type=0x04, sensor_num=0xAA,
        ev_byte=0x6F, ev_data1=0x00,
    )
    line = format_sel_record_extended(rec, {})  # empty SDR
    assert "#0xaa" in line
    assert "Fan" in line


def test_format_sel_deassertion_bit_sets_direction():
    rec = _build_sel_record(
        ts=0x40000000,            # late-2004 -> well past pre-init cutoff
        sensor_type=0x07, sensor_num=0x01,
        ev_byte=0x6F | 0x80,      # bit 7 = deassert
        ev_data1=0x00,            # IERR
    )
    line = format_sel_record_extended(rec, {})
    assert line.endswith("Deasserted")


def test_format_sel_pre_init_timestamp():
    rec = _build_sel_record(ts=0x01234567)   # < 0x20000000
    line = format_sel_record_extended(rec, {})
    assert "Pre-Init" in line
    assert "Time-stamp" in line


def test_format_sel_generic_threshold_event():
    """Event type 0x01 (threshold), offset 0x09 = Upper Critical going high."""
    rec = _build_sel_record(
        ts=0x40000000,
        sensor_type=0x01, sensor_num=0x20,
        ev_byte=0x01,                 # threshold
        ev_data1=0x09,                # offset 9
    )
    line = format_sel_record_extended(rec, {})
    assert "Upper Critical going high" in line


def test_format_sel_unknown_event_uses_hex():
    rec = _build_sel_record(
        ts=0x40000000,
        sensor_type=0xFF, sensor_num=0x01,
        ev_byte=0x6F, ev_data1=0x0E,     # offset not in table
    )
    line = format_sel_record_extended(rec, {})
    assert "sensor-specific offset 0x0e" in line


def test_format_sel_oem_record_type():
    rec = _build_sel_record(rec_type=0xC0, ts=0x40000000)
    line = format_sel_record_extended(rec, {})
    assert "OEM record type 0xc0" in line


def test_format_sel_record_id_is_hex():
    """ipmitool prints record_id in hex (matches its `sel elist` output)."""
    rec = _build_sel_record(record_id=0x1A, ts=0x40000000)
    line = format_sel_record_extended(rec, {})
    assert line.lstrip().startswith("1a |")


def test_format_sel_cable_interconnect_config_error():
    """Sensor type 0x1B / offset 0x01 = 'Config Error' (Dell SAS cable case)."""
    rec = _build_sel_record(
        ts=0x40000000,
        sensor_type=0x1B, sensor_num=0x6F,
        ev_byte=0x6F, ev_data1=0x01,
    )
    line = format_sel_record_extended(rec, {})
    assert "Config Error" in line


def test_format_sel_short_record():
    line = format_sel_record_extended(b"\x00" * 5, {})
    assert "short SEL record" in line


# -- lookup table sanity ---------------------------------------------------

def test_sensor_type_table_covers_common():
    for code in (0x01, 0x04, 0x07, 0x08, 0x0C, 0x14):
        assert code in SENSOR_TYPE


def test_generic_event_table_threshold_complete():
    """Threshold event type (0x01) needs offsets 0x00..0x0B per IPMI 2.0."""
    for off in range(0x0C):
        assert (0x01, off) in GENERIC_EVENT


def test_sensor_specific_power_supply_events_present():
    for off in range(7):
        assert (0x08, off) in SENSOR_SPECIFIC_EVENT
