"""Unit tests for SDR Type-1 decode + linear conversion (zipmi/sdr_full.py)."""

import math

import pytest

from zipmi.sdr_full import (
    SENSOR_UNIT,
    SensorMeta,
    _twos_complement,
    cook_reading,
    parse_full_sdr,
    unit_name,
)


# -- helpers -------------------------------------------------------------

def _build_full_sdr(
    sensor_num: int = 0x0E,
    sensor_type: int = 0x01,
    name: str = "TestTemp",
    analog_format: int = 0,
    unit_code: int = 1,
    linearization: int = 0,
    m: int = 1,
    b: int = -128,
    r_exp: int = 0,
    b_exp: int = 0,
) -> bytes:
    """Synthesize a Type-1 SDR sufficient for parse_full_sdr."""
    rec = bytearray(48 + 32)         # body to byte 47, then ID string
    rec[3] = 0x01
    rec[4] = (len(rec) - 5)
    rec[7] = sensor_num
    rec[12] = sensor_type
    rec[20] = (analog_format & 0x03) << 6
    rec[21] = unit_code
    rec[23] = linearization & 0x7F
    # M: 10-bit signed, low 8 in byte 24 + high 2 in byte 25 bits 7:6
    m_raw = m & 0x3FF
    rec[24] = m_raw & 0xFF
    rec[25] = ((m_raw >> 8) & 0x03) << 6
    # B
    b_raw = b & 0x3FF
    rec[26] = b_raw & 0xFF
    rec[27] = ((b_raw >> 8) & 0x03) << 6
    # exponents in byte 29
    r4 = r_exp & 0x0F
    b4 = b_exp & 0x0F
    rec[29] = (r4 << 4) | b4
    # ID string at byte 47 (type=11=8-bit ASCII, length=len)
    name_bytes = name.encode("ascii")
    rec[47] = (0b11 << 6) | (len(name_bytes) & 0x1F)
    return bytes(rec[:48]) + name_bytes


# -- helpers / two's-complement -----------------------------------------

@pytest.mark.parametrize("value,bits,expected", [
    (0, 4, 0),
    (7, 4, 7),
    (0xF, 4, -1),
    (0x8, 4, -8),
    (0x3FF, 10, -1),
    (0x200, 10, -512),
    (0x1FF, 10, 511),
])
def test_twos_complement(value, bits, expected):
    assert _twos_complement(value, bits) == expected


# -- parse_full_sdr -----------------------------------------------------

def test_parse_full_sdr_extracts_basic_fields():
    rec = _build_full_sdr(name="Ambient Temp")
    meta = parse_full_sdr(rec)
    assert meta is not None
    assert meta.name == "Ambient Temp"
    assert meta.sensor_number == 0x0E
    assert meta.sensor_type == 0x01
    assert meta.unit_code == 1
    assert meta.analog_format == 0


def test_parse_full_sdr_signed_m_and_b():
    """Verify M=-1 and B=-256 sign-extend correctly through the 10-bit field."""
    rec = _build_full_sdr(m=-1, b=-256, r_exp=-2, b_exp=3)
    meta = parse_full_sdr(rec)
    assert meta is not None
    assert meta.m == -1
    assert meta.b == -256
    assert meta.r_exp == -2
    assert meta.b_exp == 3


def test_parse_full_sdr_returns_none_for_non_type1():
    rec = bytearray(_build_full_sdr())
    rec[3] = 0x02       # Type 2 (Compact)
    assert parse_full_sdr(bytes(rec)) is None


def test_parse_full_sdr_returns_none_for_short_record():
    assert parse_full_sdr(b"\x00" * 10) is None


# -- cook_reading -------------------------------------------------------

def test_cook_reading_linear_passthrough():
    """M=1, B=0, exponents=0 -> cooked value equals raw."""
    meta = SensorMeta(0, 0, "", 0, 1, 0, m=1, b=0, r_exp=0, b_exp=0)
    assert cook_reading(meta, 42) == 42.0


def test_cook_reading_ambient_temp_idrac6():
    """Real iDRAC6 'Ambient Temp' SDR: M=1, B=-128, both exps=0.
    Raw 0x96 (150) -> 22°C, matches live BMC reading."""
    meta = SensorMeta(0x0E, 0x01, "Ambient Temp",
                      analog_format=0, unit_code=1, linearization=0,
                      m=1, b=-128, r_exp=0, b_exp=0)
    assert cook_reading(meta, 0x96) == 22.0


def test_cook_reading_scaled_by_r_exp():
    """M=2, R_exp=-1 -> y = 2*x*10^-1. Raw=10 -> 2.0."""
    meta = SensorMeta(0, 0, "", 0, 4, 0, m=2, b=0, r_exp=-1, b_exp=0)
    assert cook_reading(meta, 10) == pytest.approx(2.0)


def test_cook_reading_twos_complement_raw():
    """analog_format=2 (2's complement) sign-extends raw byte."""
    meta = SensorMeta(0, 0, "", 2, 1, 0, m=1, b=0, r_exp=0, b_exp=0)
    assert cook_reading(meta, 0xFF) == -1.0       # 0xFF as signed = -1
    assert cook_reading(meta, 0x80) == -128.0


def test_cook_reading_non_analog_returns_none():
    meta = SensorMeta(0, 0, "", 3, 0, 0, m=0, b=0, r_exp=0, b_exp=0)
    assert cook_reading(meta, 42) is None


def test_cook_reading_log10_linearization():
    """L=2 (log10). inner=100 -> log10(100)=2.0."""
    meta = SensorMeta(0, 0, "", 0, 0, 2, m=1, b=99, r_exp=0, b_exp=0)
    assert cook_reading(meta, 1) == pytest.approx(2.0)


def test_cook_reading_reciprocal_linearization():
    """L=7 (1/x). inner=4 -> 0.25."""
    meta = SensorMeta(0, 0, "", 0, 0, 7, m=1, b=3, r_exp=0, b_exp=0)
    assert cook_reading(meta, 1) == pytest.approx(0.25)


def test_cook_reading_sqrt_linearization_negative_input():
    """L=10 (sqrt) with negative inner returns None (no real result)."""
    meta = SensorMeta(0, 0, "", 0, 0, 10, m=-1, b=0, r_exp=0, b_exp=0)
    assert cook_reading(meta, 5) is None


def test_cook_reading_unknown_linearization_returns_none():
    meta = SensorMeta(0, 0, "", 0, 0, 0x70, m=1, b=0, r_exp=0, b_exp=0)
    assert cook_reading(meta, 5) is None


# -- units --------------------------------------------------------------

def test_unit_name_known():
    assert unit_name(1) == "degrees C"
    assert unit_name(18) == "RPM"
    assert unit_name(4) == "Volts"


def test_unit_name_unknown_falls_back_to_hex():
    assert unit_name(0xAA) == "unit-0xaa"


def test_unit_table_has_common_entries():
    for code in (1, 4, 5, 6, 18, 19, 22):
        assert code in SENSOR_UNIT
