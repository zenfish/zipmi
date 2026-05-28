"""Full SDR Type 1 decode + linear conversion for `zipmi sensor get`.

Pure parsers. Caller fetches the record bytes via Read FRU Data /
Get SDR; this module turns raw bytes into a SensorMeta and applies
the IPMI 2.0 §36.3 linear conversion to a cooked value with units.

We support analog Type 1 (Full Sensor) records with linearization
codes 0 (linear), 1 (ln), 2 (log10), 7 (1/x), and 11 (sqrt). Discrete
Type 2 records and analog data format = "non-analog" return the raw
byte without a unit.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


# IPMI 2.0 Table 43-15: Sensor Unit Type Codes (common ones).
SENSOR_UNIT: dict[int, str] = {
    0: "unspecified",
    1: "degrees C",
    2: "degrees F",
    3: "degrees K",
    4: "Volts",
    5: "Amps",
    6: "Watts",
    7: "Joules",
    8: "Coulombs",
    9: "VA",
    10: "Nits",
    11: "lumen",
    12: "lux",
    13: "Candela",
    14: "kPa",
    15: "PSI",
    16: "Newton",
    17: "CFM",
    18: "RPM",
    19: "Hz",
    20: "microsecond",
    21: "millisecond",
    22: "second",
    23: "minute",
    24: "hour",
    25: "day",
    26: "week",
    27: "mil",
    28: "inches",
    29: "feet",
    30: "cubic inches",
    31: "cubic feet",
    32: "mm",
    33: "cm",
    34: "m",
    35: "cubic cm",
    36: "cubic m",
    37: "liters",
    38: "fluid ounce",
    39: "radians",
    40: "steradians",
    41: "revolutions",
    42: "cycles",
    43: "gravities",
    44: "ounce",
    45: "pound",
    46: "ft-lb",
    47: "oz-in",
    48: "gauss",
    49: "gilberts",
    50: "henry",
    51: "millihenry",
    52: "farad",
    53: "microfarad",
    54: "ohms",
    55: "siemens",
    56: "mole",
    57: "becquerel",
    58: "PPM",
    60: "decibels",
    61: "DbA",
    62: "DbC",
    63: "gray",
    64: "sievert",
    65: "color temp deg K",
    66: "bit",
    67: "kilobit",
    68: "megabit",
    69: "gigabit",
    70: "byte",
    71: "kilobyte",
    72: "megabyte",
    73: "gigabyte",
    74: "word",
    75: "dword",
    76: "qword",
    77: "line",
    78: "hit",
    79: "miss",
    80: "retry",
    81: "reset",
    82: "overrun / overflow",
    83: "underrun",
    84: "collision",
    85: "packets",
    86: "messages",
    87: "characters",
    88: "error",
    89: "correctable error",
    90: "uncorrectable error",
    91: "fatal error",
    92: "grams",
}


@dataclass
class SensorMeta:
    sensor_number: int
    sensor_type: int
    name: str
    analog_format: int      # 0=unsigned, 1=1's-comp, 2=2's-comp, 3=non-analog
    unit_code: int
    linearization: int      # 0=linear, 1=ln, 2=log10, ..., 0x70=non-linear
    m: int                  # 10-bit signed
    b: int                  # 10-bit signed
    r_exp: int              # 4-bit signed
    b_exp: int              # 4-bit signed


def _twos_complement(value: int, bits: int) -> int:
    """Sign-extend an n-bit two's-complement value."""
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def parse_full_sdr(rec: bytes) -> SensorMeta | None:
    """Parse SDR Type 1 (Full Sensor Record) into a SensorMeta.

    Returns None for non-Type-1 records or malformed input.
    """
    if len(rec) < 48 or rec[3] != 0x01:
        return None
    sensor_num = rec[7]
    sensor_type = rec[12]
    units1 = rec[20]
    analog_format = (units1 >> 6) & 0x03
    unit_code = rec[21]
    linearization = rec[23] & 0x7F
    # M is 10-bit signed: low 8 in byte 24, high 2 in byte 25 bits 7:6.
    m_low = rec[24]
    m_high = (rec[25] >> 6) & 0x03
    m_raw = m_low | (m_high << 8)
    m = _twos_complement(m_raw, 10)
    # B is 10-bit signed: low in byte 26, high in byte 27 bits 7:6.
    b_low = rec[26]
    b_high = (rec[27] >> 6) & 0x03
    b_raw = b_low | (b_high << 8)
    b = _twos_complement(b_raw, 10)
    # R exponent: byte 29 bits 7:4 (signed 4-bit). B exponent: bits 3:0.
    r_exp = _twos_complement((rec[29] >> 4) & 0x0F, 4)
    b_exp = _twos_complement(rec[29] & 0x0F, 4)
    # ID string at byte 47 type/length code, body at byte 48+.
    if len(rec) > 48:
        tl = rec[47]
        length = tl & 0x1F
        name = rec[48: 48 + length].decode("latin-1", errors="replace") \
                                    .rstrip("\x00").strip()
    else:
        name = ""
    return SensorMeta(
        sensor_number=sensor_num,
        sensor_type=sensor_type,
        name=name,
        analog_format=analog_format,
        unit_code=unit_code,
        linearization=linearization,
        m=m, b=b, r_exp=r_exp, b_exp=b_exp,
    )


def cook_reading(meta: SensorMeta, raw: int) -> float | None:
    """Apply IPMI 2.0 §36.3 linear conversion:
        y = L( (M * x + B * 10^Bexp) * 10^Rexp )

    Returns None for non-analog sensors or unsupported linearization.
    """
    if meta.analog_format == 3:           # non-analog
        return None
    # Sign-extend raw value per analog data format.
    if meta.analog_format == 1:           # 1's complement
        x = raw if raw < 0x80 else -((~raw) & 0x7F)
    elif meta.analog_format == 2:         # 2's complement
        x = _twos_complement(raw, 8)
    else:                                 # unsigned
        x = raw
    inner = (meta.m * x + meta.b * (10 ** meta.b_exp)) * (10 ** meta.r_exp)
    L = meta.linearization
    if L == 0x00:
        return float(inner)
    if L == 0x01:
        return math.log(inner) if inner > 0 else None
    if L == 0x02:
        return math.log10(inner) if inner > 0 else None
    if L == 0x03:
        return math.log2(inner) if inner > 0 else None
    if L == 0x04:
        return math.exp(inner)
    if L == 0x05:
        return 10 ** inner
    if L == 0x06:
        return 2 ** inner
    if L == 0x07:
        return (1.0 / inner) if inner != 0 else None
    if L == 0x08:
        return inner * inner
    if L == 0x09:
        return inner ** 3
    if L == 0x0A:
        return math.sqrt(inner) if inner >= 0 else None
    if L == 0x0B:
        return math.copysign(abs(inner) ** (1 / 3.0), inner)
    return None


def unit_name(code: int) -> str:
    return SENSOR_UNIT.get(code, f"unit-0x{code:02x}")
