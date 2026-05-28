"""FRU (Field Replaceable Unit) inventory parsers.

Per Platform Management FRU Information Storage Definition v1.3. Pure
parsers — caller does the I/O via Get FRU Inventory Area Info (0x0A/0x10)
and Read FRU Data (0x0A/0x11).

Areas covered: Common Header, Board Info, Product Info. Chassis Info,
Internal Use, and MultiRecord areas are read but only summarized
(field strings are skipped — usually inhabited by Intel multirecord OEM
records which need per-vendor decode).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


# FRU mfg-date epoch: 1996-01-01 00:00 UTC, value in minutes (24-bit LE).
FRU_EPOCH = datetime(1996, 1, 1, tzinfo=timezone.utc)


def _decode_tl_string(data: bytes, off: int) -> tuple[str, int]:
    """Decode one type/length-coded FRU string. Returns (value, new_offset).

    type-length byte:
      [7:6] type — 11=8-bit ASCII (most common), 10=6-bit packed,
                   01=BCD plus, 00=binary/Unicode
      [5:0] length in bytes (0 = empty string; 0xC1 = end-of-area marker)
    """
    if off >= len(data):
        return "", off
    tl = data[off]
    if tl == 0xC1:
        return "__END__", off + 1
    code = (tl >> 6) & 0x03
    length = tl & 0x3F
    payload = data[off + 1: off + 1 + length]
    if code == 0b11:
        s = payload.decode("latin-1", errors="replace").rstrip("\x00").rstrip()
    elif code == 0b10:
        out: list[str] = []
        for i in range(0, len(payload), 3):
            chunk = payload[i:i + 3]
            if len(chunk) < 3:
                chunk = chunk + b"\x00" * (3 - len(chunk))
            c0 = chunk[0] & 0x3F
            c1 = ((chunk[0] >> 6) | (chunk[1] << 2)) & 0x3F
            c2 = ((chunk[1] >> 4) | (chunk[2] << 4)) & 0x3F
            c3 = (chunk[2] >> 2) & 0x3F
            out.extend(chr(0x20 + x) for x in (c0, c1, c2, c3))
        s = "".join(out).rstrip()
    elif code == 0b01:
        bcd = "0123456789 -.:,_"
        digits = []
        for b in payload:
            digits.append(bcd[b & 0x0F])
            digits.append(bcd[(b >> 4) & 0x0F])
        s = "".join(digits).strip()
    else:
        s = payload.hex()
    return s, off + 1 + length


def _verify_checksum(area: bytes) -> bool:
    """FRU areas have a zero-sum byte at the end: (sum % 256) == 0."""
    return (sum(area) & 0xFF) == 0


@dataclass
class CommonHeader:
    format_version: int
    internal_off: int     # absolute byte offset (already x8'd)
    chassis_off: int
    board_off: int
    product_off: int
    multirec_off: int
    checksum_ok: bool


def parse_common_header(data: bytes) -> CommonHeader | None:
    """Parse the 8-byte FRU Common Header at offset 0."""
    if len(data) < 8:
        return None
    return CommonHeader(
        format_version=data[0] & 0x0F,
        internal_off=data[1] * 8,
        chassis_off=data[2] * 8,
        board_off=data[3] * 8,
        product_off=data[4] * 8,
        multirec_off=data[5] * 8,
        checksum_ok=_verify_checksum(data[:8]),
    )


@dataclass
class BoardInfo:
    language_code: int
    mfg_date: datetime | None
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    part_number: str = ""
    fru_file_id: str = ""
    custom_fields: list[str] = field(default_factory=list)
    checksum_ok: bool = False


def parse_board_info(data: bytes, area_off: int) -> BoardInfo | None:
    """Parse Board Info area at the given absolute offset."""
    if area_off == 0 or area_off + 2 > len(data):
        return None
    length = data[area_off + 1] * 8
    if area_off + length > len(data):
        return None
    area = data[area_off: area_off + length]
    if len(area) < 6:
        return None
    lang = area[2]
    mfg_min = area[3] | (area[4] << 8) | (area[5] << 16)
    mfg_dt: datetime | None
    if mfg_min == 0 or mfg_min == 0xFFFFFF:
        mfg_dt = None
    else:
        mfg_dt = FRU_EPOCH + timedelta(minutes=mfg_min)
    off = 6
    fields = []
    while off < len(area):
        s, off = _decode_tl_string(area, off)
        if s == "__END__":
            break
        fields.append(s)
    # Padding strings (.fields[0..4] = mfg, product, serial, part_no, fru_file_id).
    while len(fields) < 5:
        fields.append("")
    return BoardInfo(
        language_code=lang,
        mfg_date=mfg_dt,
        manufacturer=fields[0],
        product=fields[1],
        serial=fields[2],
        part_number=fields[3],
        fru_file_id=fields[4],
        custom_fields=fields[5:],
        checksum_ok=_verify_checksum(area),
    )


@dataclass
class ProductInfo:
    language_code: int
    manufacturer: str = ""
    name: str = ""
    part_model: str = ""
    version: str = ""
    serial: str = ""
    asset_tag: str = ""
    fru_file_id: str = ""
    custom_fields: list[str] = field(default_factory=list)
    checksum_ok: bool = False


def parse_product_info(data: bytes, area_off: int) -> ProductInfo | None:
    if area_off == 0 or area_off + 2 > len(data):
        return None
    length = data[area_off + 1] * 8
    if area_off + length > len(data):
        return None
    area = data[area_off: area_off + length]
    if len(area) < 3:
        return None
    lang = area[2]
    off = 3
    fields = []
    while off < len(area):
        s, off = _decode_tl_string(area, off)
        if s == "__END__":
            break
        fields.append(s)
    while len(fields) < 7:
        fields.append("")
    return ProductInfo(
        language_code=lang,
        manufacturer=fields[0],
        name=fields[1],
        part_model=fields[2],
        version=fields[3],
        serial=fields[4],
        asset_tag=fields[5],
        fru_file_id=fields[6],
        custom_fields=fields[7:],
        checksum_ok=_verify_checksum(area),
    )
