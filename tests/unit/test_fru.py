"""Unit tests for FRU parsers (zipmi/fru.py)."""

from datetime import datetime, timezone

import pytest

from zipmi.fru import (
    FRU_EPOCH,
    parse_board_info,
    parse_common_header,
    parse_product_info,
    _decode_tl_string,
)


def _tl_string(s: str) -> bytes:
    """Encode as 8-bit ASCII TL string (type=0b11, length=len)."""
    raw = s.encode("ascii")
    return bytes([(0b11 << 6) | len(raw)]) + raw


def _finalize_area(body: bytearray) -> bytes:
    """Pad to multiple of 8, patch the length byte, then append zero-sum checksum.

    Order matters: length is part of the bytes the checksum covers, so we set
    it before computing.
    """
    while (len(body) + 1) % 8 != 0:
        body.append(0x00)
    total = len(body) + 1                # includes the upcoming checksum byte
    body[1] = total // 8                 # length field is ×8 multiples
    checksum = (-sum(body)) & 0xFF
    return bytes(body) + bytes([checksum])


def _build_board_info(mfg_min: int = 12345) -> bytes:
    body = bytearray()
    body.append(0x01)             # format_version
    body.append(0x00)             # length placeholder
    body.append(0x19)             # language code (English = 25)
    body += mfg_min.to_bytes(3, "little")
    body += _tl_string("ACME")
    body += _tl_string("WidgetBoard")
    body += _tl_string("SN12345")
    body += _tl_string("PN-001")
    body += _tl_string("file-1")
    body.append(0xC1)             # end-of-area
    return _finalize_area(body)


def _build_product_info() -> bytes:
    body = bytearray()
    body.append(0x01)
    body.append(0x00)
    body.append(0x19)
    body += _tl_string("ACME Corp")
    body += _tl_string("Frobnicator")
    body += _tl_string("FB-9000")
    body += _tl_string("v2")
    body += _tl_string("SN-PROD-7")
    body += _tl_string("AT-001")
    body += _tl_string("p-fru-id")
    body.append(0xC1)
    return _finalize_area(body)


def _build_blob() -> tuple[bytes, int, int]:
    """Build a full FRU blob: Common Header + Board Info + Product Info.

    Returns (blob, board_off, product_off).
    """
    board = _build_board_info()
    product = _build_product_info()
    board_off = 8                       # right after the 8-byte header
    product_off = board_off + len(board)
    # Common Header (8 bytes, offsets stored as ×8 multiples).
    hdr = bytearray(8)
    hdr[0] = 0x01                        # format_version
    hdr[1] = 0                           # internal_use offset
    hdr[2] = 0                           # chassis_info offset
    hdr[3] = board_off // 8              # board_info offset
    hdr[4] = product_off // 8            # product_info offset
    hdr[5] = 0                           # multirecord offset
    hdr[6] = 0                           # pad
    hdr[7] = (-sum(hdr[:7])) & 0xFF      # zero-sum checksum
    return bytes(hdr) + board + product, board_off, product_off


# -- TL-string decoder ---------------------------------------------------

def test_tl_string_8bit_ascii():
    data = _tl_string("hello")
    s, off = _decode_tl_string(data, 0)
    assert s == "hello"
    assert off == len(data)


def test_tl_string_end_marker():
    s, off = _decode_tl_string(b"\xC1", 0)
    assert s == "__END__"
    assert off == 1


def test_tl_string_empty():
    s, _ = _decode_tl_string(bytes([0xC0]), 0)   # type=11, length=0
    assert s == ""


def test_tl_string_bcd_plus():
    """BCD-plus: 0x12 = digits '2' then '1' (low nibble first)."""
    # type=01, length=2, data = [0x12, 0x34]  -> "2143"
    raw = bytes([(0b01 << 6) | 2, 0x12, 0x34])
    s, _ = _decode_tl_string(raw, 0)
    assert s == "2143"


# -- Common Header -------------------------------------------------------

def test_parse_common_header_valid():
    blob, board_off, product_off = _build_blob()
    h = parse_common_header(blob)
    assert h is not None
    assert h.format_version == 1
    assert h.board_off == board_off
    assert h.product_off == product_off
    assert h.checksum_ok is True


def test_parse_common_header_too_short():
    assert parse_common_header(b"\x01\x00") is None


def test_parse_common_header_bad_checksum():
    blob, _, _ = _build_blob()
    corrupted = bytearray(blob)
    corrupted[7] ^= 0xFF
    h = parse_common_header(bytes(corrupted))
    assert h is not None
    assert h.checksum_ok is False


# -- Board Info ----------------------------------------------------------

def test_parse_board_info_full():
    """Board Info, hand-laid bytes covering ALL five named fields incl. fru_file_id.

    Complements the shorter _HAND_BLOB test below (which stops at part_number).
    Byte layout of the AREA, per FRU v1.3 §11 (offsets absolute within area):
      [0]  0x01  format_version = 1
      [1]  0x04  length = 4 x 8 = 32 bytes total
      [2]  0x19  language code = 25 (English)
      [3]  0x00  \\
      [4]  0x00   > mfg_min = 0x000000 = 0 -> unspecified (mfg_date None)
      [5]  0x00  /
      [6]  0xC4  TL 8-bit ASCII len=4 -> manufacturer
      [7..10]   "ACME"                  = 0x41 0x43 0x4D 0x45
      [11] 0xC5  len=5 -> product
      [12..16]  "BOARD"                 = 0x42 0x4F 0x41 0x52 0x44
      [17] 0xC3  len=3 -> serial
      [18..20]  "S99"                   = 0x53 0x39 0x39
      [21] 0xC2  len=2 -> part_number
      [22..23]  "P7"                    = 0x50 0x37
      [24] 0xC3  len=3 -> fru_file_id
      [25..27]  "FID"                   = 0x46 0x49 0x44
      [28] 0xC1  end-of-area
      [29] 0x00  pad
      [30] 0x00  pad
      [31] cksum zero-sum checksum
    """
    area_no_cksum = bytes([
        0x01, 0x04, 0x19,
        0x00, 0x00, 0x00,               # mfg_min = 0 -> unspecified
        0xC4, 0x41, 0x43, 0x4D, 0x45,   # "ACME"
        0xC5, 0x42, 0x4F, 0x41, 0x52, 0x44,   # "BOARD"
        0xC3, 0x53, 0x39, 0x39,         # "S99"
        0xC2, 0x50, 0x37,               # "P7"
        0xC3, 0x46, 0x49, 0x44,         # "FID"
        0xC1, 0x00, 0x00,               # end-of-area + 2 pad
    ])  # 31 bytes; +1 checksum = 32 = 4 x 8
    area = area_no_cksum + bytes([(-sum(area_no_cksum)) & 0xFF])
    blob = b"\x00" * 8 + area
    b = parse_board_info(blob, 8)
    assert b is not None
    assert b.language_code == 25
    assert b.mfg_date is None
    assert b.manufacturer == "ACME"
    assert b.product == "BOARD"
    assert b.serial == "S99"
    assert b.part_number == "P7"
    assert b.fru_file_id == "FID"
    assert b.checksum_ok is True


def test_parse_board_info_mfg_date():
    blob, board_off, _ = _build_blob()
    b = parse_board_info(blob, board_off)
    assert b is not None
    # mfg_min=12345 -> 1996-01-01 UTC + 12345 minutes = 1996-01-09T13:45 UTC
    expected = datetime(1996, 1, 9, 13, 45, tzinfo=timezone.utc)
    assert b.mfg_date == expected


def test_parse_board_info_unspecified_mfg_date():
    """mfg_min = 0 or 0xFFFFFF means 'unspecified'."""
    blob = b"\x00" * 8 + _build_board_info(mfg_min=0)
    b = parse_board_info(blob, 8)
    assert b is not None
    assert b.mfg_date is None


def test_parse_board_info_zero_offset_returns_none():
    blob, _, _ = _build_blob()
    assert parse_board_info(blob, 0) is None


# -- Product Info --------------------------------------------------------

def test_parse_product_info_full():
    """Product Info, hand-laid bytes covering ALL seven named fields.

    Unlike Board Info, Product Info has NO mfg-date field: the first string
    starts at area offset 3 (right after the language byte), not 6. Hand bytes
    exercise that distinct start offset, which a shared builder round-trip hides.
    Byte layout of the AREA, per FRU v1.3 §12 (offsets absolute within area):
      [0]  0x01  format_version = 1
      [1]  0x04  length = 4 x 8 = 32 bytes total
      [2]  0x00  language code = 0 (English)
      [3]  0xC3  TL 8-bit ASCII len=3 -> manufacturer
      [4..6]    "DEL"                   = 0x44 0x45 0x4C
      [7]  0xC4  len=4 -> name (product name)
      [8..11]   "R640"                  = 0x52 0x36 0x34 0x30
      [12] 0xC2  len=2 -> part_model
      [13..14]  "PM"                    = 0x50 0x4D
      [15] 0xC2  len=2 -> version
      [16..17]  "v1"                    = 0x76 0x31
      [18] 0xC3  len=3 -> serial
      [19..21]  "SN1"                   = 0x53 0x4E 0x31
      [22] 0xC2  len=2 -> asset_tag
      [23..24]  "AT"                    = 0x41 0x54
      [25] 0xC2  len=2 -> fru_file_id
      [26..27]  "FF"                    = 0x46 0x46
      [28] 0xC1  end-of-area
      [29] 0x00  pad
      [30] 0x00  pad
      [31] cksum zero-sum checksum
    """
    area_no_cksum = bytes([
        0x01, 0x04, 0x00,
        0xC3, 0x44, 0x45, 0x4C,         # "DEL"
        0xC4, 0x52, 0x36, 0x34, 0x30,   # "R640"
        0xC2, 0x50, 0x4D,               # "PM"
        0xC2, 0x76, 0x31,               # "v1"
        0xC3, 0x53, 0x4E, 0x31,         # "SN1"
        0xC2, 0x41, 0x54,               # "AT"
        0xC2, 0x46, 0x46,               # "FF"
        0xC1, 0x00, 0x00,               # end-of-area + 2 pad
    ])  # 31 bytes; +1 checksum = 32 = 4 x 8
    area = area_no_cksum + bytes([(-sum(area_no_cksum)) & 0xFF])
    blob = b"\x00" * 8 + area
    p = parse_product_info(blob, 8)
    assert p is not None
    assert p.language_code == 0
    assert p.manufacturer == "DEL"
    assert p.name == "R640"
    assert p.part_model == "PM"
    assert p.version == "v1"
    assert p.serial == "SN1"
    assert p.asset_tag == "AT"
    assert p.fru_file_id == "FF"
    assert p.checksum_ok is True


def test_fru_epoch_is_1996_utc():
    assert FRU_EPOCH == datetime(1996, 1, 1, tzinfo=timezone.utc)


# -- Independent hand-laid-out bytes (no _build_* helpers) ---------------
#
# These decode a byte literal constructed by hand from the FRU v1.3 spec, so
# an offset bug in the parser would produce wrong strings/dates rather than a
# self-consistent round-trip. Expected values come from the layout below, not
# from running the parser.

# Board Info area, hand-built. Absolute offsets within the AREA:
#   [0]  0x01  format_version = 1
#   [1]  0x03  length = 3 x 8 = 24 bytes total (set to match padded length)
#   [2]  0x00  language code = 0 (English)
#   [3]  0xA0  \
#   [4]  0x05   > mfg_min = 0x0005A0 = 1440 (LE) = exactly 1 day of minutes
#   [5]  0x00  /
#   [6]  0xC3  TL: type=0b11 (8-bit ASCII), len=3  -> manufacturer
#   [7..9]    "DEL"                                 = 0x44 0x45 0x4C
#   [10] 0xC4  TL: len=4                            -> product
#   [11..14]  "R640"                                = 0x52 0x36 0x34 0x30
#   [15] 0xC5  TL: len=5                            -> serial
#   [16..20]  "CN123"                               = 0x43 0x4E 0x31 0x32 0x33
#   [21] 0xC0  TL: len=0  -> part_number = ""
#   [22] 0xC1  end-of-area marker
#   [23] 0x00  padding to reach 24 bytes (still needs checksum -> see below)
# 23 bytes so far; area len must be a multiple of 8. We target 24 bytes:
# bytes [0..22] as above (23 bytes) + 1 checksum byte = 24 = 3 x 8. So no
# extra 0x00 pad is needed; drop [23] and put the checksum there instead.
_BOARD_AREA_NO_CKSUM = bytes([
    0x01, 0x03, 0x00,               # fmt, len(x8)=24, lang
    0xA0, 0x05, 0x00,               # mfg_min = 1440 LE
    0xC3, 0x44, 0x45, 0x4C,         # "DEL"
    0xC4, 0x52, 0x36, 0x34, 0x30,   # "R640"
    0xC5, 0x43, 0x4E, 0x31, 0x32, 0x33,   # "CN123"
    0xC0,                           # part_number = ""
    0xC1,                           # end-of-area
])  # 23 bytes; +1 zero-sum checksum below = 24 total
_BOARD_AREA = _BOARD_AREA_NO_CKSUM + bytes([(-sum(_BOARD_AREA_NO_CKSUM)) & 0xFF])

# Common Header, hand-built. board_off is 8 (right after header), stored x8.
#   [3] = 8 // 8 = 1  -> board_info offset field
_HEADER_NO_CKSUM = bytes([0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
_HEADER = _HEADER_NO_CKSUM + bytes([(-sum(_HEADER_NO_CKSUM)) & 0xFF])

_HAND_BLOB = _HEADER + _BOARD_AREA


def test_parse_common_header_hand_bytes():
    """Header field [3]=1 must decode to board_off = 1*8 = 8."""
    h = parse_common_header(_HAND_BLOB)
    assert h is not None
    assert h.format_version == 1
    assert h.board_off == 8
    assert h.product_off == 0
    assert h.checksum_ok is True


def test_parse_board_info_hand_bytes_strings():
    """Independent bytes: manufacturer/product/serial from a hand layout."""
    b = parse_board_info(_HAND_BLOB, 8)
    assert b is not None
    assert b.language_code == 0
    assert b.manufacturer == "DEL"
    assert b.product == "R640"
    assert b.serial == "CN123"
    assert b.part_number == ""
    assert b.checksum_ok is True


def test_parse_board_info_hand_bytes_mfg_date():
    """mfg_min = 1440 (0x0005A0 LE) = exactly one day -> 1996-01-02 00:00 UTC."""
    b = parse_board_info(_HAND_BLOB, 8)
    assert b is not None
    assert b.mfg_date == datetime(1996, 1, 2, 0, 0, tzinfo=timezone.utc)
