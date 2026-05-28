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
    blob, board_off, _ = _build_blob()
    b = parse_board_info(blob, board_off)
    assert b is not None
    assert b.manufacturer == "ACME"
    assert b.product == "WidgetBoard"
    assert b.serial == "SN12345"
    assert b.part_number == "PN-001"
    assert b.fru_file_id == "file-1"
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
    blob, _, product_off = _build_blob()
    p = parse_product_info(blob, product_off)
    assert p is not None
    assert p.manufacturer == "ACME Corp"
    assert p.name == "Frobnicator"
    assert p.part_model == "FB-9000"
    assert p.version == "v2"
    assert p.serial == "SN-PROD-7"
    assert p.asset_tag == "AT-001"
    assert p.fru_file_id == "p-fru-id"
    assert p.checksum_ok is True


def test_fru_epoch_is_1996_utc():
    assert FRU_EPOCH == datetime(1996, 1, 1, tzinfo=timezone.utc)
