"""Unit coverage for the `ipmi` standard-command catalogue source."""
from zipmi.cli.oem_cmds import _vendor_listing, _vendor_stats
from zipmi.scapy_ipmi.cmd_names import IPMI_CMD_NAMES


def test_ipmi_listing_shape_and_size():
    listing = _vendor_listing("ipmi")
    assert listing, "ipmi listing must be non-empty"
    assert len(listing) == len(IPMI_CMD_NAMES)
    # Get Device ID is App NetFn 0x06 / cmd 0x01.
    assert (0x06, 0x01) in listing
    row = listing[(0x06, 0x01)]
    for k in ("name", "priv", "desc", "live", "missing",
              "prefix", "args", "src"):
        assert k in row, f"row missing key {k!r}"
    # _normalize_listing camelizes display names (same as OEM
    # catalogues): "Get Device ID" -> "GetDeviceID". Resolution still
    # accepts the spaced form (covered in Task 2).
    assert row["name"] == "GetDeviceID"
    assert row["prefix"] is None
    assert "Table G-1" in row["src"]


def test_ipmi_stats_total_equals_named():
    total, named = _vendor_stats("ipmi")
    assert total == named == len(IPMI_CMD_NAMES)


from zipmi.cli.oem_cmds import _find_cmd


def _hits(query):
    return _find_cmd(_vendor_listing("ipmi"), query)


def test_exact_name_unique():
    hits = _hits("Get Device ID")
    assert len(hits) == 1
    assert hits[0][0] == (0x06, 0x01)


def test_normalized_forms_unique():
    for q in ("get-device-id", "GetDeviceID", "get_device_id"):
        hits = _hits(q)
        assert len(hits) == 1, q
        assert hits[0][0] == (0x06, 0x01)


def test_ambiguous_substring_lists_many():
    hits = _hits("Get Chassis")
    assert len(hits) >= 2  # Capabilities + Status (+ more)


def test_no_match_returns_empty():
    assert _hits("DefinitelyNotAnIpmiCommandXYZ") == []


from zipmi.cli.oem_cmds import _print_vendor_listing


def test_ipmi_listing_title_not_oem(capsys):
    _print_vendor_listing("ipmi")
    out = capsys.readouterr().out
    first = out.splitlines()[0]
    assert "Table G-1" in first
    assert "OEM" not in first
    assert "GetDeviceID" in out  # a real row rendered (camelized)


def test_vendor_listing_title_unchanged(capsys):
    _print_vendor_listing("supermicro")
    first = capsys.readouterr().out.splitlines()[0]
    assert "OEM commands" in first
