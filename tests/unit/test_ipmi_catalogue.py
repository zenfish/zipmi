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
