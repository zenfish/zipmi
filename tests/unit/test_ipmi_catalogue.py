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


import zipmi


def test_cmd_oem_run_skips_load_vendor_for_ipmi(monkeypatch, capsys):
    """ipmi must NOT trigger zipmi.load_vendor (would raise)."""
    def boom(v):
        raise AssertionError(f"load_vendor({v!r}) must not be called for ipmi")
    monkeypatch.setattr(zipmi, "load_vendor", boom)

    from zipmi.cli.oem_cmds import cmd_oem_run
    import argparse
    # No cmd_name -> listing path: must not call load_vendor, returns 0.
    args = argparse.Namespace(cmd_name=None, data=[])
    rc = cmd_oem_run(args, "ipmi")
    assert rc == 0
    assert "Table G-1" in capsys.readouterr().out


from zipmi.cli.oem_cmds import VENDORS
from zipmi.cli.zipmi import build_parser


def test_ipmi_is_not_an_oem_vendor():
    assert "ipmi" not in VENDORS


def test_ipmi_verb_parses_and_dispatches():
    parser = build_parser()
    ns = parser.parse_args(["ipmi", "Get Device ID", "0x01"])
    assert ns.cmd_name == "Get Device ID"
    assert ns.data == ["0x01"]
    assert callable(ns.func)


def test_ipmi_verb_listing_no_args():
    parser = build_parser()
    ns = parser.parse_args(["ipmi"])
    assert getattr(ns, "cmd_name", None) in (None, [])
    assert callable(ns.func)
