from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_PATH = Path(__file__).parents[2] / "scripts/merge_idrac10_contracts.py"
_SPEC = importlib.util.spec_from_file_location("merge_idrac10_contracts", _PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(_MODULE)


def _catalog():
    return {"commands": [{
        "name": "ReadThing", "netfn": "0x30", "cmd": "0x01", "subcmd": "0x02",
    }]}


def _fragment():
    return {"records": {"record": {
        "name": "ReadThing", "netfn": "0x30", "cmd": "0x01", "prefix": "02",
        "subcmd": "0x02",
        "effect": "safe", "sideEffects": [],
        "requestLength": {"min": 1, "max": 1},
        "responseLength": {"min": 2, "max": 2},
        "completionCodes": [{"code": "0x00", "meaning": "success"}],
        "activation": {"privilege": "User", "inBandOnly": False, "conditions": []},
        "evidence": {"function": "ReadThing", "address": "0x1234"},
    }}}


def test_merge_preserves_identity_and_converts_response_length_to_include_cc():
    record = _MODULE.merge(_catalog(), _fragment())["commands"][0]
    assert record["effect"] == "safe"
    assert record["requestLength"] == 1
    assert record["responseLengthIncludingCc"] == 3
    assert record["codecState"] == "raw-exact"
    assert record["selectorOffset"] is None


def test_merge_rejects_unmatched_contract():
    fragment = _fragment()
    fragment["records"]["record"]["cmd"] = "0x02"
    with pytest.raises(ValueError, match="absent from catalog"):
        _MODULE.merge(_catalog(), fragment)


def test_multibyte_subcommand_matches_explicit_prefix():
    catalog = {"commands": [{
        "name": "ReadThing", "netfn": "0x30", "cmd": "0x01",
        "subcmd": "0x06 0x00",
    }]}
    fragment = _fragment()
    fragment["records"]["record"]["prefix"] = "0600"
    _MODULE.merge(catalog, fragment)


def test_array_fragment_preserves_including_cc_length_and_selector_offset():
    fragment = _fragment()
    record = fragment["records"].pop("record")
    record["requestFields"] = [{"offset": 1, "kind": "u8", "constant": 2}]
    record["responseLengthIncludingCc"] = record.pop("responseLength")
    fragment["records"] = [record]
    merged = _MODULE.merge(_catalog(), fragment)["commands"][0]
    assert merged["responseLengthIncludingCc"] == 2
    assert merged["selectorOffset"] == 1


def test_operations_fragment_normalizes_rich_audit_schema():
    catalog = {"commands": [{
        "name": "ReadThing", "netfn": "0x30", "cmd": "0x01", "subcmd": "",
    }]}
    fragment = {"operations": [{
        "name": "ReadThing",
        "prefixDiscriminant": {"netfn": "0x30", "cmd": "0x01", "subcmd": None},
        "safety": "safe/read-only", "sideEffects": [],
        "requestLength": {"kind": "minimum", "bytes": 1},
        "responseLengthIncludingCc": {"kind": "range", "bytes": [2, 4]},
        "completionCodes": {"0x00": "success"},
        "activation": {"registration": "static", "gates": []},
        "evidence": [{"symbol": "ReadThing"}],
    }]}

    merged = _MODULE.merge(catalog, fragment)["commands"][0]
    assert merged["effect"] == "safe"
    assert merged["requestLength"] == {"min": 1, "max": None}
    assert merged["responseLengthIncludingCc"] == {"min": 2, "max": 4}


def test_effect_normalization_is_fail_closed():
    assert _MODULE._effect("read-only", "ReadThing") == "safe"
    assert _MODULE._effect("mixed", "ReadThing") == "security-sensitive"
    assert _MODULE._effect("read-with-side-effects", "DellCPLDAccessStatus") == "security-sensitive"


def test_verified_fragment_promotes_only_exact_complete_codec_sides():
    fragment = _fragment()
    record = fragment["records"]["record"]
    record["codecState"] = "verified"
    record["responseLengthIncludingCc"] = {"min": 3, "max": 3}
    del record["responseLength"]
    record["requestFields"] = [{
        "offset": 0, "length": 1, "encoding": "u8", "description": "selector",
    }]
    record["responseFields"] = [
        {"offset": 0, "length": 1, "encoding": "u8",
         "description": "IPMI completion code"},
        {"offset": 1, "length": 2, "encoding": "raw-bytes", "description": "value"},
    ]

    merged = _MODULE.merge(_catalog(), fragment)["commands"][0]
    assert merged["requestCodec"] is True
    assert merged["responseCodec"] is True
    assert merged["codecState"] == "verified"
    assert merged["responseFields"][0]["name"] == "completion_code"
    assert merged["responseFields"][1]["length"] == 2
