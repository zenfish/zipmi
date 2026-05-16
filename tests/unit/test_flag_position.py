"""
tests/unit/test_flag_position.py

WHAT  Global flags (-H/-d/etc.) must parse at any token position.
WHY   Users append -d/-H after a fully typed command; argparse
      subparsers normally forbid optionals after the verb.
"""
from __future__ import annotations

import pytest

from zipmi.cli.zipmi import cmd_mc_info, parse_cli


def test_global_before_verb():
    ns = parse_cli(["-H", "1.2.3.4", "mc", "info"])
    assert ns.host == "1.2.3.4"
    assert ns.func is cmd_mc_info


def test_global_after_action():
    ns = parse_cli(["mc", "info", "-H", "1.2.3.4"])
    assert ns.host == "1.2.3.4"
    assert ns.func is cmd_mc_info


def test_global_between_verb_and_action():
    ns = parse_cli(["mc", "-H", "1.2.3.4", "info"])
    assert ns.host == "1.2.3.4"
    assert ns.func is cmd_mc_info


def test_debug_appended_at_end():
    ns = parse_cli(["scan", "all", "-d"])
    assert ns.debug is True


def test_defaults_when_no_globals(monkeypatch):
    monkeypatch.delenv("ZIPMI_TARGET", raising=False)
    monkeypatch.delenv("ZIPMI_USER", raising=False)
    monkeypatch.delenv("ZIPMI_PASS", raising=False)
    ns = parse_cli(["mc", "info"])
    assert ns.port == 623
    assert ns.debug is False
    assert ns.host is None


def test_unknown_flag_hard_errors():
    with pytest.raises(SystemExit) as exc:
        parse_cli(["mc", "info", "--hots", "x"])
    assert exc.value.code != 0


def test_top_help_lists_globals():
    from zipmi.cli.zipmi import build_parser
    help_text = build_parser().format_help()
    assert "--host" in help_text
    assert "--debug" in help_text
