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


def test_vbmc_flags_renamed_with_v_prefix():
    ns = parse_cli(["vbmc", "serve", "--vport", "7000",
                    "--vbind", "0.0.0.0", "--vpersona", "dell_idrac6"])
    assert ns.vport == 7000
    assert ns.vbind == "0.0.0.0"
    assert ns.vpersona == "dell_idrac6"


def test_vbmc_no_port_collision_with_global():
    # -p is the global connection port; --vport is the vBMC listen port.
    ns = parse_cli(["-p", "700", "vbmc", "serve", "--vport", "7000"])
    assert ns.port == 700
    assert ns.vport == 7000


def test_vbmc_old_port_goes_to_global_not_vport():
    # --port is now the global IPMI connection port (absorbed by the pre-parser).
    # It no longer silently sets the vBMC listen port; --vport must be used for that.
    ns = parse_cli(["vbmc", "serve", "--port", "7000"])
    assert ns.port == 7000      # global connection port got it
    assert ns.vport == 6230     # vBMC listen port stays at its default
