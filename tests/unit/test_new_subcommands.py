"""Parser-shape tests for newly added subcommands.

Each verb gets a smoke test that confirms the subparser is registered
and dispatches to the right handler. Live-BMC interaction is covered
by integration tests / manual runs.
"""

import pytest

from zipmi.cli.zipmi import parse_cli


def _func_name(argv: list[str]) -> str:
    return parse_cli(argv).func.__name__


def test_sel_clear_dispatches():
    assert _func_name(["-H", "x", "sel", "clear"]) == "cmd_sel_clear"


def test_sel_time_get_dispatches():
    assert _func_name(["-H", "x", "sel", "time", "get"]) == "cmd_sel_time_get"


def test_sel_time_set_dispatches_with_now():
    args = parse_cli(["-H", "x", "sel", "time", "set", "now"])
    assert args.func.__name__ == "cmd_sel_time_set"
    assert args.timestamp == "now"


def test_sel_time_set_dispatches_with_epoch():
    args = parse_cli(["-H", "x", "sel", "time", "set", "0x6a17a88e"])
    assert args.timestamp == "0x6a17a88e"


def test_sel_time_set_requires_timestamp_arg(capsys):
    with pytest.raises(SystemExit):
        parse_cli(["-H", "x", "sel", "time", "set"])
