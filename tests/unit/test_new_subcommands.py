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


def test_chassis_restart_cause_dispatches():
    assert (_func_name(["-H", "x", "chassis", "restart_cause"])
            == "cmd_chassis_restart_cause")


def test_chassis_policy_list_dispatches():
    args = parse_cli(["-H", "x", "chassis", "policy", "list"])
    assert args.func.__name__ == "cmd_chassis_policy"
    assert args.policy == "list"


def test_chassis_policy_set_each_value():
    for pol in ("always-off", "previous", "always-on"):
        args = parse_cli(["-H", "x", "chassis", "policy", pol])
        assert args.policy == pol


def test_chassis_policy_rejects_unknown(capsys):
    with pytest.raises(SystemExit):
        parse_cli(["-H", "x", "chassis", "policy", "bogus"])


def test_user_test_password_dispatch_and_no_global_collision():
    """Positional 'password' must not clobber global -P."""
    args = parse_cli(["-H", "x", "-P", "sessionpw", "user", "test", "2", "testpw"])
    assert args.func.__name__ == "cmd_user_test_password"
    assert args.password == "sessionpw"      # global -P
    assert args.test_password == "testpw"    # positional
    assert args.user_id == 2
    assert args.size == 16


def test_user_set_password_dispatch_and_no_global_collision():
    args = parse_cli(["-H", "x", "-P", "sessionpw",
                      "user", "set", "password", "3", "newpw", "20"])
    assert args.func.__name__ == "cmd_user_set_password"
    assert args.password == "sessionpw"
    assert args.new_password == "newpw"
    assert args.user_id == 3
    assert args.size == 20


def test_user_enable_disable_dispatch():
    a1 = parse_cli(["-H", "x", "user", "enable", "5"])
    a2 = parse_cli(["-H", "x", "user", "disable", "5"])
    assert a1.func.__name__ == "cmd_user_enable"
    assert a2.func.__name__ == "cmd_user_disable"


def test_user_set_name_dispatch():
    args = parse_cli(["-H", "x", "user", "set", "name", "4", "alice"])
    assert args.func.__name__ == "cmd_user_set_name"
    assert args.user_id == 4
    assert args.name == "alice"


def test_user_priv_dispatch_with_channel():
    args = parse_cli(["-H", "x", "user", "priv", "2", "admin", "1"])
    assert args.func.__name__ == "cmd_user_priv"
    assert args.level == "admin"
    assert args.channel == 1


def test_user_priv_channel_default():
    args = parse_cli(["-H", "x", "user", "priv", "2", "user"])
    assert args.channel == 0x0E


def test_user_priv_rejects_unknown_level(capsys):
    with pytest.raises(SystemExit):
        parse_cli(["-H", "x", "user", "priv", "2", "godmode"])
