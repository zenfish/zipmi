"""Parser-shape tests for newly added subcommands.

Each verb gets a smoke test that confirms the subparser is registered
and dispatches to the right handler. Live-BMC interaction is covered
by integration tests / manual runs.
"""

import pytest

import zipmi.cli.zipmi as _z
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


def test_channel_info_dispatch_default_channel():
    args = parse_cli(["-H", "x", "channel", "info"])
    assert args.func.__name__ == "cmd_channel_info"
    assert args.channel == 0x0E


def test_channel_info_explicit_channel():
    args = parse_cli(["-H", "x", "channel", "info", "1"])
    assert args.channel == 1


def test_channel_getaccess_dispatch():
    args = parse_cli(["-H", "x", "channel", "getaccess", "1", "2"])
    assert args.func.__name__ == "cmd_channel_getaccess"
    assert args.channel == 1
    assert args.user_id == 2


def test_session_info_default_active():
    args = parse_cli(["-H", "x", "session", "info"])
    assert args.func.__name__ == "cmd_session_info"
    assert args.selector == "active"


def test_session_info_explicit_index():
    args = parse_cli(["-H", "x", "session", "info", "3"])
    assert args.selector == "3"


def test_mc_watchdog_get_dispatches():
    assert _func_name(["-H", "x", "mc", "watchdog", "get"]) == "cmd_mc_watchdog_get"


def test_mc_watchdog_reset_dispatches():
    assert _func_name(["-H", "x", "mc", "watchdog", "reset"]) == "cmd_mc_watchdog_reset"


def test_fru_print_dispatch_default_device_id():
    args = parse_cli(["-H", "x", "fru", "print"])
    assert args.func.__name__ == "cmd_fru_print"
    assert args.device_id == 0


def test_fru_print_explicit_device_id():
    args = parse_cli(["-H", "x", "fru", "print", "2"])
    assert args.device_id == 2


def test_sensor_get_dispatches():
    args = parse_cli(["-H", "x", "sensor", "get", "Ambient Temp"])
    assert args.func.__name__ == "cmd_sensor_get"
    assert args.name == "Ambient Temp"


def test_sensor_get_requires_name(capsys):
    with pytest.raises(SystemExit):
        parse_cli(["-H", "x", "sensor", "get"])


def test_mc_watchdog_off_requires_yes_and_dispatches():
    args = parse_cli(["-H", "x", "mc", "watchdog", "off"])
    assert args.func.__name__ == "cmd_mc_watchdog_off"
    assert args.yes is False
    args2 = parse_cli(["-H", "x", "mc", "watchdog", "off", "--yes"])
    assert args2.yes is True


class _FakeSession:
    """Records send_raw calls; context-manager like the real Session."""
    def __init__(self):
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_raw(self, netfn, cmd, data):
        self.sent.append((netfn, cmd, bytes(data)))
        if (netfn, cmd) == (0x06, 0x25):        # Get Watchdog: 8 bytes; running bit set
            return 0x00, bytes([0x40 | 0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00])
        return 0x00, b""


def test_mc_watchdog_off_without_yes_sends_nothing(monkeypatch):
    """The destructive gate must BLOCK the write, not just parse a flag."""
    def _boom(_args):
        raise AssertionError("_open_session called — gate failed to block!")
    monkeypatch.setattr(_z, "_open_session", _boom)
    args = parse_cli(["-H", "x", "mc", "watchdog", "off"])   # no --yes
    rc = _z.cmd_mc_watchdog_off(args)
    assert rc == 2                                            # refused, nothing sent


def test_mc_watchdog_off_with_yes_clears_running_bit(monkeypatch):
    """With --yes it reads (0x25) then writes (0x24) with the 0x40 running bit
    cleared — the actual disable logic, not just dispatch."""
    fake = _FakeSession()
    monkeypatch.setattr(_z, "_open_session", lambda _args: fake)
    args = parse_cli(["-H", "x", "mc", "watchdog", "off", "--yes"])
    rc = _z.cmd_mc_watchdog_off(args)
    assert rc == 0
    assert fake.sent[0][:2] == (0x06, 0x25)                  # reads current config first
    assert fake.sent[1][:2] == (0x06, 0x24)                  # then Set Watchdog
    assert fake.sent[1][2][0] == 0x05                        # 0x45 & ~0x40 → running bit cleared


# -- -V / --version global -----------------------------------------------


def test_version_flag_short_exits_zero(capsys):
    from zipmi import __version__
    with pytest.raises(SystemExit) as e:
        parse_cli(["-V"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_version_flag_long_exits_zero(capsys):
    from zipmi import __version__
    with pytest.raises(SystemExit) as e:
        parse_cli(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


# -- i2c / spd parser shape ----------------------------------------------


def test_i2c_dispatches():
    args = parse_cli(["-H", "x", "i2c", "bus=public", "chan=0",
                      "0x50", "16", "0x00"])
    assert args.func.__name__ == "cmd_i2c"
    assert args.tokens == ["bus=public", "chan=0", "0x50", "16", "0x00"]


def test_spd_dispatches():
    args = parse_cli(["-H", "x", "spd", "bus=public", "chan=0", "0x50"])
    assert args.func.__name__ == "cmd_spd"
    assert args.tokens == ["bus=public", "chan=0", "0x50"]
    assert args.size == 256


def test_spd_custom_size():
    args = parse_cli(["-H", "x", "spd", "--size", "512", "bus=public", "0x50"])
    assert args.size == 512


# -- bus byte construction (IPMI 2.0 §22.11) -----------------------------


def test_i2c_bus_byte_public_chan0():
    from zipmi.cli.zipmi import _parse_i2c_bus_chan
    bus, rest = _parse_i2c_bus_chan(["bus=public", "chan=0", "0x50", "16"])
    assert bus == 0x00
    assert rest == ["0x50", "16"]


def test_i2c_bus_byte_public_chan_set():
    from zipmi.cli.zipmi import _parse_i2c_bus_chan
    bus, _ = _parse_i2c_bus_chan(["bus=public", "chan=7", "0x50", "1"])
    # chan=7 in [7:4], priv_bus=0, private=0 → 0x70
    assert bus == 0x70


def test_i2c_bus_byte_private():
    from zipmi.cli.zipmi import _parse_i2c_bus_chan
    bus, _ = _parse_i2c_bus_chan(["bus=3", "0x50", "1"])
    # chan=0, priv_bus=3 in [3:1] → (3<<1)|1 = 0x07
    assert bus == 0x07


def test_i2c_bus_byte_default_no_tokens():
    from zipmi.cli.zipmi import _parse_i2c_bus_chan
    bus, rest = _parse_i2c_bus_chan(["0x50", "16"])
    assert bus == 0x00
    assert rest == ["0x50", "16"]


def test_i2c_chan_without_bus_rejected():
    from zipmi.cli.zipmi import _parse_i2c_bus_chan
    with pytest.raises(ValueError):
        _parse_i2c_bus_chan(["chan=5", "0x50", "1"])


def test_hex_dump_format():
    from zipmi.cli.zipmi import _hex_dump
    out = _hex_dump(b"hello world\x00\x01\x02\x03\x04")
    lines = out.splitlines()
    assert lines[0].startswith("00000: 68 65 6c 6c 6f 20 77 6f 72 6c 64 00 01 02 03 04")
    assert lines[0].endswith("hello world.....")
