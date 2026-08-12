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


class _Rec:
    """Tiny attribute bag for canned send_cmd responses (Reserve SEL, etc.)."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _EffectSession:
    """Context-manager fake that records BOTH send_raw and send_cmd.

    send_raw(netfn, cmd, data) -> (cc, bytes): looks up a canned reply in
    ``raw_replies[(netfn, cmd)]`` (default cc=0, no data).
    send_cmd(netfn, cmd, req=None) -> object: canned in ``cmd_replies``.
    Every call is appended to ``self.sent`` / ``self.cmds`` for assertions.
    """
    def __init__(self, raw_replies=None, cmd_replies=None):
        self.sent = []          # list[(netfn, cmd, bytes)]
        self.cmds = []          # list[(netfn, cmd, req)]
        self._raw = raw_replies or {}
        self._cmd = cmd_replies or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_raw(self, netfn, cmd, data):
        self.sent.append((netfn, cmd, bytes(data)))
        return self._raw.get((netfn, cmd), (0x00, b""))

    def send_cmd(self, netfn, cmd, req=None):
        self.cmds.append((netfn, cmd, req))
        return self._cmd[(netfn, cmd)]


def _install(monkeypatch, fake):
    monkeypatch.setattr(_z, "_open_session", lambda _args: fake)
    return fake


# ---------------------------------------------------------------------------
# EFFECT tests: drive each handler through a fake session and assert the exact
# (netfn, cmd, payload) it puts on the wire. Expected bytes are derived from the
# IPMI 2.0 spec for each command, NOT copied from the handler.
# ---------------------------------------------------------------------------


def test_sel_clear_effect_reserve_then_clr_aa(monkeypatch):
    """§31.9 Clear SEL: Reserve SEL (0x0A/0x42) → 0x0A/0x47 with
    reservation_id LE + 'CLR' + 0xAA to initiate, then poll with 0x00.
    Poll reply byte0 low nibble == 1 means erase complete."""
    fake = _install(monkeypatch, _EffectSession(
        cmd_replies={(0x0A, 0x42): _Rec(reservation_id=0x1234)},
        raw_replies={(0x0A, 0x47): (0x00, bytes([0x01]))},   # status: complete
    ))
    rc = _z.cmd_sel_clear(parse_cli(["-H", "x", "sel", "clear"]))
    assert rc == 0
    assert fake.cmds[0][:2] == (0x0A, 0x42)                  # Reserve SEL
    # initiate: reservation 0x1234 -> LE 34 12, then C L R, then 0xAA
    assert fake.sent[0] == (0x0A, 0x47, b"\x34\x12CLR\xaa")
    # first poll: same rid + 'CLR' + 0x00
    assert fake.sent[1] == (0x0A, 0x47, b"\x34\x12CLR\x00")


def test_sel_time_get_effect(monkeypatch):
    """§31.10 Get SEL Time: 0x0A/0x48, empty request; 4-byte LE reply."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x0A, 0x48): (0x00, (0x6a17a88e).to_bytes(4, "little"))},
    ))
    rc = _z.cmd_sel_time_get(parse_cli(["-H", "x", "sel", "time", "get"]))
    assert rc == 0
    assert fake.sent == [(0x0A, 0x48, b"")]


def test_sel_time_set_effect_epoch_le(monkeypatch):
    """§31.11 Set SEL Time: 0x0A/0x49, 4-byte LE seconds-since-epoch."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_sel_time_set(
        parse_cli(["-H", "x", "sel", "time", "set", "0x6a17a88e"]))
    assert rc == 0
    assert fake.sent == [(0x0A, 0x49, b"\x8e\xa8\x17\x6a")]


def test_chassis_restart_cause_effect(monkeypatch):
    """§28.11 Get System Restart Cause: 0x00/0x07, empty request."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x00, 0x07): (0x00, bytes([0x01, 0x00]))},
    ))
    rc = _z.cmd_chassis_restart_cause(
        parse_cli(["-H", "x", "chassis", "restart_cause"]))
    assert rc == 0
    assert fake.sent == [(0x00, 0x07, b"")]


def test_chassis_policy_list_effect(monkeypatch):
    """§28.8 Set Power Restore Policy: 'list' uses no-change variant 0x03."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x00, 0x06): (0x00, bytes([0x07]))},
    ))
    rc = _z.cmd_chassis_policy(
        parse_cli(["-H", "x", "chassis", "policy", "list"]))
    assert rc == 0
    assert fake.sent == [(0x00, 0x06, b"\x03")]


def test_chassis_policy_set_effect(monkeypatch):
    """§28.8 policy field: always-off=0, previous=1, always-on=2."""
    for pol, code in (("always-off", 0x00), ("previous", 0x01),
                      ("always-on", 0x02)):
        fake = _install(monkeypatch, _EffectSession())
        rc = _z.cmd_chassis_policy(
            parse_cli(["-H", "x", "chassis", "policy", pol]))
        assert rc == 0
        assert fake.sent == [(0x00, 0x06, bytes([code]))]


def test_user_set_name_effect(monkeypatch):
    """§22.28 Set User Name: 0x06/0x45, byte0=user_id (bits5:0),
    then 16-byte name NUL-padded."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_user_set_name(
        parse_cli(["-H", "x", "user", "set", "name", "4", "alice", "--yes"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x45, bytes([0x04]) + b"alice".ljust(16, b"\x00"))]


def test_user_enable_effect(monkeypatch):
    """§22.30 Set User Password op=enable(0x01): 0x06/0x47,
    byte0=user_id, byte1=op (no password buffer for enable)."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_user_enable(
        parse_cli(["-H", "x", "user", "enable", "5", "--yes"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x47, bytes([0x05, 0x01]))]


def test_user_disable_effect(monkeypatch):
    """op=disable(0x00)."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_user_disable(
        parse_cli(["-H", "x", "user", "disable", "5", "--yes"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x47, bytes([0x05, 0x00]))]


def test_user_set_password_effect_20byte(monkeypatch):
    """op=set(0x02): byte0 gets bit7 set for a 20-byte slot; password
    NUL-padded to 20."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_user_set_password(
        parse_cli(["-H", "x", "user", "set", "password", "3", "newpw", "20",
                   "--yes"]))
    assert rc == 0
    expect = bytes([0x03 | 0x80, 0x02]) + b"newpw".ljust(20, b"\x00")
    assert fake.sent == [(0x06, 0x47, expect)]


def test_user_test_password_effect_16byte(monkeypatch):
    """op=test(0x03), default 16-byte slot; no --yes (read-only)."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_user_test_password(
        parse_cli(["-H", "x", "user", "test", "2", "testpw"]))
    assert rc == 0
    expect = bytes([0x02, 0x03]) + b"testpw".ljust(16, b"\x00")
    assert fake.sent == [(0x06, 0x47, expect)]


def test_user_priv_effect(monkeypatch):
    """§22.26 Set User Access: 0x06/0x43. byte0 bit7=0 (leave flags),
    bits3:0=channel; byte1=user_id; byte2=priv level; byte3=session limit 0."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_user_priv(
        parse_cli(["-H", "x", "user", "priv", "2", "admin", "1", "--yes"]))
    assert rc == 0
    # channel=1, user=2, admin=0x04, limit=0
    assert fake.sent == [(0x06, 0x43, bytes([0x01, 0x02, 0x04, 0x00]))]


def test_channel_info_effect(monkeypatch):
    """§22.24 Get Channel Info: 0x06/0x42, one byte = channel number."""
    reply = bytes([0x01, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x42): (0x00, reply)},
    ))
    rc = _z.cmd_channel_info(parse_cli(["-H", "x", "channel", "info", "1"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x42, bytes([0x01]))]


def test_channel_getaccess_effect(monkeypatch):
    """§22.27 Get User Access: 0x06/0x44, byte0=channel, byte1=user_id."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x44): (0x00, bytes([0x10, 0x01, 0x00, 0x04]))},
    ))
    rc = _z.cmd_channel_getaccess(
        parse_cli(["-H", "x", "channel", "getaccess", "1", "2"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x44, bytes([0x01, 0x02]))]


def test_session_info_active_effect(monkeypatch):
    """§22.20 Get Session Info: 0x06/0x3D. 'active' -> selector 0x00."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x3D): (0x00, bytes([0x01, 0x05, 0x01, 0x02,
                                                 0x04, 0x0E]))},
    ))
    rc = _z.cmd_session_info(parse_cli(["-H", "x", "session", "info"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x3D, b"\x00")]


def test_session_info_explicit_index_effect(monkeypatch):
    """Numeric selector -> that index byte (session-index lookup, table 22-25)."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x3D): (0x00, bytes([0x01, 0x05, 0x01, 0x02,
                                                 0x04, 0x0E]))},
    ))
    rc = _z.cmd_session_info(parse_cli(["-H", "x", "session", "info", "3"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x3D, bytes([0x03]))]


def test_mc_watchdog_get_effect(monkeypatch):
    """§27.7 Get Watchdog Timer: 0x06/0x25, empty request; 8-byte reply."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x25): (0x00, bytes([0x45, 0x00, 0x00, 0x00,
                                                 0x10, 0x00, 0x00, 0x00]))},
    ))
    rc = _z.cmd_mc_watchdog_get(parse_cli(["-H", "x", "mc", "watchdog", "get"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x25, b"")]


def test_mc_watchdog_reset_effect(monkeypatch):
    """§27.5 Reset Watchdog Timer: 0x06/0x22, empty request (pats the dog)."""
    fake = _install(monkeypatch, _EffectSession())
    rc = _z.cmd_mc_watchdog_reset(
        parse_cli(["-H", "x", "mc", "watchdog", "reset"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x22, b"")]


def test_fru_print_effect_inventory_probe(monkeypatch):
    """§34.1 Get FRU Inventory Area Info: 0x0A/0x10, one byte = device id.
    With a zero-size device the handler stops after the probe."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x0A, 0x10): (0x00, bytes([0x00, 0x00, 0x00]))},  # 0 bytes
    ))
    rc = _z.cmd_fru_print(parse_cli(["-H", "x", "fru", "print", "2"]))
    assert rc == 1                                  # empty blob -> short FRU
    assert fake.sent[0] == (0x0A, 0x10, bytes([0x02]))


def test_sensor_get_effect_sdr_repo_probe(monkeypatch):
    """cmd_sensor_get walks the SDR: first Get SDR Repo Info (0x0A/0x20).
    record_count 0 -> clean early return, proving it issues the walk start."""
    fake = _install(monkeypatch, _EffectSession(
        cmd_replies={(0x0A, 0x20): _Rec(record_count=0)},
    ))
    rc = _z.cmd_sensor_get(parse_cli(["-H", "x", "sensor", "get", "Foo"]))
    assert rc == 1
    assert fake.cmds[0][:2] == (0x0A, 0x20)


def test_i2c_effect_master_write_read(monkeypatch):
    """§22.11 Master Write-Read: 0x06/0x52, [bus_byte, slave<<1, read_cnt, wdata].
    bus=public chan=0 -> bus_byte 0x00; slave 0x50 -> 0xA0; read 16; write 0x00."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x52): (0x00, bytes(range(16)))},
    ))
    rc = _z.cmd_i2c(parse_cli(["-H", "x", "i2c", "bus=public", "chan=0",
                               "0x50", "16", "0x00"]))
    assert rc == 0
    assert fake.sent == [(0x06, 0x52, bytes([0x00, 0xA0, 0x10, 0x00]))]


def test_spd_effect_chunked_reads(monkeypatch):
    """spd reads the EEPROM in 16-byte Master Write-Read chunks; each request
    is [bus_byte, slave<<1, chunk_len, offset_low]. 256 bytes -> 16 chunks."""
    fake = _install(monkeypatch, _EffectSession(
        raw_replies={(0x06, 0x52): (0x00, bytes(16))},
    ))
    rc = _z.cmd_spd(parse_cli(["-H", "x", "spd", "bus=public", "0x50"]))
    assert rc == 0
    assert len(fake.sent) == 16                     # 256 / 16
    # first chunk: slave 0x50<<1=0xA0, read 16, offset 0
    assert fake.sent[0] == (0x06, 0x52, bytes([0x00, 0xA0, 0x10, 0x00]))
    # second chunk: offset advances to 16 (0x10)
    assert fake.sent[1] == (0x06, 0x52, bytes([0x00, 0xA0, 0x10, 0x10]))


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


def test_full_version_carries_git_sha_from_source():
    # full_version() prefixes the base version and, when run from this checkout
    # (a .git is present), appends the live +g<sha> tag. Guards against the tag
    # being dropped — the whole point is telling an installed copy from source.
    import os
    import zipmi
    v = zipmi.full_version()
    assert v.startswith(zipmi.__version__)
    root = os.path.dirname(os.path.dirname(os.path.abspath(zipmi.__file__)))
    if os.path.isdir(os.path.join(root, ".git")):
        assert "+g" in v, f"source run should carry a git sha, got {v!r}"


def test_git_describe_returns_empty_outside_repo(tmp_path):
    from zipmi import _git_describe
    assert _git_describe(str(tmp_path)) == ""


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
