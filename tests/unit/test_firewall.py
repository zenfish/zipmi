"""Unit tests for the `firewall` verb (IPMI 2.0 §21 firmware-firewall discovery).

Pure bit/mask decoders are tested directly; cmd_firewall is driven through a
scripted FakeSession (no network) by monkeypatching _open_session.
"""
import argparse
import json

import pytest

from zipmi.cli.zipmi import (
    _fw_bits, _fw_netfn_support, _fw_cmd_mask, _fw_cmd_enables, _fw_subfn_mask,
    cmd_firewall, build_parser, emit,
)


# -- emit(): the single --json output contract ----------------------------

def test_emit_json_dumps_and_signals_handled(capsys):
    """emit returns True and prints parseable JSON when --json is set, so the
    caller knows to skip its text rendering."""
    ns = argparse.Namespace(json=True)
    assert emit(ns, {"a": 1, "b": [2, 3]}) is True
    assert json.loads(capsys.readouterr().out) == {"a": 1, "b": [2, 3]}


def test_emit_noop_without_json(capsys):
    """Without --json, emit returns False and prints nothing (caller renders text)."""
    assert emit(argparse.Namespace(json=False), {"a": 1}) is False
    assert capsys.readouterr().out == ""
    # missing attr entirely also treated as off (getattr default)
    assert emit(argparse.Namespace(), {"a": 1}) is False


@pytest.fixture(autouse=True)
def _clean_registry(clean_oem_registry):
    """Firewall command naming/classification must see standard IPMI names, not
    OEM names leaked into the global registry by other tests (import-memoized).
    Run every test in this module against a cleared OEM registry."""
    yield


# -- pure mask decoders ---------------------------------------------------

def test_fw_bits_empty():
    assert _fw_bits(b"") == []
    assert _fw_bits(b"\x00\x00") == []


def test_fw_bits_single_byte_lsb_first():
    assert _fw_bits(bytes([0b00000001])) == [0]
    assert _fw_bits(bytes([0b00000101])) == [0, 2]
    assert _fw_bits(bytes([0b10000000])) == [7]


def test_fw_bits_multibyte_offsets():
    # byte0 bit0 -> cmd 0 ; byte1 bit0 -> cmd 8 ; byte1 bit2 -> cmd 10
    assert _fw_bits(bytes([0x01, 0x05])) == [0, 8, 10]


def test_fw_bits_all_set_16_bytes_is_128_codes():
    assert _fw_bits(b"\xff" * 16) == list(range(128))


# -- Get NetFn Support (0x09) decode --------------------------------------

class _S:
    """Scripted session: send_raw(netfn, cmd, data=b'') -> canned (cc, bytes).

    Keys try (netfn, cmd, data) then (netfn, cmd); default = (0xC1, b'').
    """
    def __init__(self, responses):
        self.responses = responses
        self.sent = []

    def send_raw(self, netfn, cmd, data=b""):
        self.sent.append((netfn, cmd, bytes(data)))
        r = self.responses
        return r.get((netfn, cmd, bytes(data))) or r.get((netfn, cmd)) or (0xC1, b"")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fw_netfn_support_pair_decode():
    # pair-mask byte0 bit3 set -> pair index 3 -> NetFn 2*3 = 0x06 (App)
    s = _S({(0x06, 0x09): (0, b"\x00" + bytes([0x08]))})
    assert _fw_netfn_support(s, 0x0e) == [0x06]


def test_fw_netfn_support_multiple():
    # bits 0 and 5 -> pairs 0,5 -> NetFn 0x00 and 0x0A
    s = _S({(0x06, 0x09): (0, b"\x00" + bytes([0b00100001]))})
    assert _fw_netfn_support(s, 0x0e) == [0x00, 0x0A]


def test_fw_netfn_support_real_cray_mask():
    """Real Get NetFn Support response captured from a Cray XD670 (MegaRAC)."""
    s = _S({(0x06, 0x09): (0, bytes.fromhex("026f004083000000000000000000000000"))})
    assert _fw_netfn_support(s, 0x0e) == [0x00, 0x02, 0x04, 0x06, 0x0a, 0x0c, 0x2c, 0x30, 0x32, 0x3e]


def test_fw_netfn_support_cc_error_returns_empty():
    assert _fw_netfn_support(_S({(0x06, 0x09): (0xC1, b"")}), 0x0e) == []


def test_fw_netfn_support_short_returns_empty():
    assert _fw_netfn_support(_S({(0x06, 0x09): (0, b"\x00")}), 0x0e) == []


# -- per-NetFn masks ------------------------------------------------------

def test_fw_cmd_mask_ok_and_truncates_to_16():
    s = _S({(0x06, 0x0A): (0, bytes(range(20)))})
    m = _fw_cmd_mask(s, 0x0A, 0x0e, 0x06)
    assert m == bytes(range(16))


def test_fw_cmd_mask_short_is_none():
    assert _fw_cmd_mask(_S({(0x06, 0x0A): (0, b"\x00" * 8)}), 0x0A, 0x0e, 0x06) is None


def test_fw_cmd_mask_cc_error_is_none():
    assert _fw_cmd_mask(_S({(0x06, 0x0A): (0xD4, b"\x00" * 16)}), 0x0A, 0x0e, 0x06) is None


def test_fw_cmd_enables_ok():
    s = _S({(0x06, 0x61): (0, b"\x0f" + b"\x00" * 15)})   # 0x61 Get Command Enables
    assert _fw_bits(_fw_cmd_enables(s, 0x0e, 0x06)) == [0, 1, 2, 3]


def test_fw_subfn_mask_ok_and_error():
    assert _fw_subfn_mask(_S({(0x06, 0x0C): (0, b"\x03")}), 0x0C, 0x0e, 0x2c, 0x01) == b"\x03"
    assert _fw_subfn_mask(_S({(0x06, 0x0C): (0xC1, b"")}), 0x0C, 0x0e, 0x2c, 0x01) is None


# -- cmd_firewall end to end (scripted session) ---------------------------

def _fw_scenario():
    """App(0x06) with cmds {1,2} in the table; cmd 1 enabled, cmd 2 DISABLED."""
    ch = 0x0e
    return _S({
        (0x06, 0x09, bytes([ch])): (0, b"\x00" + bytes([0x08])),          # NetFn 0x06 supported
        (0x06, 0x0A, bytes([ch, 0x06, 0])): (0, bytes([0x06]) + b"\x00" * 15),  # cmds 1,2 supported
        (0x06, 0x0B, bytes([ch, 0x06, 0])): (0, bytes([0x02]) + b"\x00" * 15),  # cmd 1 configurable
        (0x06, 0x61, bytes([ch, 0x06, 0])): (0, bytes([0x02]) + b"\x00" * 15),  # cmd 1 enabled, cmd 2 not (0x61 Get Command Enables)
    })


def _run_firewall(monkeypatch, s, **overrides):
    import zipmi.cli.zipmi as Z
    monkeypatch.setattr(Z, "_open_session", lambda args: s)
    kw = dict(channel="0x0e", probe=False, subfn=False, json=False, host="test")
    kw.update(overrides)
    return cmd_firewall(argparse.Namespace(**kw))


def test_cmd_firewall_runs_and_prints(monkeypatch, capsys):
    rc = _run_firewall(monkeypatch, _fw_scenario())
    out = capsys.readouterr().out
    assert rc == 0
    assert "Firmware Firewall" in out
    assert "0x06(App)" in out
    assert "DISABLED" in out          # cmd 2 is blocked


def test_cmd_firewall_json_structure(monkeypatch, capsys):
    """--json emits to stdout as shape B: netfns is an ARRAY of records, each
    with integer `netfn` + `netfn_hex` + name, and the streaming text is
    suppressed (the JSON must parse clean, no narration prefix)."""
    _run_firewall(monkeypatch, _fw_scenario(), json=True)
    data = json.loads(capsys.readouterr().out)     # parses => no text leaked
    assert isinstance(data["netfns"], list)
    nf = next(n for n in data["netfns"] if n["netfn"] == 0x06)
    assert nf["netfn_hex"] == "0x06"
    assert nf["total_in_table"] == 2          # cmds 1 and 2
    assert nf["disabled"] == [2]              # cmd 2 in support but not enabled
    assert data["channel"] == 0x0e


def test_cmd_firewall_probe_sends_each_command(monkeypatch, capsys):
    s = _fw_scenario()
    # make named commands resolve as implemented (cc 0) when probed
    s.responses[(0x06, 0x01)] = (0, b"")
    s.responses[(0x06, 0x02)] = (0xC1, b"")
    _run_firewall(monkeypatch, s, probe=True)
    # probe issues a bare send_raw(netfn, cmd) per named command
    assert any(t[:2] == (0x06, 0x01) and t[2] == b"" for t in s.sent)


def test_cmd_firewall_no_netfns_is_clean(monkeypatch, capsys):
    s = _S({(0x06, 0x09): (0xC1, b"")})       # firewall not answered / blocked
    rc = _run_firewall(monkeypatch, s)
    assert rc == 0
    assert "Supported NetFns" in capsys.readouterr().out


# -- parser wiring --------------------------------------------------------

def test_firewall_subcommand_registered():
    """Parser routes `firewall` to cmd_firewall AND defaults to safe mode.

    The safe-by-default contract (commit 537ed73) lives in the parser
    defaults: with no flags, probing is off and --unsafe is off, so a bare
    `firewall` invocation can never fire state-changing commands. Pin those
    defaults, not just that the subcommand parses.
    """
    p = build_parser()
    ns = p.parse_args(["-H", "x", "firewall", "--channel", "0x0e"])
    assert ns.func is cmd_firewall
    assert ns.channel == "0x0e"
    assert ns.probe is False        # discovery is read-only by default
    assert getattr(ns, "unsafe", False) is False  # state-changing gated off


def test_probe_safe_gates_state_changing(monkeypatch, capsys):
    # App cmd 0x01 = Get Device ID (read-only), 0x02 = Cold Reset (state-changing).
    s = _fw_scenario()
    s.responses[(0x06, 0x01)] = (0, b"")
    s.responses[(0x06, 0x02)] = (0, b"")
    _run_firewall(monkeypatch, s, probe=True)          # safe: no --unsafe
    sent = [(t[0], t[1]) for t in s.sent]
    assert (0x06, 0x01) in sent                        # Get* probed
    assert (0x06, 0x02) not in sent                    # Cold Reset NOT sent
    assert "not sent: state-changing" in capsys.readouterr().out


def test_probe_unsafe_sends_state_changing(monkeypatch, capsys):
    s = _fw_scenario()
    s.responses[(0x06, 0x02)] = (0, b"")
    _run_firewall(monkeypatch, s, probe=True, unsafe=True)
    assert (0x06, 0x02) in [(t[0], t[1]) for t in s.sent]   # Cold Reset sent under --unsafe
