"""
test_idrac10_commands.py — verify the iDRAC10 rich-command catalog codegen.

WHAT     Loads idrac10_commands_generated.py + the idrac10.py consumer and
         asserts the catalog imports with its pinned count, that
         load_vendor("idrac10") still registers, and spot-checks specific
         commands round-trip with correct NetFn/cmd/subcmd/priv.
WHY      The catalog is generated from idrac10-commands.json (RE'd +
         adversarially verified commands). A regression that drops entries
         or mis-parses hex NetFn/cmd/subcmd should fail loudly. Mirror of
         test_idrac9_dispatch.py.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager

import pytest

from zipmi.scapy_ipmi.oem.idrac10_commands_generated import IDRAC10_COMMANDS

_PRIVS = ("Admin", "Operator", "User", "Callback", "OEM", "undetermined")

# name -> (netfn, cmd, subcmd, priv-substring, lib). Read straight from
# IDRAC10_COMMANDS; spans distinct libs so a content swap fails.
_PINNED_CMDS = {
    "DellCmdGetBootstrapCredentials": (0x2c, 0x02, None, "Admin", "libmisccmd"),
    "CmdOEMDellFactory/SecureDefaultPassword": (0x30, 0xa5, 0x04, "User", "libmaser"),
    "CmdOEMMASERPartitionAccess/CmdOEMAttachPartitions":
        (0x30, 0xa2, 0x05, "Admin", "libmaser"),
    "CmdOEMGetChassisCapabilities": (0x00, 0x00, None, "User", "liboemcmds"),
    "CmdOEMEnableMsgChannelRecv": (0x06, 0x32, None, "User", "libmodular"),
}


@pytest.mark.parametrize("c", IDRAC10_COMMANDS, ids=lambda c: c.name)
def test_every_command_wellformed(c):
    """One case per catalog entry — a dropped/fabricated/malformed command fails loudly."""
    assert c.name and c.name.strip(), "empty name"
    # netfn/cmd: every catalog row has a firmware-proven byte identity.
    for f in (c.netfn, c.cmd):
        assert f is None or (isinstance(f, int) and 0 <= f <= 0xFF)
    # subcmd: int (multi-byte folded, may exceed 0xff) or None.
    assert c.subcmd is None or isinstance(c.subcmd, int)
    assert isinstance(c.in_band_only, bool)
    assert any(p.lower() in c.priv.lower() for p in _PRIVS), f"unknown priv {c.priv!r}"
    # These fields were RE'd per command — blank means a doc hole, not valid data.
    for field in ("purpose", "request", "response", "confidence", "lib"):
        assert getattr(c, field).strip(), f"empty {field}"
    pin = _PINNED_CMDS.get(c.name)
    if pin:
        netfn, cmd, subcmd, priv_sub, lib = pin
        assert (c.netfn, c.cmd, c.subcmd) == (netfn, cmd, subcmd)
        assert priv_sub.lower() in c.priv.lower()
        assert c.lib == lib


def test_known_commands_resolve():
    """Pin name -> exact (netfn,cmd,subcmd,priv,lib) across distinct libs.

    A scrambled name->row mapping or offset corruption fails at least one.
    """
    for name, (netfn, cmd, subcmd, priv_sub, lib) in _PINNED_CMDS.items():
        c = next(x for x in IDRAC10_COMMANDS if x.name == name)
        assert c.netfn == netfn, f"{name} netfn"
        assert c.cmd == cmd, f"{name} cmd"
        assert c.subcmd == subcmd, f"{name} subcmd"
        assert priv_sub.lower() in c.priv.lower(), f"{name} priv"
        assert c.lib == lib, f"{name} lib"


def test_catalog_keys_unique():
    """(name, netfn, cmd, subcmd) is the identity — no dupes survived the merge/dedup."""
    keys = [(c.name, c.netfn, c.cmd, c.subcmd) for c in IDRAC10_COMMANDS]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate command keys: {dupes}"


def test_catalog_imports_all():
    from zipmi.scapy_ipmi.oem.idrac10_commands_generated import (
        IDRAC10_COMMANDS, IDrac10Command,
    )
    assert isinstance(IDRAC10_COMMANDS, list)
    assert len(IDRAC10_COMMANDS) == 456
    assert all(isinstance(c, IDrac10Command) for c in IDRAC10_COMMANDS)


def test_hex_fields_parsed_to_int():
    """NetFn/cmd/subcmd land as ints (or None), not the raw '0x..' strings."""
    from zipmi.scapy_ipmi.oem.idrac10_commands_generated import IDRAC10_COMMANDS
    for c in IDRAC10_COMMANDS:
        assert c.netfn is None or isinstance(c.netfn, int)
        assert c.cmd is None or isinstance(c.cmd, int)
        assert c.subcmd is None or isinstance(c.subcmd, int)
        assert isinstance(c.in_band_only, bool)
    assert all(c.netfn is not None and c.cmd is not None for c in IDRAC10_COMMANDS)


def test_wire_prefixes_preserve_colliding_handlers_and_live_evidence():
    """Alternate handlers at the same pair remain separately addressable."""
    keys = [(c.netfn, c.cmd, c.prefix) for c in IDRAC10_COMMANDS]
    assert len(keys) == len(set(keys)) == 456
    assert {
        (c.name, c.prefix) for c in IDRAC10_COMMANDS
        if (c.netfn, c.cmd) == (0x2c, 0x01)
    } == {
        ("CmdDcmiGetDcmiCapabilityInfo", b"\xdc"),
        ("DellCmdGetMgrCertFingerprint", b"R\x01"),
    }
    assert {
        (c.name, c.prefix) for c in IDRAC10_COMMANDS
        if (c.netfn, c.cmd) == (0x2c, 0x02)
    } == {
        ("CmdDcmiGetPowerReading", b"\xdc"),
        ("DellCmdGetBootstrapCredentials", b"R"),
    }
    assert sum(c.live is not None for c in IDRAC10_COMMANDS) == 445


def test_cli_keeps_every_exact_wire_operation():
    from zipmi.cli.oem_cmds import _vendor_listing

    rows = _vendor_listing("idrac10")
    assert len(rows) == 456
    assert rows[(0x2c, 0x01, 0xdc)]["name"] == "CmdDcmiGetDcmiCapabilityInfo"
    assert rows[(0x2c, 0x01, 0x52, 0x01)]["name"] == "DellCmdGetMgrCertFingerprint"
    assert rows[(0x2c, 0x02, 0xdc)]["name"].startswith("CmdDcmiGetPowerReading")
    assert rows[(0x2c, 0x02, 0x52)]["name"] == "DellCmdGetBootstrapCredentials"
    assert rows[(0x06, 0x33)]["name"].startswith("DellCmdNodeMgrDebugInfo")
    assert sum(row["live"] is not None for row in rows.values()) == 445


def test_unclassified_named_operation_requires_unsafe(capsys):
    from zipmi.cli.oem_cmds import cmd_oem_run

    args = argparse.Namespace(
        cmd_name="DellCmdNodeMgrDebugInfo_06_33", data=[], unsafe=False,
    )
    assert cmd_oem_run(args, "idrac10") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_explicit_prefix_is_sent_once(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, data))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    args = argparse.Namespace(
        cmd_name="DellCmdGetMgrCertFingerprint", data=[], unsafe=True, json=False,
    )
    assert cmd_oem_run(args, "idrac10") == 0
    assert sent == [(0x2c, 0x01, b"R\x01")]


def test_cli_parser_accepts_idrac10_unsafe():
    from zipmi.cli.zipmi import parse_cli

    args = parse_cli([
        "oem", "idrac10", "--unsafe", "DellCmdGetMgrCertFingerprint",
    ])
    assert args.unsafe is True


def test_toolset_and_recreate_contracts_are_selector_exact():
    from zipmi.scapy_ipmi.oem.idrac10 import IDRAC10_COMMANDS, IDRAC10_PAYLOADS

    toolset = [c for c in IDRAC10_COMMANDS if (c.netfn, c.cmd) == (0x30, 0xa7)]
    assert len(toolset) == 9
    assert {c.prefix for c in toolset} == {bytes([selector]) for selector in range(9)}
    assert next(c for c in toolset if c.prefix == b"\x02").effect == "safe"
    assert next(c for c in toolset if c.prefix == b"\x08").effect == "destructive"
    recreate = next(c for c in IDRAC10_COMMANDS if c.name == "CmdOEMRecreateMASER")
    assert recreate.request_length == (2, 2)
    assert recreate.effect == "destructive"
    assert len(IDRAC10_PAYLOADS) == 6

    req_type, resp_type = IDRAC10_PAYLOADS[(0x30, 0xa7, 0x05)]
    request = req_type(version=1, toolset=0, timeout=30, reserved=b"\0\0")
    assert bytes(request) == b"\x05\x01\x00\x1e\x00\x00\x00"
    response = resp_type(b"\x00\x00\x34\x12\x00")
    assert response.marker_handle == 0x1234


def test_safe_exact_toolset_status_runs_without_unsafe(monkeypatch):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, data))
            return 0, b"\x00"

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    args = argparse.Namespace(
        cmd_name="CmdOEMToolSet/GetStatus", data=["1", "3", "0", "0"],
        unsafe=False, json=False,
    )
    assert cmd_oem_run(args, "idrac10") == 0
    assert sent == [(0x30, 0xa7, b"\x02\x01\x03\x00\x00")]


def test_load_vendor_idrac10_registers():
    """load_vendor('idrac10') populates the OEM registry with catalog names."""
    import zipmi
    zipmi.load_vendor("idrac10")
    from zipmi.scapy_ipmi.oem._registry import OEM_CMD_NAMES, ENTERPRISE_IDS
    # Dell / iDRAC9 / iDRAC10 all reuse 674; first-loaded wins the slot.
    assert ENTERPRISE_IDS.get(674) in ("idrac10", "idrac9", "dell")
    assert (0x2c, 0x02) in OEM_CMD_NAMES


def test_lookup_helper():
    """idrac10.lookup(netfn, cmd[, subcmd]) returns the full-doc command(s)."""
    import zipmi
    zipmi.load_vendor("idrac10")
    from zipmi.scapy_ipmi.oem.idrac10 import lookup

    # Bootstrap credentials — netfn 0x2c cmd 0x02, no sub-command byte.
    hits = lookup(0x2c, 0x02)
    names = {c.name for c in hits}
    assert "DellCmdGetBootstrapCredentials" in names
    boot = next(c for c in hits if c.name == "DellCmdGetBootstrapCredentials")
    assert boot.subcmd is None
    assert "Admin" in boot.priv
    assert boot.lib == "libmisccmd"

    # SecureDefaultPassword — netfn 0x30 cmd 0xa5 sub-command 0x04.
    hits = lookup(0x30, 0xa5, 0x04)
    sec = next(c for c in hits
               if "SecureDefaultPassword" in c.name)
    assert sec.netfn == 0x30 and sec.cmd == 0xa5 and sec.subcmd == 0x04

    # AttachPartitions — netfn 0x30 cmd 0xa2 sub-command 0x05.
    hits = lookup(0x30, 0xa2, 0x05)
    att = next(c for c in hits if "AttachPartitions" in c.name)
    assert att.subcmd == 0x05


def test_dispatch_still_loads():
    """The pre-existing dispatch-tuple registration is untouched."""
    from zipmi.scapy_ipmi.oem.idrac10 import IDRAC10_DISPATCH, IDRAC10_CMD_NAMES
    assert len(IDRAC10_DISPATCH) >= 300
    assert len(IDRAC10_CMD_NAMES) >= 100
