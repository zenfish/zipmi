# z-artifact: cd4526e1-d4bc-44f8-9cc1-f7ee89e45088
"""MegaRAC/YAFU generated-document and named-route invariants."""

from __future__ import annotations

from argparse import Namespace
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
import re
import subprocess
import sys

from zipmi.cli.oem_cmds import _cmd_oem_help, _vendor_listing, cmd_oem_run
from zipmi.scapy_ipmi.oem.megarac import MEGARAC_COMMANDS
from zipmi.scapy_ipmi.oem.yafu import YAFU_COMMANDS


ROOT = Path(__file__).parents[2]


def test_generated_megarac_documents_preserve_catalog_boundaries() -> None:
    subprocess.run(
        [sys.executable, "scripts/generate_megarac_reference.py", "--check"],
        cwd=ROOT, check=True,
    )
    reference = (ROOT / "docs/megarac-command-reference.html").read_text()
    table = (ROOT / "docs/megarac-command-table.html").read_text()

    assert len(MEGARAC_COMMANDS) == 95
    assert len(YAFU_COMMANDS) == 42
    assert not set(MEGARAC_COMMANDS) & set(YAFU_COMMANDS)
    assert reference.count('<tr data-search="') == 137
    assert table.count('<tr data-search="') == 137
    assert "137</strong>Unique NetFn/Cmd addresses" in reference
    assert "95</strong>MegaRAC registrations" in table
    assert "42</strong>YAFU family entries" in table
    assert Counter(re.findall(r'data-safety="([^"]+)"', reference)) == {
        "read-only": 57, "state-changing": 37, "sensitive": 22,
        "destructive": 11, "disruptive": 10,
    }
    assert Counter(re.findall(r'data-execution="([^"]+)"', reference)) == {
        "Requires --unsafe": 80, "Allowed by default": 57,
    }
    assert Counter(re.findall(r'data-request="([^"]+)"', reference)) == {
        "Partial": 136, "Unknown": 1,
    }
    assert "MegaRAC 0x30 versus possible 0x3e split remains unresolved" in reference
    assert "YAFU target activation and minimum privilege remain unproved" in reference
    assert "No single target firmware image or hash applies" in reference
    assert 'data-safety="disruptive"' in reference and "AMIRestartWebService" in reference
    assert 'data-safety="sensitive"' in reference and "AMISetRootPassword" in reference
    assert "Operations with captured live requests" in reference
    assert 'data-live="true"' not in reference


def test_megarac_and_yafu_listings_keep_rich_help_and_fail_closed(capsys) -> None:
    megarac = _vendor_listing("megarac")
    yafu = _vendor_listing("yafu")

    assert len(megarac) == 95 and len(yafu) == 42
    redis = megarac[(0x30, 0x2A)]
    assert redis["requires_unsafe"] is True
    assert "Redis command string" in redis["request"]
    assert "unauthed from host KCS" in redis["security"]
    assert redis["src"] == "module: accessredis"
    assert megarac[(0x30, 0x69)]["requires_unsafe"] is False
    assert yafu[(0x32, 0x23)]["requires_unsafe"] is True
    assert yafu[(0x32, 0x30)]["requires_unsafe"] is True
    assert yafu[(0x32, 0x01)]["requires_unsafe"] is False
    assert yafu[(0x32, 0x01)]["priv"] is None

    assert _cmd_oem_help("megarac", "AMIAccessRedisDB") == 0
    help_text = capsys.readouterr().out
    assert "Request:" in help_text and "Response:" in help_text
    assert "Security:" in help_text and "module: accessredis" in help_text
    assert "oem megarac --unsafe AMIAccessRedisDB" in help_text

    args = Namespace(cmd_name="AMISetServiceConf", data=[], unsafe=False, json=True)
    assert cmd_oem_run(args, "megarac") == 2
    assert "add --unsafe" in capsys.readouterr().err
    args = Namespace(cmd_name="WriteFlash", data=[], unsafe=False, json=True)
    assert cmd_oem_run(args, "yafu") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_megarac_and_yafu_safe_and_acknowledged_routes_send(monkeypatch) -> None:
    import zipmi.cli.zipmi as cli

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    for vendor, name, unsafe in (
        ("megarac", "AMIGetServiceConf", False),
        ("megarac", "AMISetServiceConf", True),
        ("yafu", "GetFlashInfo", False),
        ("yafu", "WriteFlash", True),
    ):
        args = Namespace(cmd_name=name, data=[], unsafe=unsafe, json=True)
        assert cmd_oem_run(args, vendor) == 0

    assert sent == [
        (0x30, 0x69, b""), (0x30, 0x6A, b""),
        (0x32, 0x01, b""), (0x32, 0x23, b""),
    ]


def test_cli_parsers_accept_megarac_and_yafu_unsafe() -> None:
    from zipmi.cli.zipmi import parse_cli

    for vendor in ("megarac", "yafu"):
        args = parse_cli(["oem", vendor, "--unsafe", "placeholder"])
        assert args.unsafe is True
