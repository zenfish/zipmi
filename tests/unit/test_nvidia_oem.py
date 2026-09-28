# z-artifact: 930bca74-dd79-4286-80ec-2c559829452d
"""Firmware-bound NVIDIA GB200 OEM contracts, routing, and references."""
from __future__ import annotations

import argparse
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


def test_nvidia_catalog_and_reference_are_closed():
    from zipmi.scapy_ipmi.oem.nvidia import NVIDIA_COMMANDS, NVIDIA_PAYLOADS

    root = Path(__file__).parents[2]
    subprocess.run(
        [sys.executable, "scripts/generate_nvidia_gb200_reference.py", "--check"],
        cwd=root, check=True,
    )
    reference = (root / "docs/nvidia-gb200-command-reference.html").read_text()
    table = (root / "docs/nvidia-gb200-command-table.html").read_text()

    assert len(NVIDIA_COMMANDS) == len(NVIDIA_PAYLOADS) == 8
    assert "8</strong>Unique NetFn/Cmd addresses" in reference
    assert "8</strong>Documented operations" in reference
    assert "8 / 0 / 0 / 0</strong>Request layout:" in reference
    assert "8 / 0 / 0 / 0</strong>Response layout:" in reference
    assert "6 / 2 / 0</strong>Named operation route:" in reference
    assert "1</strong>Operations with captured live requests" in reference
    assert reference.count('<tr data-search="') == 8
    assert reference.count('data-safety="read-only"') == 6
    assert reference.count('data-safety="sensitive"') == 2
    assert reference.count('<summary>Safety details</summary>') == 3
    assert 'id="operation-expand-all"' in reference
    assert "details[data-bulk-disclosure]" in reference
    assert '<p class="muted">No persistent or service effect.</p>' in reference
    assert table.count('<tr data-search="') == 8
    assert "hostusb0" in reference and "looks up usb0" in reference
    assert "Calvin" in reference and "1000" in reference
    assert "44890aba03e8f56f965a46cb872f6c23285610ad" in reference
    assert "Matching analyzed source commit" in reference
    assert "preserves caller-supplied hash bytes 32–63" in reference


def test_nvidia_fixed_codecs_match_wire_contracts():
    import zipmi
    from zipmi.scapy_ipmi.oem._registry import decode_payload_response, lookup_payload

    zipmi.load_vendor("nvidia")
    request, _response = lookup_payload("nvidia", 0x3C, 0x30, b"\x01")
    assert bytes(request(descriptor_type=1)) == b"\x01"
    decoded = decode_payload_response("nvidia", 0x3C, 0x30, b"\x01", 0, b"\x05\x25")
    assert decoded.descriptor == 0x0525

    decoded = decode_payload_response("nvidia", 0x3C, 0x32, b"", 0, b"gb200-bmc")
    assert decoded.hostname == b"gb200-bmc"
    decoded = decode_payload_response("nvidia", 0x3C, 0x34, b"", 0, bytes(range(16)))
    assert decoded.uuid == bytes(range(16))
    decoded = decode_payload_response("nvidia", 0x3C, 0x34, b"", 0, b"\x01\x02")
    assert decoded.uuid == b"\x01\x02"
    decoded = decode_payload_response("nvidia", 0x3C, 0x35, b"", 0, b"\x01\xbb")
    assert decoded.port == 443

    request, _response = lookup_payload("nvidia", 0x3C, 0x37, b"\x01")
    assert bytes(request()) == b"\x01"
    response = bytes([2]) + bytes(range(32)) + bytes(range(64))
    decoded = decode_payload_response("nvidia", 0x3C, 0x37, b"\x01", 0, response)
    assert decoded.password_type == 2
    assert decoded.salt == bytes(range(32))
    assert decoded.password_hash == bytes(range(64))


def test_nvidia_cli_is_bounded_and_fail_closed(monkeypatch, capsys):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, bytes(97)

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    unsafe = argparse.Namespace(
        cmd_name="Get BIOS Password", data=[], unsafe=False, json=False,
    )
    assert cmd_oem_run(unsafe, "nvidia") == 2
    assert "add --unsafe" in capsys.readouterr().err

    allowed = argparse.Namespace(
        cmd_name="Get BIOS Password", data=[], unsafe=True, json=False,
    )
    assert cmd_oem_run(allowed, "nvidia") == 0
    assert sent == [(0x3C, 0x37, b"\x01")]

    wrong_length = argparse.Namespace(
        cmd_name="Get Redfish Service Port", data=["0"], unsafe=False, json=False,
    )
    assert cmd_oem_run(wrong_length, "nvidia") == 2
    assert "requires exactly 0 payload bytes" in capsys.readouterr().err

    help_args = argparse.Namespace(
        cmd_name="Get BIOS Password", data=["help"], unsafe=False, json=False,
    )
    assert cmd_oem_run(help_args, "nvidia") == 0
    assert "oem openbmc-nvidia --unsafe 'Get BIOS Password'" in capsys.readouterr().out

    root = Path(__file__).parents[2]
    parsed = subprocess.run(
        [sys.executable, "-m", "zipmi.cli.zipmi", "oem", "openbmc-nvidia",
         "--unsafe", "Get BIOS Password", "help"],
        cwd=root, capture_output=True, text=True,
    )
    assert parsed.returncode == 0, parsed.stderr
    assert "oem openbmc-nvidia --unsafe 'Get BIOS Password'" in parsed.stdout


def test_nvidia_set_password_requires_exact_remaining_body(monkeypatch, capsys):
    from zipmi.cli import zipmi as cli
    from zipmi.cli.oem_cmds import cmd_oem_run

    args = argparse.Namespace(
        cmd_name="Set BIOS Password", data=["2"], unsafe=True, json=False,
    )
    assert cmd_oem_run(args, "nvidia") == 2
    assert "requires exactly 97 data bytes after the fixed prefix; got 1" in capsys.readouterr().err

    sent = []

    class Session:
        def send_raw(self, netfn, cmd, data):
            sent.append((netfn, cmd, bytes(data)))
            return 0, b""

    @contextmanager
    def fake_open_session(_args):
        yield Session()

    monkeypatch.setattr(cli, "_open_session", fake_open_session)
    body = ["1"] + ["0"] * 96
    args.data = body
    assert cmd_oem_run(args, "nvidia") == 0
    assert sent == [(0x3C, 0x36, b"\x01\x01" + bytes(96))]
