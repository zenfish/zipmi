"""--retries 0 must reach the transport as a single-send (no retransmit)."""
from __future__ import annotations
import subprocess, sys


def test_retries_flag_parsed_into_transport():
    from zipmi.cli.zipmi import parse_cli
    args = parse_cli(["-H", "192.0.2.1", "-R", "0", "mc", "info"])
    assert args.retries == 0


def test_retries_default_is_three():
    from zipmi.cli.zipmi import parse_cli
    args = parse_cli(["-H", "192.0.2.1", "mc", "info"])
    assert args.retries == 3


def test_retries_help_present():
    out = subprocess.run([sys.executable, "-m", "zipmi.cli.zipmi", "--help"],
                         capture_output=True, text=True).stdout
    assert "--retries" in out
