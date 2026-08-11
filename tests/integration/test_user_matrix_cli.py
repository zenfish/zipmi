"""
test_user_matrix_cli.py — end-to-end wiring for `user-matrix list`.

Drives the real CLI → session → build_matrix → JSON path against a loopback
vbmc. The dell_idrac6 persona does not implement the channel-enumeration
commands, so content is empty here (real content is asserted in
tests/unit/test_user_matrix.py::test_build_matrix_one_channel_two_users);
this proves the whole pipeline runs and emits well-formed JSON.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_user_matrix_json_against_vbmc():
    port = _free_port()
    srv = subprocess.Popen(
        [sys.executable, "-m", "zipmi.cli.zipmi", "vbmc", "serve",
         "--vpersona", "dell_idrac6", "--vport", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        out = subprocess.run(
            [sys.executable, "-m", "zipmi.cli.zipmi", "-H", "127.0.0.1",
             "-p", str(port), "-U", "root", "-P", "calvin",
             "user-matrix", "list", "--json"],
            capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        data = json.loads(out.stdout)                 # must be well-formed JSON
        assert data["target"] == "127.0.0.1"
        assert set(data) >= {"target", "channels", "users", "findings",
                             "max_user_count", "enabled_user_count"}
        assert isinstance(data["channels"], dict)
        assert isinstance(data["users"], dict)
        assert isinstance(data["findings"], list)
    finally:
        srv.terminate()
        srv.wait(timeout=5)


def test_scan_all_json_runs_full_grid():
    """scan all --json emits the user-matrix grid JSON (channels + findings)."""
    port = _free_port()
    srv = subprocess.Popen(
        [sys.executable, "-m", "zipmi.cli.zipmi", "vbmc", "serve",
         "--vpersona", "dell_idrac6", "--vport", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        out = subprocess.run(
            [sys.executable, "-m", "zipmi.cli.zipmi", "-H", "127.0.0.1",
             "-p", str(port), "-U", "root", "-P", "calvin",
             "scan", "all", "--json"],
            capture_output=True, text=True, timeout=30)
        data = json.loads(out.stdout)                 # clean JSON, no text noise
        assert "channels" in data and "findings" in data
        assert isinstance(data["findings"], list)
    finally:
        srv.terminate()
        srv.wait(timeout=5)
