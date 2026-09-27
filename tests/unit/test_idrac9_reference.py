# z-artifact: bd4d1335-9087-4a4f-916b-191282a3dcad
"""Generated iDRAC9 operation-reference and dispatch-table coverage."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_idrac9_generated_documents_are_current_and_complete():
    subprocess.run(
        [sys.executable, "scripts/generate_idrac9_reference.py", "--check"],
        cwd=ROOT,
        check=True,
    )
    reference = (ROOT / "docs/idrac9-command-reference.html").read_text()
    table = (ROOT / "docs/idrac9-command-table.html").read_text()

    assert '<link rel="stylesheet" href="assets/oem-command-reference.css">' in reference
    assert "<!-- z-artifact: 99f51650-f4a9-460d-90b9-58f7c4131e8a generated -->" in reference
    assert "58</strong>Unique NetFn/Cmd addresses" in reference
    assert "276</strong>Documented operations" in reference
    assert "0 / 233 / 43 / 0</strong>Request layout:" in reference
    assert "0 / 233 / 43 / 0</strong>Response layout:" in reference
    assert "0 / 276 / 0</strong>Named operation route:" in reference
    assert "276</strong>Operations with captured live requests" in reference
    assert reference.count('<tr data-search="') == 276
    assert reference.count('data-request="Unknown"') == 43
    assert reference.count('data-response="Unknown"') == 43
    assert reference.count("ABSENT; host 10.0.9.9") == 9
    assert {name: reference.count(f'data-safety="{name}"') for name in (
        "read-only", "sensitive", "state-changing", "disruptive", "destructive", "unknown",
    )} == {
        "read-only": 119,
        "sensitive": 9,
        "state-changing": 93,
        "disruptive": 8,
        "destructive": 12,
        "unknown": 35,
    }

    assert '<link rel="stylesheet" href="assets/oem-command-reference.css">' in table
    assert "<!-- z-artifact: a897957a-00f7-4aff-953b-87f237c9544b generated -->" in table
    assert "293</strong>Registration rows" in table
    assert "271</strong>Unique NetFn/Cmd identities" in table
    assert "239</strong>Runtime-bound registrations" in table
    assert "73</strong>Runtime-bound symbols unresolved" in table
    assert table.count('<tr data-search="') == 293
    assert table.count('<code class="nowrap">0x06 / 0x42</code>') == 3
    assert table.count(
        "<td>Static registration; runtime-bound; handler symbol unresolved</td>"
    ) == 73


def test_idrac9_reference_preserves_wire_and_provenance_truth():
    reference = (ROOT / "docs/idrac9-command-reference.html").read_text()
    table = (ROOT / "docs/idrac9-command-table.html").read_text()

    assert "zipmi oem idrac9 --unsafe DellCmdGetSysInfo0x01" in reference
    assert "06/59 data 01" in reference
    assert re.search(
        r'data-safety="read-only"[^>]*>(?:(?!</tr>).)*'
        r'<strong>DellCmdGetPowerCycleInterval</strong>',
        reference,
    )
    assert "43 contracts retain undetermined request and response layouts" in reference
    assert "293 firmware registrations and 271 unique NetFn/Cmd identities" in reference
    assert "libosa.so.9.9.9" in table
    assert "handler address 0x" in table
    assert "flags 0x" in table


def test_idrac9_named_routes_require_explicit_unsafe(capsys):
    from zipmi.cli.oem_cmds import _vendor_listing, cmd_oem_run

    listing = _vendor_listing("idrac9")
    assert len(listing) == 632
    assert all(row["requires_unsafe"] for row in listing.values())

    args = argparse.Namespace(
        cmd_name="DellCmdGetSysInfo0x01", data=[], unsafe=False,
    )
    assert cmd_oem_run(args, "idrac9") == 2
    assert "add --unsafe" in capsys.readouterr().err


def test_cli_parser_accepts_idrac9_unsafe():
    from zipmi.cli.zipmi import parse_cli

    args = parse_cli(["oem", "idrac9", "--unsafe", "DellCmdGetSysInfo0x01"])
    assert args.unsafe is True
