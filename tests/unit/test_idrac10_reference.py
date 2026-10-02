# z-artifact: e692ade3-8750-4316-b829-0504912deff8
"""Generated iDRAC10 shared-reference coverage and execution truth."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def test_idrac10_reference_is_current_and_complete():
    root = Path(__file__).parents[2]
    subprocess.run(
        [sys.executable, "scripts/generate_idrac10_reference.py", "--check"],
        cwd=root, check=True,
    )
    reference = (root / "docs/idrac10-command-reference.html").read_text()

    assert '<link rel="stylesheet" href="assets/oem-command-reference.css">' in reference
    assert "<!-- z-artifact: 2c8c7d99-ac5f-457d-a2cb-30a659cb2a21 generated -->" in reference
    assert "255</strong>Unique NetFn/Cmd addresses" in reference
    assert "581</strong>Documented operations" in reference
    assert "37 / 538 / 6 / 0</strong>Request layout:" in reference
    assert "218 / 322 / 41 / 0</strong>Response layout:" in reference
    assert "96 / 485 / 0</strong>Named operation route:" in reference
    assert "445</strong>Operations with captured live requests" in reference
    assert reference.count('<tr data-search="') == 581
    assert reference.count('data-live="true"') == 445
    assert reference.count('<code class="command">zipmi oem idrac10') == 581
    assert {name: reference.count(f'data-safety="{name}"') for name in (
        "read-only", "sensitive", "state-changing", "disruptive", "destructive", "unknown",
    )} == {
        "read-only": 215,
        "sensitive": 119,
        "state-changing": 162,
        "disruptive": 1,
        "destructive": 15,
        "unknown": 69,
    }


def test_idrac10_reference_preserves_wire_and_execution_boundaries():
    root = Path(__file__).parents[2]
    reference = (root / "docs/idrac10-command-reference.html").read_text()

    assert "zipmi oem idrac10 --unsafe DellCmdGetMgrCertFingerprint" in reference
    assert "2c/01 data 52 01" in reference
    assert "zipmi oem idrac10 DellCmdGetSysInfo01 &lt;4 payload bytes&gt;" in reference
    assert "06/59 selector@1 01" in reference
    assert "zipmi oem idrac10 CmdOEMToolSetGetStatus &lt;4 payload bytes&gt;" in reference
    assert re.search(
        r'data-safety="read-only"[^>]*>.*?<strong>DellCmdNodeMgrDebugInfo</strong>.*?'
        r'zipmi oem idrac10 --unsafe DellCmdNodeMgrDebugInfo_06_33 &lt;payload bytes&gt;',
        reference,
    )
    assert re.search(
        r'data-safety="disruptive"[^>]*>.*?<strong>DellCmdBladeACPowerCycle</strong>',
        reference,
    )
    assert re.search(
        r'data-safety="destructive"[^>]*>.*?<strong>DellRollbackFW</strong>',
        reference,
    )
    assert re.search(
        r'data-safety="destructive"[^>]*>.*?'
        r'<strong>SubCmdHandler/DellBpFwUpdateInterface</strong>',
        reference,
    )
    assert "372c49cf8fc167aaff0acc03925a782698937bddba21cbca57146a7c8d722ca9" in reference
    assert "Root filesystem SHA-256" not in reference
    assert "All 581 catalog records have a recovered NetFn/Cmd identity" in reference
    assert "34 data bytes after completion code" in reference
    assert "35 bytes including completion code" not in reference
    assert "<td class=\"wire\">completion_code</td>" not in reference
    assert "bytes[None]" not in reference
    assert "Cross-target operator note (Supermicro X14 only; not evidence of Dell policy)" in reference
    assert "rejected policy candidate returned misleading completion code 0xC8" in reference
