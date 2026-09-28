# z-artifact: 8382c3ef-b17b-4d90-8cc1-5886c8c23fa2
"""Compact OEM firmware-identity table generation invariants."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).parents[2]


class IdentityRows(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_body = False
        self.rows = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "tbody" and attributes.get("id") == "identity-rows":
            self.in_body = True
        elif self.in_body and tag == "tr":
            self.rows += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "tbody" and self.in_body:
            self.in_body = False


def page(name: str) -> str:
    return (ROOT / "docs" / name).read_text()


def row_count(document: str) -> int:
    parser = IdentityRows()
    parser.feed(document)
    return parser.rows


def test_compact_command_tables_are_generated_and_searchable() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from oem_disclosure import DISCLOSURE_BYTES, field

    assert DISCLOSURE_BYTES == 80
    assert "data-bulk-disclosure" not in field("é" * 40)
    assert 'data-bulk-disclosure><summary>Show full value</summary><span>' in field("é" * 41)
    assert "&lt;" in field("<" * 81)
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_oem_command_tables.py"), "--check"],
        cwd=ROOT, check=True,
    )
    for name in (
        "advantech-asmb787-command-table.html",
        "lenovo-xcc-command-table.html",
        "fujitsu-irmc-s6-command-table.html",
        "idrac10-command-table.html",
        "idrac9-command-table.html",
        "ieit-nf5468m6-command-table.html",
        "megarac-command-table.html",
        "nvidia-gb200-command-table.html",
    ):
        document = page(name)
        assert '<link rel="stylesheet" href="assets/oem-command-reference.css">' in document
        assert 'id="identity-filter"' in document
        assert ('id="identity-expand-all" class="expand-all" type="button" '
                'aria-controls="identity-rows" aria-expanded="false" disabled'
                in document)
        assert "row=>!row.hidden" in document
        assert "details[data-bulk-disclosure]" in document
        assert "expandAllUpdatePending" in document
        assert 'id="identity-scrollbar"' in document
        assert "updateFloatingScrollbar" in document
        assert "document.createTreeWalker" in document
        assert "details.dataset.searchOpened" in document
        assert ("<th>#</th><th>NetFn / Cmd</th><th>Prefix / LUN</th><th>Handler</th>"
                in document)


def test_advantech_table_preserves_corrected_dispatch_denominator() -> None:
    document = page("advantech-asmb787-command-table.html")
    assert row_count(document) == 187
    assert "187</strong>Registration rows" in document
    assert "187</strong>Unique NetFn/Cmd identities" in document
    assert "0x32 / 0x66" in document and "AMIRestoreDefaults" in document
    assert "statically registered in owning dispatcher table" in document


def test_lenovo_table_preserves_prefix_qualified_duplicate_identities() -> None:
    document = page("lenovo-xcc-command-table.html")
    assert row_count(document) == 225
    assert "225</strong>Registration rows" in document
    assert "210</strong>Unique NetFn/Cmd identities" in document
    assert "0x5e 0x2b 0x00" in document
    assert "cpp_registration" in document and "legacy_admission_only" in document


def test_fujitsu_table_preserves_lun_and_registration_denominators() -> None:
    document = page("fujitsu-irmc-s6-command-table.html")
    assert row_count(document) == 148
    assert "148</strong>Registration rows" in document
    assert "138</strong>Unique NetFn/Cmd/LUN identities" in document
    assert document.count("LUN 3") >= 3
    assert "wire LUN 3" in document


def test_idrac10_table_preserves_cross_library_registrations() -> None:
    document = page("idrac10-command-table.html")
    assert row_count(document) == 429
    assert "429</strong>Registration rows" in document
    assert "346</strong>Unique NetFn/Cmd identities" in document
    assert "383</strong>Unique NetFn/Cmd/handler identities" in document
    assert document.count("0x2c / 0x01") >= 2
    assert "DellCmdGetMgrCertFingerprint" in document
    assert "CmdDcmiGetDcmiCapabilityInfo" in document
    assert "Not decoded from the 16-byte dispatch record" in document
