#!/usr/bin/env python3
# what: regenerate the OEM command-count in README.md from the live registry.
# why: the count drifts as OEM dispatch tables grow; hardcoding it rots (same
#      trap the `zipmi oem` vendor blurbs fell into). Compute it, don't type it.
# success: exit 0; README marker updated (or already current). Non-zero on error.
# run: python scripts/update_readme_stats.py   (or `make readme-stats`)
# related: zipmi.cli.oem_cmds.oem_command_totals, scripts/check_doc_sync.py
"""Rewrite the <!--OEM-COUNT-->N<!--/OEM-COUNT--> marker in README.md with the
live `known` OEM-command total — every discovered dispatch slot (idrac9 counted
by all 349 known slots, incl. the 72 nameless runtime-bound ones). Computed by
zipmi.cli.oem_cmds.oem_command_totals(), the same code path behind `zipmi oem`,
so the README can never diverge from the tool."""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
MARKER = re.compile(r"(<!--OEM-COUNT-->)(\d+)(<!--/OEM-COUNT-->)")


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from zipmi.cli.oem_cmds import oem_command_totals

    known, _named = oem_command_totals()
    text = README.read_text()
    m = MARKER.search(text)
    if not m:
        print("update_readme_stats: OEM-COUNT marker not found in README.md",
              file=sys.stderr)
        return 1
    old = m.group(2)
    if old == str(known):
        print(f"update_readme_stats: already current ({known})")
        return 0
    README.write_text(MARKER.sub(rf"\g<1>{known}\g<3>", text))
    print(f"update_readme_stats: {old} -> {known}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
