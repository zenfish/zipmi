#!/usr/bin/env python3
# what: regenerate documented OEM command-counts from the live registry.
# why: the count drifts as OEM dispatch tables grow; hardcoding it rots (same
#      trap the `zipmi oem` vendor blurbs fell into). Compute it, don't type it.
# success: exit 0; every OEM-COUNT marker updated. Non-zero on error.
# run: python scripts/update_readme_stats.py   (or `make readme-stats`)
# related: zipmi.cli.oem_cmds.oem_command_totals, scripts/check_doc_sync.py
"""Rewrite <!--OEM-COUNT-->N<!--/OEM-COUNT--> markers in user-facing docs with the
live `known` OEM-command total — every discovered dispatch slot (idrac9 counted
by all 349 known slots, incl. the 72 nameless runtime-bound ones). Computed by
zipmi.cli.oem_cmds.oem_command_totals(), the same code path behind `zipmi oem`,
so the README can never diverge from the tool."""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = (ROOT / "README.md", ROOT / "docs/command-table.md")
MARKER = re.compile(r"(<!--OEM-COUNT-->)(\d+)(<!--/OEM-COUNT-->)")
NAMED_MARKER = re.compile(
    r"(<!--OEM-NAMED-COUNT-->)(\d+)(<!--/OEM-NAMED-COUNT-->)"
)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from zipmi.cli.oem_cmds import oem_command_totals

    known, named = oem_command_totals()
    changed = []
    for path in TARGETS:
        text = path.read_text()
        if not MARKER.search(text):
            print(f"update_readme_stats: OEM-COUNT marker not found in {path.relative_to(ROOT)}",
                  file=sys.stderr)
            return 1
        updated = MARKER.sub(rf"\g<1>{known}\g<3>", text)
        updated = NAMED_MARKER.sub(rf"\g<1>{named}\g<3>", updated)
        if updated != text:
            path.write_text(updated)
            changed.append(str(path.relative_to(ROOT)))
    detail = f"updated {', '.join(changed)}" if changed else "already current"
    print(f"update_readme_stats: {detail} ({known})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
