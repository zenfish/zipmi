"""
zipmi.parsers.idrac9_md — parse iDRAC9 IPMI command enumeration markdown.

WHAT     Reads the iDRAC9 firmware reverse-engineering notes
         (IPMI_COMMAND_ENUMERATION.md)
         and extracts the per-section (cmd-name, handler, library) tuples.
         The doc lists handler names without cmd byte codes — codes have
         to be inferred from cmd names where the standard spec maps them.

WHY      iDRAC9 ships ~60 IPMI .so libraries with hundreds of handlers.
         The RE doc is the most-complete inventory we have. Without
         ingesting it, zipmi has zero awareness of any iDRAC9 OEM cmd
         (which is a separate code base from iDRAC6 — both 0x30 NetFn
         but different sub-cmd surface).

USAGE    python -m zipmi.parsers.idrac9_md  # emits Python module

OUTPUT   IDRAC9_HANDLERS list of (section, library, cmd_name, handler).

NOTES    The source doc carries no NetFn/cmd code per row, so we cannot
         populate the (NetFn, cmd) registry the way the iDRAC6 codegen
         does. Instead we expose IDRAC9_HANDLERS as a section-grouped
         catalog usable for cross-reference (e.g. when fuzzing iDRAC9
         and seeing a handler name in a crash trace).

RELATED  zipmi/scapy_ipmi/oem/idrac9_generated.py (output),
         zipmi/scapy_ipmi/oem/idrac9.py (consumer).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from dataclasses import dataclass


@dataclass
class IDrac9Handler:
    section: str
    library: str
    cmd_name: str
    handler: str
    notes: str = ""


_SECTION_RE = re.compile(r"^###\s+(?:⚠️\s+)?(.+?)\s*$")
_LIB_RE = re.compile(r"`(lib[A-Za-z0-9_]+\.so(?:\.\d+\.\d+\.\d+)?)`")


def parse_md(text: str) -> list[IDrac9Handler]:
    out: list[IDrac9Handler] = []
    section = ""
    library = ""
    in_table = False
    for line in text.splitlines():
        line = line.rstrip()
        # Section header.
        m = _SECTION_RE.match(line)
        if m:
            full = m.group(1)
            # Library hint embedded in section header: "Foo (NetFn 0xNN) — `libbar.so`"
            mlib = _LIB_RE.search(full)
            library = mlib.group(1) if mlib else ""
            section = re.sub(r"\s*—.*$", "", full).strip()
            section = re.sub(r"\s*\(NetFn[^)]*\)", "", section).strip()
            in_table = False
            continue
        if line.startswith("|---"):
            in_table = True
            continue
        if in_table and line.startswith("|"):
            cells = [c.strip(" *") for c in line.strip("|").split("|")]
            cells = [c.replace("**", "") for c in cells]
            if len(cells) < 2:
                continue
            cmd_name = cells[0]
            if not cmd_name or cmd_name.lower().startswith("command"):
                continue
            handler = cells[1] if len(cells) > 1 else ""
            notes = cells[2] if len(cells) > 2 else ""
            if not handler.startswith("Cmd"):
                # Skip header "Handler" rows or notes-only lines.
                continue
            out.append(IDrac9Handler(
                section=section, library=library,
                cmd_name=cmd_name, handler=handler, notes=notes,
            ))
        elif not line.startswith("|"):
            in_table = False
    return out


def emit_module(handlers: list[IDrac9Handler], src: str) -> str:
    lines = [
        '"""',
        "zipmi.scapy_ipmi.oem.idrac9_generated — auto-generated handler catalog.",
        "",
        "DO NOT EDIT BY HAND. Regenerate with:",
        "    python -m zipmi.parsers.idrac9_md > zipmi/scapy_ipmi/oem/idrac9_generated.py",
        "",
        f"Source: {src}",
        f"Entries: {len(handlers)}",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass",
        "",
        "@dataclass(frozen=True)",
        "class IDrac9Handler:",
        "    section: str",
        "    library: str",
        "    cmd_name: str",
        "    handler: str",
        "    notes: str",
        "",
        "IDRAC9_HANDLERS: list[IDrac9Handler] = [",
    ]
    for h in handlers:
        lines.append(
            f"    IDrac9Handler("
            f"section={h.section!r}, library={h.library!r}, "
            f"cmd_name={h.cmd_name!r}, handler={h.handler!r}, "
            f"notes={h.notes!r}),"
        )
    lines.append("]")
    lines.append("")
    lines.append("# Quick-lookup dicts.")
    lines.append("HANDLERS_BY_NAME: dict[str, IDrac9Handler] = {h.handler: h for h in IDRAC9_HANDLERS}")
    lines.append("HANDLERS_BY_LIBRARY: dict[str, list[IDrac9Handler]] = {}")
    lines.append("for _h in IDRAC9_HANDLERS:")
    lines.append("    HANDLERS_BY_LIBRARY.setdefault(_h.library or '(none)', []).append(_h)")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    src = str(Path(__file__).resolve().parent.parent / "data" / "sources" / "IPMI_COMMAND_ENUMERATION.md")
    if len(args) > 1:
        src = args[1]
    with open(src) as f:
        text = f.read()
    handlers = parse_md(text)
    sys.stdout.write(emit_module(handlers, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
