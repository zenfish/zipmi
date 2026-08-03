"""
zipmi.parsers.idrac10_dispatch_md — parse iDRAC10 binary dispatch tables.

WHAT     Reads the iDRAC10 firmware reverse-engineering notes
         (idrac10-dispatch-tables.md, produced by the iDRAC10 dispatch-table
         extraction script against the iDRAC10
         rootfs /usr/lib/ipmi/*.so.9.9.9 libs) and emits a Python module
         with structured (NetFn, cmd) → DispatchEntry mappings. Mirror of
         `idrac9_dispatch_md.py`.
WHY      iDRAC10 (aarch64, PIE) stores each dispatch entry as
         [cmd][netfn][priv][flags][pad][handler-reloc]. Handler pointers
         are dynamic relocations resolved from .dynsym, so the static
         extraction already carries (NetFn, cmd, priv, handler-name).
         Unlike iDRAC9 (which built its master table at runtime), iDRAC10
         ships the +138-entry libipmicmdtableapi master table statically,
         so all names resolve at extraction time. 429 rows total, 383
         unique (NetFn, cmd, handler) triples once cross-lib dupes collapse.
USAGE    python -m zipmi.parsers.idrac10_dispatch_md \
             > zipmi/scapy_ipmi/oem/idrac10_dispatch_generated.py
SUCCESS  Module imports cleanly; IDRAC10_DISPATCH has 383 entries.
RELATED  iDRAC10 firmware reverse-engineering notes (idrac10-dispatch-tables.md),
         zipmi/scapy_ipmi/oem/idrac10.py (consumer),
         zipmi/parsers/idrac9_dispatch_md.py (sibling for iDRAC9).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from dataclasses import dataclass


@dataclass
class IDrac10DispatchEntry:
    netfn: int
    cmd: int
    priv: int
    flags: int
    handler_addr: int
    handler_symbol: str
    table: str           # source .so name


# Markdown row example (handler addr is variable-width, PIE offset):
# | 8 | 0x06 (App) | 0x0a | 0x02 (User) | 0x83 | 0x4e0e0 | `CmdOEMGetCommandSupport` |
_ROW_RE = re.compile(
    r"^\|\s*\d+\s*"
    r"\|\s*0x([0-9a-f]{2})\s*\([^)]+\)\s*"   # NetFn
    r"\|\s*0x([0-9a-f]{2})\s*"                # cmd
    r"\|\s*0x([0-9a-f]{2})\s*\([^)]+\)\s*"   # priv
    r"\|\s*0x([0-9a-f]{2})\s*"                # flags
    r"\|\s*0x([0-9a-f]+)\s*"                  # handler addr (variable width)
    r"\|\s*`([^`]+)`\s*\|",                    # symbol
    re.IGNORECASE,
)
# Section header example:  ## `liboemcmds.so.9.9.9` — 238 entries
_TABLE_RE = re.compile(r"^##\s+`([^`]+)`")


def parse_md(text: str) -> list[IDrac10DispatchEntry]:
    out: list[IDrac10DispatchEntry] = []
    table = ""
    for line in text.splitlines():
        m = _TABLE_RE.match(line)
        if m:
            table = m.group(1)
            continue
        m = _ROW_RE.match(line)
        if not m:
            continue
        out.append(IDrac10DispatchEntry(
            netfn=int(m.group(1), 16),
            cmd=int(m.group(2), 16),
            priv=int(m.group(3), 16),
            flags=int(m.group(4), 16),
            handler_addr=int(m.group(5), 16),
            handler_symbol=m.group(6),
            table=table,
        ))
    return out


def dedupe(entries: list[IDrac10DispatchEntry]) -> list[IDrac10DispatchEntry]:
    """Collapse to unique (netfn, cmd, handler_symbol) triples (first wins).

    Matches the 383-unique count in the source doc's "For diff" list:
    the same (NetFn, cmd, handler) appears in more than one .so (e.g.
    CmdGetChassisCapabilities in both libipmicmdtableapi and libdcmi).
    """
    seen: set[tuple[int, int, str]] = set()
    out: list[IDrac10DispatchEntry] = []
    for e in entries:
        key = (e.netfn, e.cmd, e.handler_symbol)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def emit_module(entries: list[IDrac10DispatchEntry], src: str) -> str:
    uniq = dedupe(entries)
    lines = [
        '"""',
        "zipmi.scapy_ipmi.oem.idrac10_dispatch_generated — auto-generated.",
        "",
        "DO NOT EDIT BY HAND. Regenerate with:",
        "    python -m zipmi.parsers.idrac10_dispatch_md \\",
        "        > zipmi/scapy_ipmi/oem/idrac10_dispatch_generated.py",
        "",
        f"Source: {src}",
        f"Rows parsed: {len(entries)}",
        f"Unique (netfn, cmd, handler): {len(uniq)}",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass",
        "",
        "@dataclass(frozen=True)",
        "class IDrac10DispatchEntry:",
        "    netfn: int",
        "    cmd: int",
        "    priv: int",
        "    flags: int",
        "    handler_addr: int",
        "    handler_symbol: str",
        "    table: str",
        "",
        "# All rows across every dispatch table (with cross-lib duplicates).",
        "IDRAC10_DISPATCH_ALL: list[IDrac10DispatchEntry] = [",
    ]
    for e in entries:
        lines.append(
            f"    IDrac10DispatchEntry("
            f"netfn=0x{e.netfn:02x}, cmd=0x{e.cmd:02x}, "
            f"priv=0x{e.priv:02x}, flags=0x{e.flags:02x}, "
            f"handler_addr=0x{e.handler_addr:x}, "
            f"handler_symbol={e.handler_symbol!r}, "
            f"table={e.table!r}),"
        )
    lines.append("]")
    lines.append("")
    lines.append(
        "# Unique (netfn, cmd, handler_symbol) triples, first-writer wins."
    )
    lines.append("IDRAC10_DISPATCH: list[IDrac10DispatchEntry] = [")
    for e in uniq:
        lines.append(
            f"    IDrac10DispatchEntry("
            f"netfn=0x{e.netfn:02x}, cmd=0x{e.cmd:02x}, "
            f"priv=0x{e.priv:02x}, flags=0x{e.flags:02x}, "
            f"handler_addr=0x{e.handler_addr:x}, "
            f"handler_symbol={e.handler_symbol!r}, "
            f"table={e.table!r}),"
        )
    lines.append("]")
    lines.append("")
    lines.append("# (NetFn, cmd) → entry. Last writer wins on duplicate keys.")
    lines.append("IDRAC10_DISPATCH_BY_KEY: dict[tuple[int, int], IDrac10DispatchEntry] = {")
    lines.append("    (e.netfn, e.cmd): e for e in IDRAC10_DISPATCH")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    src = str(Path(__file__).resolve().parent.parent / "data" / "sources" / "idrac10-dispatch-tables.md")
    if len(args) > 1:
        src = args[1]
    with open(src) as f:
        text = f.read()
    entries = parse_md(text)
    sys.stdout.write(emit_module(entries, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
