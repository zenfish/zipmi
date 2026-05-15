"""
zipmi.parsers.idrac9_dispatch_md — parse iDRAC9 binary dispatch tables.

WHAT     Reads /Volumes/yyy/phd/bmc/idrac9-firmware/idrac9-dispatch-tables.md
         (produced by `dump_dispatch_tables.py` against the iDRAC9 rootfs
         .so libs) and emits a Python module with structured (NetFn, cmd)
         → DispatchEntry mappings. Closes the gap left by `idrac9_md.py`,
         which produced a name-only catalog.
WHY      The upstream `IPMI_COMMAND_ENUMERATION.md` lists handler symbols
         per .so library but no NetFn/cmd bytes — bytes live in the
         binary `G_asOEMIPMIReqeustHandleTable` (and DCMI/OSA siblings).
         Static extraction now exposes 293 (NetFn, cmd, priv) tuples;
         this parser turns them into a generated module zipmi can load.
USAGE    python -m zipmi.parsers.idrac9_dispatch_md \
             > zipmi/scapy_ipmi/oem/idrac9_dispatch_generated.py
SUCCESS  Module imports cleanly; IDRAC9_DISPATCH has 293 entries.
RELATED  /Volumes/yyy/phd/bmc/idrac9-firmware/dump_dispatch_tables.py,
         zipmi/scapy_ipmi/oem/idrac9.py (consumer).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass


@dataclass
class IDrac9DispatchEntry:
    netfn: int
    cmd: int
    priv: int
    flags: int
    handler_addr: int
    handler_symbol: str  # "(runtime-bound)" if unresolved
    table: str           # source table name


# Markdown row example:
# |   8 | 0x06 (App) | 0x0a | 0x02 (User) | 0x83 | 0x44579b3c | `CmdOEMGetCommandSupport` |
_ROW_RE = re.compile(
    r"^\|\s*\d+\s*"
    r"\|\s*0x([0-9a-f]{2})\s*\([^)]+\)\s*"   # NetFn
    r"\|\s*0x([0-9a-f]{2})\s*"                # cmd
    r"\|\s*0x([0-9a-f]{2})\s*\([^)]+\)\s*"   # priv
    r"\|\s*0x([0-9a-f]{2})\s*"                # flags
    r"\|\s*0x([0-9a-f]{8})\s*"                # handler addr
    r"\|\s*`([^`]+)`\s*\|",                    # symbol
    re.IGNORECASE,
)
_TABLE_RE = re.compile(r"^##\s+`([^`]+)`")


def parse_md(text: str) -> list[IDrac9DispatchEntry]:
    out: list[IDrac9DispatchEntry] = []
    table = ""
    for line in text.splitlines():
        m = _TABLE_RE.match(line)
        if m:
            table = m.group(1)
            continue
        m = _ROW_RE.match(line)
        if not m:
            continue
        out.append(IDrac9DispatchEntry(
            netfn=int(m.group(1), 16),
            cmd=int(m.group(2), 16),
            priv=int(m.group(3), 16),
            flags=int(m.group(4), 16),
            handler_addr=int(m.group(5), 16),
            handler_symbol=m.group(6),
            table=table,
        ))
    return out


def emit_module(entries: list[IDrac9DispatchEntry], src: str) -> str:
    lines = [
        '"""',
        "zipmi.scapy_ipmi.oem.idrac9_dispatch_generated — auto-generated.",
        "",
        "DO NOT EDIT BY HAND. Regenerate with:",
        "    python -m zipmi.parsers.idrac9_dispatch_md \\",
        "        > zipmi/scapy_ipmi/oem/idrac9_dispatch_generated.py",
        "",
        f"Source: {src}",
        f"Entries: {len(entries)}",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from dataclasses import dataclass",
        "",
        "@dataclass(frozen=True)",
        "class IDrac9DispatchEntry:",
        "    netfn: int",
        "    cmd: int",
        "    priv: int",
        "    flags: int",
        "    handler_addr: int",
        "    handler_symbol: str",
        "    table: str",
        "",
        "IDRAC9_DISPATCH_ENTRIES: list[IDrac9DispatchEntry] = [",
    ]
    for e in entries:
        lines.append(
            f"    IDrac9DispatchEntry("
            f"netfn=0x{e.netfn:02x}, cmd=0x{e.cmd:02x}, "
            f"priv=0x{e.priv:02x}, flags=0x{e.flags:02x}, "
            f"handler_addr=0x{e.handler_addr:08x}, "
            f"handler_symbol={e.handler_symbol!r}, "
            f"table={e.table!r}),"
        )
    lines.append("]")
    lines.append("")
    lines.append("# (NetFn, cmd) → entry. Last writer wins on duplicate keys.")
    lines.append("IDRAC9_DISPATCH: dict[tuple[int, int], IDrac9DispatchEntry] = {")
    lines.append("    (e.netfn, e.cmd): e for e in IDRAC9_DISPATCH_ENTRIES")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    src = "/Volumes/yyy/phd/bmc/idrac9-firmware/idrac9-dispatch-tables.md"
    if len(args) > 1:
        src = args[1]
    with open(src) as f:
        text = f.read()
    entries = parse_md(text)
    sys.stdout.write(emit_module(entries, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
