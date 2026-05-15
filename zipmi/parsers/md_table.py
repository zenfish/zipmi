"""
zipmi.parsers.md_table — parse Dell fullfw RE markdown dispatch tables.

WHAT     Reads `/Volumes/yyy/phd/bmc/dell/fullfw-ipmi-commands.md` (Dan's
         hand-curated dispatch + live-probe tables, 283 rows) and returns
         structured DispatchEntry records keyed by (netfn, cmd).

WHY      Hand-listing 13 OEM names in oem/dell.py left ~270 documented
         entries unused. Codegen lifts ALL of them into the registry
         in one pass. Subsequent `zipmi raw` / `fuzz sweep` /
         pcap-dissection output gains the named handler + privilege +
         sessionless flag + live-test response shape automatically.

USAGE    Run as a module to regenerate the static output:
             python -m zipmi.parsers.md_table > zipmi/scapy_ipmi/oem/dell_generated.py
         Or import:
             from zipmi.parsers.md_table import parse_md
             entries = parse_md(open("...md").read())

OUTPUT   list[DispatchEntry] — see DispatchEntry dataclass below.

RELATED  zipmi/scapy_ipmi/oem/dell.py (consumes the codegen),
         /Volumes/yyy/phd/bmc/dell/fullfw-ipmi-commands.md (source).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field, asdict


PRIV_MAP = {
    "U":   "Unspecified",
    "CB":  "Callback",
    "Usr": "User",
    "Op":  "Operator",
    "Adm": "Administrator",
    "OEM": "OEM",
    "—":   "Unspecified",
    "":    "Unspecified",
}


@dataclass
class DispatchEntry:
    netfn: int
    cmd: int
    name: str = ""
    priv: str = ""             # raw priv string from doc
    sessionless: bool = False
    handler_addr: int | None = None
    live_status: str = ""      # YES + bytes, NO 0xC1, 0xC7, etc.
    not_present: bool = False  # OEM table: cmd routed but returns 0xC1
    description: str = ""


_RAW_RE = re.compile(r"`raw\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)(?:\s+[^`]*)?`")
_HANDLER_RE = re.compile(r"`0x([0-9a-fA-F]+)`")


def _clean(cell: str) -> str:
    return cell.strip().replace("`", "").replace("**", "")


def _parse_priv(cell: str) -> str:
    s = _clean(cell)
    return PRIV_MAP.get(s, s)


def _parse_sessionless(cell: str) -> bool:
    s = _clean(cell).lower()
    return s.startswith("yes")


def _parse_handler_addr(cell: str) -> int | None:
    m = _HANDLER_RE.search(cell)
    return int(m.group(1), 16) if m else None


def _parse_row(cells: list[str]) -> DispatchEntry | None:
    """Decode one table row into a DispatchEntry, or None if not parseable."""
    if not cells:
        return None
    raw_cell = cells[0]
    m = _RAW_RE.search(raw_cell)
    if not m:
        return None
    netfn = int(m.group(1), 16)
    cmd = int(m.group(2), 16)

    n = len(cells)
    e = DispatchEntry(netfn=netfn, cmd=cmd)

    # Multiple table layouts in this doc; classify by NF + content hints.
    if n == 5:
        # cmd | name | priv | sessionless | desc — App / Standard table
        e.name = _clean(cells[1])
        e.priv = _parse_priv(cells[2])
        e.sessionless = _parse_sessionless(cells[3])
        e.description = _clean(cells[4])
    elif n == 6:
        # cmd | name | priv | sessionless | live | desc
        # OR cmd | response | name | desc (live-probe table)
        # Distinguish by whether cell[2] looks like a privilege code.
        if _clean(cells[2]) in PRIV_MAP:
            e.name = _clean(cells[1])
            e.priv = _parse_priv(cells[2])
            e.sessionless = _parse_sessionless(cells[3])
            e.live_status = _clean(cells[4])
            e.description = _clean(cells[5])
        else:
            # Live probe table: cmd | response | likely-fn | interpretation
            e.live_status = _clean(cells[1])
            e.name = _clean(cells[2])
            e.description = _clean(cells[3])
    elif n == 7:
        # cmd | handler | name | priv | sessionless | live | desc
        # OR Override-table-style: cmd | OEM-handler | std-handler | std-name | desc
        if _clean(cells[3]) in PRIV_MAP:
            e.handler_addr = _parse_handler_addr(cells[1])
            e.name = _clean(cells[2])
            e.priv = _parse_priv(cells[3])
            e.sessionless = _parse_sessionless(cells[4])
            e.live_status = _clean(cells[5])
            e.description = _clean(cells[6])
        else:
            # Override-table row (oem/std handler addrs + std name + reason)
            e.handler_addr = _parse_handler_addr(cells[1])
            e.name = _clean(cells[3])
            e.description = _clean(cells[4]) if len(cells) > 4 else ""
    elif n == 8:
        # cmd | handler | name | priv | sessionless | lan_status | live_present | desc
        e.handler_addr = _parse_handler_addr(cells[1])
        e.name = _clean(cells[2])
        e.priv = _parse_priv(cells[3])
        e.sessionless = _parse_sessionless(cells[4])
        lan = _clean(cells[5])
        e.live_status = lan
        e.not_present = "NOT PRESENT" in _clean(cells[6])
        e.description = _clean(cells[7])
    else:
        # Skip unknown layouts (probably descriptive paragraph rows).
        return None

    return e


def parse_md(text: str) -> list[DispatchEntry]:
    """Parse the doc; return one entry per `raw` table row.

    When the same (netfn, cmd) appears in multiple tables (live probe vs
    dispatch table), the dispatch-table entry wins on name/priv/handler;
    the live-probe entry contributes live_status if present.
    """
    by_key: dict[tuple[int, int], DispatchEntry] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip(" ") for c in line.strip("|\n").split("|")]
        # Strip the row's leading + trailing empty cells produced by the
        # surrounding pipes — already done by .strip("|").
        e = _parse_row(cells)
        if e is None:
            continue
        key = (e.netfn, e.cmd)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = e
            continue
        # Merge: prefer dispatch-table fields (priv set) over live-probe
        # rows (priv unset). Always carry forward whatever live_status we
        # find.
        if not existing.priv and e.priv:
            existing.priv = e.priv
        if existing.handler_addr is None and e.handler_addr is not None:
            existing.handler_addr = e.handler_addr
        if not existing.name or "(" in existing.name:
            existing.name = existing.name or e.name
        if e.live_status and (not existing.live_status
                              or existing.live_status.startswith("?")):
            existing.live_status = e.live_status
        if not existing.description and e.description:
            existing.description = e.description
        if e.not_present:
            existing.not_present = True
    return list(by_key.values())


# -------------------------------------------------------------------------
# Code generation: emit a static Python module the OEM dell.py can import.

def _py_repr(s: str) -> str:
    return repr(s)


def emit_module(entries: list[DispatchEntry], source_path: str) -> str:
    """Build a Python source file declaring DELL_DISPATCH + helpers."""
    lines = []
    lines.append('"""')
    lines.append("zipmi.scapy_ipmi.oem.dell_generated — auto-generated from")
    lines.append("the Dell iDRAC6 fullfw dispatch-table RE.")
    lines.append("")
    lines.append("DO NOT EDIT BY HAND. Regenerate with:")
    lines.append("    python -m zipmi.parsers.md_table > zipmi/scapy_ipmi/oem/dell_generated.py")
    lines.append("")
    lines.append(f"Source: {source_path}")
    lines.append(f"Entries: {len(entries)}")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from dataclasses import dataclass")
    lines.append("")
    lines.append("@dataclass(frozen=True)")
    lines.append("class DellEntry:")
    lines.append("    name: str")
    lines.append("    priv: str")
    lines.append("    sessionless: bool")
    lines.append("    handler_addr: int | None")
    lines.append("    live_status: str")
    lines.append("    not_present: bool")
    lines.append("    description: str")
    lines.append("")
    lines.append("DELL_DISPATCH: dict[tuple[int, int], DellEntry] = {")
    for e in sorted(entries, key=lambda x: (x.netfn, x.cmd)):
        key = f"(0x{e.netfn:02x}, 0x{e.cmd:02x})"
        lines.append(
            f"    {key}: DellEntry("
            f"name={_py_repr(e.name)}, "
            f"priv={_py_repr(e.priv)}, "
            f"sessionless={e.sessionless}, "
            f"handler_addr={e.handler_addr}, "
            f"live_status={_py_repr(e.live_status)}, "
            f"not_present={e.not_present}, "
            f"description={_py_repr(e.description)}),"
        )
    lines.append("}")
    lines.append("")
    lines.append("# Convenience views.")
    lines.append("DELL_NAMES: dict[tuple[int, int], str] = {")
    lines.append("    k: v.name for k, v in DELL_DISPATCH.items() if v.name")
    lines.append("}")
    lines.append("DELL_SESSIONLESS: set[tuple[int, int]] = {")
    lines.append("    k for k, v in DELL_DISPATCH.items() if v.sessionless")
    lines.append("}")
    lines.append("DELL_DISABLED: set[tuple[int, int]] = {")
    lines.append("    k for k, v in DELL_DISPATCH.items() if v.not_present")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


_NETFN_LABELS = {
    0x00: "Chassis",
    0x02: "Bridge",
    0x04: "Sensor / Event",
    0x06: "App",
    0x08: "Firmware",
    0x0A: "Storage",
    0x0C: "Transport",
    0x2C: "Group",
    0x2E: "OEM / Group (extended)",
    0x30: "Dell OEM",
}


def emit_markdown(entries: list[DispatchEntry], source_path: str) -> str:
    """Render the dispatch entries as a docs/dell-command-table.md doc.

    Mirrors the same row schema as docs/command-table.md (Cmd | Name |
    Priv | Sessionless | Live R710 | Notes) so a reader can scan one
    table for the full Dell surface.
    """
    lines = []
    lines.append("# Dell iDRAC6 — full dispatch table")
    lines.append("")
    lines.append("Auto-generated from the Dell fullfw RE. **DO NOT EDIT BY HAND.**")
    lines.append("Regenerate with:")
    lines.append("")
    lines.append("```")
    lines.append("python -m zipmi.parsers.md_table --markdown > docs/dell-command-table.md")
    lines.append("```")
    lines.append("")
    lines.append(f"Source: `{source_path}`  ")
    lines.append(f"Entries: **{len(entries)}** unique (NetFn, cmd) pairs")
    lines.append("")

    # Group by NetFn.
    by_nf: dict[int, list[DispatchEntry]] = {}
    for e in entries:
        by_nf.setdefault(e.netfn, []).append(e)

    # Top-level summary.
    lines.append("## Summary")
    lines.append("")
    lines.append("| NetFn | Group | Entries | Sessionless | Stubbed |")
    lines.append("|------|-------|---------|-------------|---------|")
    for nf in sorted(by_nf):
        rows = by_nf[nf]
        sl = sum(1 for r in rows if r.sessionless)
        st = sum(1 for r in rows if r.not_present)
        label = _NETFN_LABELS.get(nf, "")
        lines.append(f"| 0x{nf:02x} | {label} | {len(rows)} | {sl} | {st} |")
    lines.append(f"| | **Total** | **{len(entries)}** | "
                 f"**{sum(1 for r in entries if r.sessionless)}** | "
                 f"**{sum(1 for r in entries if r.not_present)}** |")
    lines.append("")

    # Per-NetFn detail.
    for nf in sorted(by_nf):
        label = _NETFN_LABELS.get(nf, "")
        lines.append(f"## NetFn 0x{nf:02x} — {label}")
        lines.append("")
        lines.append("| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |")
        lines.append("|-----|------|------|-------------|---------|-------------|---------|-------|")
        for e in sorted(by_nf[nf], key=lambda x: x.cmd):
            sl = "✓" if e.sessionless else ""
            stub = "✗ stubbed" if e.not_present else ""
            handler = f"`0x{e.handler_addr:08x}`" if e.handler_addr else ""
            live = e.live_status.replace("|", "\\|")[:50]
            desc = e.description.replace("|", "\\|")[:80]
            name = e.name.replace("|", "\\|")
            lines.append(
                f"| 0x{e.cmd:02x} | {name} | {e.priv} | {sl} | {stub} | "
                f"{live} | {handler} | {desc} |"
            )
        lines.append("")

    lines.append("## Legend")
    lines.append("")
    lines.append("- **Priv**: minimum privilege per dispatch table — Callback, User, Operator, "
                 "Administrator, OEM, or Unspecified.")
    lines.append("- **Sessionless**: cmd is reachable before opening an IPMI session "
                 "(bit 7 of the dispatch descriptor byte).")
    lines.append("- **Stubbed**: dispatch table override redirects this cmd to a "
                 "shared 0xC1-returning stub. Functionally disabled on Dell.")
    lines.append("- **Live (R710)**: response observed against Dell PowerEdge R710 / "
                 "iDRAC6 1.70, 192.168.0.23 (probed 2026-04-06 and beyond).")
    lines.append("- **Handler**: ARM little-endian address inside fullfw binary; useful "
                 "for Ghidra cross-reference.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv)
    src = "/Volumes/yyy/phd/bmc/dell/fullfw-ipmi-commands.md"
    fmt = "py"
    if "--markdown" in args:
        fmt = "md"
        args.remove("--markdown")
    if len(args) > 1:
        src = args[1]
    with open(src) as f:
        text = f.read()
    entries = parse_md(text)
    if fmt == "md":
        sys.stdout.write(emit_markdown(entries, src))
    else:
        sys.stdout.write(emit_module(entries, src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
