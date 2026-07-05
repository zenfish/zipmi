"""
zipmi.scapy_ipmi.oem.idrac10 — Dell iDRAC10 OEM command registration.

WHAT     Loads the iDRAC10 dispatch tables (recovered from rootfs
         /usr/lib/ipmi/*.so.9.9.9 ELF libs) and registers
         (NetFn, cmd) → name into the OEM registry. Activates via
         `zipmi.load_vendor("idrac10")`.
WHY      iDRAC10 ships its full IPMI command surface as static dispatch
         tables (unlike iDRAC9, whose master table was built at runtime),
         so every handler symbol resolves from .dynsym at extraction time.
         Names are derived directly from the Dell `Cmd*` / `Dell*` handler
         symbols — there is no separate name catalog to cross-reference.
SUCCESS  After load_vendor("idrac10"), OEM_CMD_NAMES gains ≥ 300 entries.
TARGET   iDRAC10 firmware 1.30.10.50 (aarch64), Dell IANA 674.
RELATED  zipmi/parsers/idrac10_dispatch_md.py (codegen),
         /Volumes/yyy/phd/bmc/dell/idrac10-virtual/idrac10-dispatch-tables.md.
"""
from __future__ import annotations

from ._registry import OEM_CMD_NAMES, register
from .idrac10_commands_generated import IDRAC10_COMMANDS, IDrac10Command
from .idrac10_dispatch_generated import IDRAC10_DISPATCH, IDrac10DispatchEntry

DELL_IANA = 674  # iDRAC10 reuses Dell's IANA Enterprise Number

# Handler symbols that carry no per-command meaning (shared trampolines /
# stubs). Skipping them keeps a generic wrapper from clobbering a more
# specific name another vendor registered for the same (NetFn, cmd).
_GENERIC_HANDLERS = {
    "DellDCSSCBMCWrapper",
    "DellNMCommand",
    "SubCmdHandler",
    "NotSupportRequestHandle",
    "FileObjCmdHandler",
    "CmdOSAOEMCmdHandler",
}


def _humanize_handler(sym: str) -> str:
    """Strip 'Cmd' / 'OEM' / 'Dell' prefixes and space out CamelCase."""
    name = sym
    for prefix in ("DellCmdOEM", "CmdOEM", "OEMCmd", "DellCmd", "DellOEMCmd",
                   "Dell", "Cmd", "OEM"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    out = []
    for i, c in enumerate(name):
        if c.isupper() and i and not name[i - 1].isupper():
            out.append(" ")
        out.append(c)
    return "".join(out).strip()


def _resolve_name(e: IDrac10DispatchEntry) -> str | None:
    """Human name for a specific handler; None for generic trampolines."""
    sym = e.handler_symbol
    if not sym or sym in _GENERIC_HANDLERS:
        return None
    return f"iDRAC10 {_humanize_handler(sym)}"


# (NetFn, cmd) → name. First specific handler wins; generics are skipped.
IDRAC10_CMD_NAMES: dict[tuple[int, int], str] = {}
for _e in IDRAC10_DISPATCH:
    _name = _resolve_name(_e)
    if _name is not None:
        IDRAC10_CMD_NAMES.setdefault((_e.netfn, _e.cmd), _name)

# (NetFn, cmd) → privilege level required (0=None..5=OEM). Last writer wins.
IDRAC10_PRIV: dict[tuple[int, int], int] = {
    (e.netfn, e.cmd): e.priv for e in IDRAC10_DISPATCH
}


# --- Rich per-command catalog (idrac10-commands.json, 447 entries) ----------
# The dispatch tables above name the wire surface; the catalog adds the
# human doc (purpose/request/response/security). Entries with an
# undetermined NetFn or cmd (RE couldn't pin them) are kept in the flat
# IDRAC10_COMMANDS list but skipped from the (NetFn, cmd) indexes below.

# (NetFn, cmd) → list of catalog commands. Several commands share a
# (NetFn, cmd) and differ only by sub-command byte, so this maps to a list.
IDRAC10_COMMANDS_BY_KEY: dict[tuple[int, int], list[IDrac10Command]] = {}
for _c in IDRAC10_COMMANDS:
    if _c.netfn is None or _c.cmd is None:
        continue
    IDRAC10_COMMANDS_BY_KEY.setdefault((_c.netfn, _c.cmd), []).append(_c)

# (NetFn, cmd) → catalog name. First-writer-wins on sub-command collisions.
IDRAC10_COMMAND_NAMES: dict[tuple[int, int], str] = {}
for _c in IDRAC10_COMMANDS:
    if _c.netfn is None or _c.cmd is None:
        continue
    IDRAC10_COMMAND_NAMES.setdefault((_c.netfn, _c.cmd), f"iDRAC10 {_c.name}")

# Names to register: the rich catalog name wins over the generic dispatch
# name for iDRAC10's own slots. But never clobber a (NetFn, cmd) another
# vendor already claimed with a specific name — Dell/iDRAC6/iDRAC9 all reuse
# IANA 674 and genuinely share wire slots (e.g. NetFn 0x30 cmd 0xC0 is
# iDRAC6 PROCHOTThrottle but iDRAC10 DellPwrEfficiency). First vendor to
# name a slot keeps it, matching the documented iDRAC9 non-clobber rule.
_claimed = set(OEM_CMD_NAMES)
_IDRAC10_NAMES = {**IDRAC10_CMD_NAMES, **IDRAC10_COMMAND_NAMES}
register("idrac10", DELL_IANA,
         {k: v for k, v in _IDRAC10_NAMES.items() if k not in _claimed})


def lookup(netfn: int, cmd: int,
           subcmd: int | None = None) -> list[IDrac10Command]:
    """Full-doc lookup for a wire (NetFn, cmd[, subcmd]).

    Returns every catalog command at that (NetFn, cmd). When `subcmd` is
    given, narrows to commands whose sub-command matches (a command with no
    sub-command byte, subcmd=None, always matches so the base handler is
    still returned). Empty list = not in the catalog.
    """
    hits = IDRAC10_COMMANDS_BY_KEY.get((netfn, cmd), [])
    if subcmd is None:
        return list(hits)
    return [c for c in hits if c.subcmd == subcmd or c.subcmd is None]


__all__ = [
    "DELL_IANA",
    "IDRAC10_CMD_NAMES",
    "IDRAC10_COMMANDS",
    "IDRAC10_COMMANDS_BY_KEY",
    "IDRAC10_COMMAND_NAMES",
    "IDRAC10_DISPATCH",
    "IDRAC10_PRIV",
    "IDrac10Command",
    "lookup",
]
