"""
zipmi.cli.oem_cmds — `zipmi oem <vendor> [cmd-name [data ...]]` dispatcher.

WHAT     Vendors are reached through the `oem` verb only (no top-level
         per-vendor shortcuts — they crowded the top-level --help):
           * `zipmi oem`                        — list available vendors
           * `zipmi oem <vendor>`               — list vendor's OEM cmds
           * `zipmi oem <vendor> <name> [data]` — run cmd by name
         OpenBMC flavors are namespaced `openbmc-<v>` (e.g. `zipmi oem openbmc-intel`).

WHY      `zipmi raw 0x30 0xC0 0x00` works but nobody remembers the hex.
         Most reverse-engineered command catalogues in this tree carry a
         human name (`CmdGetExtendedConfigure`, `Dell PROCHOTThrottle`,
         `Supermicro UtilRestoreConfig`). Letting the user type that
         name is friendlier and self-documenting; without arguments,
         each vendor verb prints its catalogue so you can browse.

SUCCESS  `zipmi -H 192.168.0.23 oem idrac6 GetChassisStatus` runs the cmd and
         prints the response bytes. `zipmi oem idrac6` (no host needed) prints
         the catalogue.

RELATED  zipmi.scapy_ipmi.oem.{dell,idrac9,supermicro}
         (vendor name dicts), zipmi/__init__.py:load_vendor,
         zipmi.cli.zipmi:_open_session
"""
from __future__ import annotations

import argparse
import re
import sys

from .. import _msg
from ..scapy_ipmi.commands import COMP_CODE


def emit(args, data):
    # Lazy import: pulling zipmi.cli.zipmi at module load eagerly loads extra
    # OEM vendor tables, polluting the shared registry (breaks test_oem).
    from .zipmi import emit as _emit
    return _emit(args, data)


# Vendor manifest. Add a key here to surface a new vendor on the CLI.
# `blurb` is a one-line description; cmd counts come from _vendor_stats()
# at print time so listing and catalogue can never drift apart.
VENDORS: dict[str, dict] = {
    "idrac6": {
        "iana": 674,
        "blurb": "Dell PowerEdge / iDRAC6 (RE'd from iDRAC6 fullfw)",
    },
    "idrac9": {
        "iana": 674,
        "blurb": "Dell iDRAC9 (dispatch tables + RE'd catalog, 276 cmds, IANA 674)",
    },
    "idrac10": {
        "iana": 674,
        "blurb": "Dell iDRAC10 (RE'd + verified catalog, 447 cmds, IANA 674)",
    },
    "supermicro-x11": {
        "iana": 10876,
        "blurb": "Supermicro X11 (AMI+smcipmitool stack) — top-level + sub-cmd dispatch via 1st data byte",
    },
    "supermicro-x14": {
        # AST2600 Phosphor OpenBMC + SMC OEM patches; raw NetFn 0x30 + DMTF
        # group-ext (no IANA on wire) → None. Distinct stack from X11.
        "iana": None,
        "blurb": "Supermicro X14 (AST2600 OpenBMC + SMC OEM) — NetFn 0x30 + DMTF group 0x52/0xDC",
    },
    "megarac": {
        # AMI PEN 20974, but rides raw NetFn 0x30 (no IANA on wire) → None.
        # No `cmd_names` key: proprietary top-level vendor, own _vendor_listing
        # branch. 95 opcode-resolved cmds (static RE of the .so registration tables).
        "iana": None,
        "blurb": "AMI MegaRAC SP-X (HPE/Cray XD670 et al) — NetFn 0x30, 95 RE'd OEM cmds",
    },
    # --- OpenBMC vendor flavors (open source; see oem/openbmc.py manifest) ---
    # All registered via the simple register(vendor, iana, {(netfn,cmd):name})
    # pattern, so `cmd_names` points the generic listing branch at the module's
    # name table. Adding a new OpenBMC vendor = one oem/<v>.py + one row here.
    "intel": {
        "iana": 343, "cmd_names": ("intel", "INTEL_CMD_NAMES"),
        "blurb": "Intel server boards — NetFn 0x30/0x32/0x3E + fw 0x08 (provider: intel-ipmi-oem)",
    },
    "facebook": {
        "iana": 40981, "cmd_names": ("facebook", "FACEBOOK_CMD_NAMES"),
        "blurb": "Facebook/Meta sleds — NetFn 0x30/0x36/0x38 + Bridge-IC (provider: fb-ipmi-oem)",
    },
    "google": {
        "iana": 11129, "cmd_names": ("google", "GOOGLE_CMD_NAMES"),
        "blurb": "Google — NetFn 0x2E IANA envelope + sub-cmds (provider: google-ipmi-sys)",
    },
    "ampere": {
        "iana": None, "cmd_names": ("ampere", "AMPERE_CMD_NAMES"),
        "blurb": "Ampere Altra (ARM) — NetFn 0x3C (provider: ampere-ipmi-oem)",
    },
    "openpower": {
        "iana": 2, "cmd_names": ("openpower", "OPENPOWER_CMD_NAMES"),
        "blurb": "IBM/OpenPOWER — NetFn 0x32/0x3A (provider: openpower-host-ipmi-oem)",
    },
    "inspur": {
        "iana": 37945, "cmd_names": ("inspur", "INSPUR_CMD_NAMES"),
        "blurb": "Inspur — NetFn 0x3C (provider: inspur-ipmi-oem)",
    },
    "foxconn": {
        "iana": None, "cmd_names": ("foxconn", "FOXCONN_CMD_NAMES"),
        "blurb": "Foxconn/fii — NetFn 0x34 (provider: foxconn-ipmi-oem)",
    },
    "wistron": {
        "iana": None, "cmd_names": ("wistron", "WISTRON_CMD_NAMES"),
        "blurb": "Wistron — NetFn 0x32 (provider: wistron-ipmi-oem)",
    },
    "nvidia": {
        "iana": None, "cmd_names": ("nvidia", "NVIDIA_CMD_NAMES"),
        "blurb": "Nvidia — raw NetFn 0x3C, cmds 0x30-0x37 (provider: phosphor-host-ipmid oem/nvidia)",
    },
}


def _openbmc_vendor_keys() -> list[str]:
    """Canonical keys of the OpenBMC vendor flavors (manifest entries with a
    cmd_names pointer). These are namespaced under `openbmc-<v>` on the CLI —
    the bare `<v>` is NOT a verb (keeps `zipmi oem` from drowning in nine
    rows that crowd out the proprietary vendors and the standard set)."""
    return [k for k, v in VENDORS.items() if v.get("cmd_names") is not None]


def _is_openbmc_vendor(vendor: str) -> bool:
    return VENDORS.get(vendor, {}).get("cmd_names") is not None


def _display_verb(vendor: str) -> str:
    """How the user actually invokes a vendor on the CLI: OpenBMC flavors are
    namespaced `openbmc-<v>`; everything else is the bare key."""
    return f"openbmc-{vendor}" if _is_openbmc_vendor(vendor) else vendor


def _vendor_stats(vendor: str) -> tuple[int, int]:
    """Return (known_dispatch_slots, with_human_name) for vendor.

    The two numbers diverge on iDRAC9: 271 binary dispatch entries
    were RE'd out of the .so libs but only 46 cross-reference to a
    handler symbol with a known name. The rest are runtime-bound
    stubs, callable but nameless.
    """
    if vendor == "idrac6":
        from ..scapy_ipmi.oem.dell_generated import DELL_DISPATCH
        total = len(DELL_DISPATCH)
        named = sum(1 for e in DELL_DISPATCH.values() if e.name)
        return total, named
    if vendor == "idrac9":
        from ..scapy_ipmi.oem.idrac9_dispatch_generated import IDRAC9_DISPATCH
        from ..scapy_ipmi.oem.idrac9 import IDRAC9_CMD_NAMES
        from ..scapy_ipmi.oem.idrac9_binary_names import IDRAC9_BINARY_NAMES
        # Total = union of dispatch keys and any name-only / runtime-only
        # keys that show up in the catalogues; named = how many of those
        # we have a handler symbol for.
        all_keys = (set(IDRAC9_DISPATCH) | set(IDRAC9_CMD_NAMES)
                    | set(IDRAC9_BINARY_NAMES))
        named_keys = set(IDRAC9_CMD_NAMES) | set(IDRAC9_BINARY_NAMES)
        return len(all_keys), len(named_keys)
    if vendor == "idrac10":
        listing = _vendor_listing("idrac10")
        return len(listing), len(listing)
    if vendor in ("supermicro", "supermicro-x11", "supermicro-x14", "megarac"):
        listing = _vendor_listing(vendor)
        return len(listing), len(listing)
    if VENDORS.get(vendor, {}).get("cmd_names") is not None:
        listing = _vendor_listing(vendor)
        return len(listing), len(listing)
    if vendor == "ipmi":
        from ..scapy_ipmi.cmd_names import IPMI_CMD_NAMES
        n = len(IPMI_CMD_NAMES)
        return n, n
    return 0, 0


# Java decompiled-class name → human-readable subsystem label.
SRC_CLASS_LABELS: dict[str, str] = {
    "IPMINM20Command":          "Intel Node Manager 2.0",
    "IPMIDCMOEMCommand":        "Intel DCMI/OEM",
    "IPMIDCMICommand":          "DCMI 1.5 standard",
    "IPMIRaritanOEMCommand":    "Raritan KVM-over-IP (X9-era SM)",
    "IPMIAMIOEMCommand":        "AMI BMC core",
    "IPMIAMIYAFUCommand":       "AMI YAFU flash protocol",
    "IPMINVMECommand":          "NVMe drive control",
    "DCPMMCommand":             "Intel Optane DCPMM",
    "IPMICMMOEMCommand":        "MicroBlade/SuperBlade chassis mgr (CMM)",
    "IPMIMicroBladeOEMCommand": "MicroBlade chassis OEM",
    "IPMICMMDiagCommand":       "CMM diagnostic",
    "IPMIBMCFileCommand":       "BMC file upload/download (BIOS OOB)",
    "IPMIPEFCommand":           "Platform Event Filter",
    "IPMISDRCommand":           "SDR (sensor data records)",
    "IPMISDRCommandForCMMDiag": "SDR (CMM diag variant)",
    "IPMISELCommand":           "SEL (system event log)",
    "IPMIChassisCommand":       "IPMI chassis (NetFn 0x00)",
    "IPMIGlobalCommand":        "IPMI app/global (NetFn 0x06)",
    "IPMIWatchdogCommand":      "IPMI watchdog (NetFn 0x06)",
    "IPMIMessagingCommand":     "IPMI messaging/session (NetFn 0x06)",
    "IPMIX9BIOSOEMCommand":     "X9-era BIOS OEM",
    "IPMIOEMRoTCommand":        "OEM root-of-trust (Aspeed AST2600 RoT)",
    "IPMIOEMCommand":           "Supermicro OEM (general)",
    "IPMIDiagnostic":           "Diagnostic suite",
    "DiagnosticCommand":        "Diagnostic suite",
    "RMCP":                     "RMCP / RMCP+ session setup",
    "IPMIMessage":              "(internal helper)",
    "IPMITASCommand":           "Trusted asset service",
    "IPMIHealthCheckCommand":   "Health check",
    "IPMIInterfaceConfig":      "Interface config",
    "IPMIDoctor":               "Doctor (diagnostic)",
}


def _human_src(cls: str) -> str:
    return SRC_CLASS_LABELS.get(cls, cls)


def _human_args(args: str) -> str:
    """Translate Java parameter list into something a user can read.

    Inputs look like:
      `byte[] rawPECI`
      `byte updateType, byte flags`
      `byte device, byte group, byte slot, byte controller`
      `int firmwareSize`
      `boolean isExtended, int cpuSet`

    Output uses concise type tags so a reader unfamiliar with Java
    knows whether to type one byte (`byte X`), a fixed-width int,
    or a variable-length byte array (`byte[]`):

      byte X     → "X (1B)"
      byte[] X   → "X (variable bytes — hex 0xNN ...)"
      int X      → "X (4B int, LE)"
      short X    → "X (2B short, LE)"
      boolean X  → "X (1B bool, 0 or 1)"
      String X   → "X (ASCII string)"
    """
    args = (args or "").strip()
    if not args:
        return ""
    parts = [p.strip() for p in args.split(",") if p.strip()]
    out = []
    for p in parts:
        toks = p.rsplit(" ", 1)
        if len(toks) != 2:
            out.append(p)
            continue
        ty, name = toks
        ty = ty.strip()
        name = name.strip()
        if ty == "byte":
            out.append(f"{name} (1B)")
        elif ty == "byte[]":
            out.append(f"{name} (var bytes)")
        elif ty in ("int", "Integer"):
            out.append(f"{name} (4B int LE)")
        elif ty in ("short", "Short"):
            out.append(f"{name} (2B int LE)")
        elif ty == "long":
            out.append(f"{name} (8B int LE)")
        elif ty == "boolean":
            out.append(f"{name} (1B bool 0/1)")
        elif ty == "String":
            out.append(f"{name} (ASCII)")
        else:
            out.append(f"{name} ({ty})")
    return ", ".join(out)


_SM_RESPONSE_PATS = re.compile(
    r"^\((?:empty|empty resp|[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*"
    r"|\d+x\s+[0-9a-fA-F]{2})\)$|^error\s+0x[0-9a-fA-F]+$",
    re.IGNORECASE,
)


VENDOR_TAG: dict[str, str] = {
    "idrac6": "Idrac6",
    "idrac9": "Idrac9",
    "idrac10": "Idrac10",
    "supermicro": "Smc",
    "supermicro-x11": "Smc",
    "supermicro-x14": "SmcX14",
}


def _camelize(s: str) -> str:
    """Strip non-alnum chars, CamelCase whatever's left.

    'GPIO read'                  -> 'GpioRead'
    'ISO mount (variant)'        -> 'IsoMount'   (parens already split out)
    '(documented in FAQ)'        -> ''           (caller synthesizes)
    'getCMMVersion'              -> 'GetCMMVersion'
    'StartRestore — CRITICAL...' -> 'StartRestore'  (em-dash already split)
    """
    s = re.sub(r"[^A-Za-z0-9]+", " ", s)
    parts = s.split()
    if not parts:
        return ""
    out = []
    for p in parts:
        if p[0].isupper():
            out.append(p[0] + p[1:])
        else:
            out.append(p[0].upper() + p[1:])
    return "".join(out)


def _normalize_listing(out: dict, vendor: str) -> dict:
    """Final pass on every vendor listing: collapse spaces / punct in
    names, synthesize `<Vendor>OEM_<NetFn>_<Cmd>[_<prefix>...]`
    placeholders for empty / generic entries, and disambiguate name
    collisions by suffixing with the wire bytes.
    """
    tag = VENDOR_TAG.get(vendor, vendor.capitalize())

    GENERIC = {"Unknown", "documentedInFAQ", "documented", "DocumentedInFAQ",
               "(documented in FAQ)", "documentedinFaq", ""}

    # Step 1: camelize + synthesize placeholders.
    for key, info in list(out.items()):
        name = info.get("name") or ""
        clean = _camelize(name)
        if clean in GENERIC or not clean or clean.lower().startswith("documented"):
            netfn, cmd = key[0], key[1]
            prefix = key[2:]
            wire = f"{netfn:02X}_{cmd:02X}"
            for b in prefix:
                wire += f"_{b:02X}"
            clean = f"{tag}OEM_{wire}"
        info["name"] = clean

    # Step 2: detect collisions, suffix with wire bytes.
    name_to_keys: dict[str, list[tuple]] = {}
    for key, info in out.items():
        name_to_keys.setdefault(info["name"], []).append(key)
    for name, keys in name_to_keys.items():
        if len(keys) <= 1:
            continue
        # Multiple entries collide. Suffix each with its wire bytes.
        for key in keys:
            netfn, cmd = key[0], key[1]
            prefix = key[2:]
            suffix = f"_{netfn:02X}_{cmd:02X}"
            for b in prefix:
                suffix += f"_{b:02X}"
            out[key]["name"] = name + suffix

    return out


def _split_sm_name(raw: str) -> tuple[str, str]:
    """Split smcipmi RE-doc cmd labels into (name, description).

    The source labels mix three styles:
      * `OEMFlashFWCmd — CRITICAL (system() ...)` — function name plus
        an em-dash + risk note.
      * `NTP config (needs params)` — function name plus a trailing
        parens-wrapped note.
      * `(empty)`, `(00 00)`, `error 0xFF`, `Buffer (16x 00)` — these
        are NOT function names. They're live-test response samples
        from the original RE author. Surface them as
        `name=Unknown, desc=response: …`.
    Em-dashes inside parens (`Network config — HIGH RISK
    (LanConfigApply path)` becomes `... HIGH RISK (LanConfigApply
    path)` with the dash inside the parens already) get preserved.
    """
    s = raw.strip()

    # Sample-response cases: bump everything into description.
    if _SM_RESPONSE_PATS.match(s):
        return ("Unknown", f"observed response: {s}")
    # "<noun> (response sample)" — e.g. "Buffer (16x 00)", "Status (02 ff)"
    if s.endswith(")") and "(" in s:
        before = s[:s.rfind("(")].strip()
        inside = s[s.rfind("(") + 1:-1].strip()
        # If the parens hold a hex-byte sample / "<N>x <hh>" / "empty",
        # treat the noun as a placeholder name.
        if re.fullmatch(
            r"(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*"
            r"|\d+x\s+[0-9a-fA-F]{2}|empty(?:\s+resp)?)",
            inside,
            re.IGNORECASE,
        ):
            label = "Unknown" if before in ("Status", "Buffer") else before
            note = "empty response" if "empty" in inside.lower() else f"response: {inside}"
            return (label or "Unknown", note)

    # em-dash separator (only at top level — not inside parens).
    for sep in (" — ", " -- "):
        if sep in s:
            head, _, tail = s.partition(sep)
            # Make sure the dash isn't inside parens.
            if head.count("(") == head.count(")"):
                return head.strip(), tail.strip()

    # trailing parens with a real description ("(Network/Web Config)")
    if s.endswith(")") and "(" in s:
        idx = s.rfind("(")
        if idx > 0 and s[:idx].strip():
            return s[:idx].strip(), s[idx + 1:-1].strip()
    return s, ""


def _vendor_listing(vendor: str) -> dict[tuple[int, int], dict]:
    """Return {(netfn, cmd) → {name, priv, desc, live, missing}} for vendor.

    Imports the per-vendor module on demand so a stale entry in
    VENDORS doesn't blow up zipmi --help.
    """
    # Generic branch: OpenBMC-style vendors whose manifest entry carries a
    # `cmd_names` pointer (module, ATTR) to a {(netfn,cmd): name} dict. One
    # branch serves every such vendor — no per-vendor code needed.
    spec = VENDORS.get(vendor, {}).get("cmd_names")
    if spec is not None:
        import importlib
        mod = importlib.import_module(f"zipmi.scapy_ipmi.oem.{spec[0]}")
        names = getattr(mod, spec[1])
        prefix = re.compile(rf"^{re.escape(vendor)}\s+", re.IGNORECASE)
        return {
            key: {
                "name": prefix.sub("", nm),
                "priv": None, "desc": "", "live": None, "missing": False,
                # baked fixed-prefix bytes (key[2:]) — auto-supplied on send so
                # the user drops the mandatory selector/IANA (see nvidia/intel/fb).
                "prefix": bytes(key[2:]) if len(key) > 2 else None,
            }
            for key, nm in names.items()
        }
    if vendor == "idrac6":
        from ..scapy_ipmi.oem.dell_generated import DELL_DISPATCH
        from ..scapy_ipmi.oem.dell import (
            DELL_NAME_OVERRIDES, DELL_BINARY_NAMES,
        )
        from ..scapy_ipmi.oem.idrac6_known_context import KNOWN_CONTEXT
        out: dict[tuple[int, int], dict] = {}
        for key, e in DELL_DISPATCH.items():
            if not e.name:
                continue
            override = DELL_NAME_OVERRIDES.get(key) or DELL_BINARY_NAMES.get(key)
            raw = override or e.name
            name = re.sub(r"^Dell\s+", "", raw)
            # When binary RE disagrees with the MD-author's name, the
            # MD's description + not_present flag were based on the
            # WRONG identification (the original RE author looked at
            # nearby symbols / comments instead of the actual handler
            # at the dispatch slot). Binary is authoritative — clear
            # the stale MD metadata in that case.
            md_normalized = _normalize(f"Dell {e.name}") if e.name else ""
            bin_normalized = _normalize(override or "")
            md_authoritative = (not override) or md_normalized == bin_normalized
            out[key] = {
                "name": name,
                "priv": e.priv,
                "desc": e.description if md_authoritative else "",
                "live": e.live_status if md_authoritative else None,
                "missing": e.not_present if md_authoritative else False,
            }
        # Layer Dell-doc-derived context on top. Hand-curated entries
        # (with prefix bytes — IANA prefixes for NetFn 0x2E, sub-bytes
        # for NetFn 0x30) get their own rows so the listing surfaces
        # the right wire bytes for each variant.
        for key, ctx in KNOWN_CONTEXT.items():
            netfn, cmd = key[0], key[1]
            prefix = key[2:]
            row = out.get(key)
            if row is None:
                base_e = DELL_DISPATCH.get((netfn, cmd))
                # Prefer the curated name from KNOWN_CONTEXT; fall back
                # to binary symbol → MD name → handler-addr placeholder.
                base_name = (ctx.get("name")
                             or DELL_NAME_OVERRIDES.get((netfn, cmd))
                             or DELL_BINARY_NAMES.get((netfn, cmd))
                             or (base_e.name if base_e else "(documented in Dell RE)"))
                base_name = re.sub(r"^Dell\s+", "", base_name)
                row = {
                    "name": base_name,
                    "priv": base_e.priv if base_e else None,
                    "desc": "",
                    "live": base_e.live_status if base_e else None,
                    "missing": False,
                    "prefix": bytes(prefix) if prefix else None,
                }
                out[key] = row
            else:
                # Override existing row name when curated name available
                # (replaces handler-addr placeholders with real names).
                if ctx.get("name"):
                    row["name"] = ctx["name"]
            if ctx.get("summary"):
                row["desc"] = ctx["summary"]
            if ctx.get("reservation_from"):
                row["reservation_from"] = ctx["reservation_from"]
        return _normalize_listing(out, vendor)
    if vendor == "idrac9":
        from ..scapy_ipmi.oem.idrac9 import IDRAC9_CMD_NAMES
        from ..scapy_ipmi.oem.idrac9_dispatch_generated import IDRAC9_DISPATCH
        from ..scapy_ipmi.oem.idrac9_binary_names import IDRAC9_BINARY_NAMES
        from ..scapy_ipmi.oem.idrac9_known_context import KNOWN_CONTEXT as I9_CTX
        PRIVS = {0: "Unspec", 1: "Callback", 2: "User",
                 3: "Operator", 4: "Admin"}

        def _short_table(t: str) -> str:
            t = t or ""
            if t.startswith("G_as"):
                t = t[4:]
            for suffix in ("ReqeustHandleTable", "RequestHandleTable",
                           "HandleTable", "Table"):
                if t.endswith(suffix):
                    t = t[:-len(suffix)]
                    break
            return t.strip() or "?"

        def _short_lib(l: str) -> str:
            return l.replace(".so.9.9.9", "")

        out: dict = {}
        for key, e in IDRAC9_DISPATCH.items():
            # Resolution order: hand-curated NAME (RE doc) → addr→sym
            # via dynsym (idrac9_binary_names) → fallback stub.
            named = IDRAC9_CMD_NAMES.get(key)
            bin_entry = IDRAC9_BINARY_NAMES.get(key)
            tbl = _short_table(e.table)
            # Strip redundant "iDRAC9" prefix on display names (the
            # `zipmi idrac9` verb already provides vendor context).
            def _strip(n):
                return re.sub(r"^iDRAC9\s+", "", n) if n else n
            if named:
                name = _strip(named)
                desc = (f"table {tbl}, sym {e.handler_symbol}"
                        if e.handler_symbol and e.handler_symbol != "(runtime-bound)"
                        else f"table {tbl}")
            elif bin_entry:
                sym, lib = bin_entry
                name = sym
                desc = f"table {tbl}, lib {_short_lib(lib)}"
            else:
                name = "(unnamed handler stub)"
                desc = f"table {tbl} (runtime-bound stub)"
            out[key] = {
                "name": name,
                "priv": PRIVS.get(e.priv),
                "desc": desc,
                "live": None,
                "missing": False,
            }
        for key, name in IDRAC9_CMD_NAMES.items():
            out.setdefault(key, {
                "name": _strip(name), "priv": None,
                "desc": "name-only entry, not in dispatch table",
                "live": None, "missing": False,
            })
        for key, (sym, lib) in IDRAC9_BINARY_NAMES.items():
            out.setdefault(key, {
                "name": sym,
                "priv": None,
                "desc": f"runtime-only (lib {_short_lib(lib)}, not in static dispatch)",
                "live": None, "missing": False,
            })
        # Final pass: layer hand-curated context (risk tags + reservation
        # flows) on top. Same shape as idrac6 / supermicro.
        for key, ctx in I9_CTX.items():
            row = out.get(key)
            if row is None:
                netfn, cmd = key[0], key[1]
                prefix = key[2:] if len(key) > 2 else ()
                row = {
                    "name": ctx.get("name") or "(documented)",
                    "priv": None, "desc": "",
                    "live": None, "missing": False,
                    "prefix": bytes(prefix) if prefix else None,
                }
                out[key] = row
            elif ctx.get("name"):
                row["name"] = ctx["name"]
            if ctx.get("summary"):
                row["desc"] = ctx["summary"]
            if ctx.get("reservation_from"):
                row["reservation_from"] = ctx["reservation_from"]
        # Layer the rich RE'd catalog (idrac9-commands.json, 276 cmds) on
        # top so `zipmi idrac9 <name> help` surfaces the full doc
        # (request/response/security/confidence/lib), mirroring idrac10.
        # Catalog keys fold subcmd into the wire prefix; entries with a
        # sub-command byte add their own rows, base handlers merge onto the
        # existing dispatch row (catalog name + doc win — it's the
        # adversarially-verified source).
        from ..scapy_ipmi.oem.idrac9 import IDRAC9_COMMANDS
        for c in IDRAC9_COMMANDS:
            if c.netfn is None or c.cmd is None:
                continue  # RE couldn't pin the wire bytes; not CLI-runnable
            if c.subcmd is None:
                key = (c.netfn, c.cmd)
                prefix = None
            else:
                sb = c.subcmd.to_bytes(
                    max(1, (c.subcmd.bit_length() + 7) // 8), "big")
                key = (c.netfn, c.cmd) + tuple(sb)
                prefix = sb
            rich = {
                "request": c.request, "response": c.response,
                "security": c.security, "confidence": c.confidence,
                "inband": c.in_band_only, "lib": c.lib,
                "backend_deps": c.backend_deps,
            }
            row = out.get(key)
            if row is None:
                out[key] = {
                    "name": c.name, "priv": c.priv or None,
                    "desc": c.purpose, "live": None, "missing": False,
                    "prefix": prefix, **rich,
                }
            else:
                row.update(rich)
                row["name"] = c.name
                if c.purpose:
                    row["desc"] = c.purpose
                if c.priv:
                    row["priv"] = c.priv
        return _normalize_listing(out, vendor)
    if vendor == "idrac10":
        from ..scapy_ipmi.oem.idrac10 import IDRAC10_COMMANDS
        out: dict = {}
        for c in IDRAC10_COMMANDS:
            if c.netfn is None or c.cmd is None:
                continue  # RE couldn't pin the wire bytes; not CLI-runnable
            if c.subcmd is None:
                key: tuple = (c.netfn, c.cmd)
                prefix = None
            else:
                # subcmd is folded big-endian (single or multi byte).
                sb = c.subcmd.to_bytes(
                    max(1, (c.subcmd.bit_length() + 7) // 8), "big")
                key = (c.netfn, c.cmd) + tuple(sb)
                prefix = sb
            out[key] = {
                "name": c.name,
                "priv": c.priv or None,
                "desc": c.purpose,
                "live": None,
                "missing": False,
                "prefix": prefix,
                # Rich doc fields surfaced by `<name> help` (see _cmd_oem_help).
                "request": c.request,
                "response": c.response,
                "security": c.security,
                "confidence": c.confidence,
                "inband": c.in_band_only,
                "lib": c.lib,
                "backend_deps": c.backend_deps,
            }
        return _normalize_listing(out, vendor)
    if vendor == "supermicro-x14":
        from ..scapy_ipmi.oem.supermicro_x14 import SUPERMICRO_X14
        out: dict[tuple, dict] = {
            key: {"name": e["name"], "priv": e.get("priv"), "desc": e.get("desc", ""),
                  "live": None, "missing": False,
                  "prefix": bytes(key[2:]) if len(key) > 2 else None}
            for key, e in SUPERMICRO_X14.items()
        }
        return _normalize_listing(out, "supermicro-x14")
    if vendor in ("supermicro", "supermicro-x11"):
        from ..scapy_ipmi.oem.supermicro import SM_TOP_CMDS, SM_SUBCMDS
        from ..scapy_ipmi.oem.supermicro_smcipmi_names import SMCIPMI_METHODS
        from ..scapy_ipmi.oem.supermicro_known_context import KNOWN_CONTEXT
        out: dict = {}
        for k, raw in SM_TOP_CMDS.items():
            name, desc = _split_sm_name(raw)
            name = re.sub(r"^Supermicro\s+", "", name)
            out[k] = {"name": name, "priv": None,
                      "desc": desc or "top-level dispatcher — pick a sub-cmd",
                      "live": None, "missing": False, "prefix": None,
                      "args": "", "src": "smcipmi RE notes"}
        for (netfn, cmd), subs in SM_SUBCMDS.items():
            for sub, raw in subs.items():
                name, desc = _split_sm_name(raw)
                out[(netfn, cmd, sub)] = {
                    "name": name,
                    "priv": None,
                    "desc": desc,
                    "live": None,
                    "missing": False,
                    "prefix": bytes([sub]),
                    "args": "",
                    "src": "smcipmi RE notes",
                }
        for nf, cmd, prefix, method, args, src_cls in SMCIPMI_METHODS:
            key = (nf, cmd) + tuple(prefix) if prefix else (nf, cmd)
            if key in out:
                continue
            out[key] = {
                "name": method,
                "priv": None,
                "desc": "",
                "live": None, "missing": False,
                "prefix": bytes(prefix) if prefix else None,
                "args": args,
                "src": _human_src(src_cls),
            }
        # Final pass: layer the FAQ + reservation-flow context onto
        # whatever already exists. Covers both smcipmi and SMCIPMITool
        # entries; surfaces hand-curated docs for cmds whose name +
        # args alone don't tell you what they do.
        for key, ctx in KNOWN_CONTEXT.items():
            row = out.get(key)
            if row is None:
                # Context-only row — surface as a documented cmd.
                netfn, cmd = key[0], key[1]
                prefix = key[2:]
                row = {
                    "name": ctx.get("name") or "(documented in FAQ)",
                    "priv": None, "desc": "",
                    "live": None, "missing": False,
                    "prefix": bytes(prefix) if prefix else None,
                    "args": "", "src": ctx.get("source", "FAQ"),
                }
                out[key] = row
            elif ctx.get("name"):
                row["name"] = ctx["name"]
            if ctx.get("summary"):
                row["desc"] = ctx["summary"]
            if ctx.get("reservation_from"):
                row["reservation_from"] = ctx["reservation_from"]
        return _normalize_listing(out, vendor)
    if vendor == "ipmi":
        from ..scapy_ipmi.cmd_names import IPMI_CMD_NAMES
        out: dict[tuple[int, int], dict] = {
            (netfn, cmd): {
                "name": name,
                "priv": None,
                "desc": "",
                "live": None,
                "missing": False,
                "prefix": None,
                "args": "",
                "src": "IPMI 2.0 spec, Table G-1",
            }
            for (netfn, cmd), name in IPMI_CMD_NAMES.items()
        }
        return _normalize_listing(out, "ipmi")
    if vendor == "megarac":
        from ..scapy_ipmi.oem.megarac import MEGARAC_COMMANDS
        out = {
            key: {"name": e["name"], "priv": e.get("priv"),
                  "desc": f"module: {e['module']}", "live": None,
                  "missing": False, "prefix": None}
            for key, e in MEGARAC_COMMANDS.items()
        }
        return _normalize_listing(out, "megarac")
    raise KeyError(f"unknown vendor: {vendor}")


# Name normalisation: strip vendor prefixes + Cmd/OEM filler, lowercase,
# drop separators. Lets `GetChassisStatus`, `get-chassis-status`,
# `Cmd Get Chassis Status`, and `getchassisstatus` all match the same
# entry.
_PREFIX_RE = re.compile(r"^(?:idrac6|idrac9|dell|supermicro|cmd|oem|sm)+",
                        re.IGNORECASE)


def _normalize(s: str) -> str:
    s = s.strip()
    while True:
        m = _PREFIX_RE.match(s)
        if not m or not m.group(0):
            break
        s = s[m.end():].lstrip(" _-")
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _find_cmd(
    listing: dict[tuple[int, int], dict],
    query: str,
) -> list[tuple[tuple[int, int], dict]]:
    """Resolve user input to listing entries.

    Phase 1: literal case-insensitive substring on the displayed name —
      this is what the user actually typed, so if they wrote
      `CmdGetChassisCapabilities` we should NOT silently match
      `CmdOEMGetChassisCapabilities` just because both normalise to the
      same letters.
    Phase 2: normalised exact match (vendor/Cmd/OEM prefixes stripped,
      separators ignored). Catches `get-chassis-status`, `getchassisstatus`.
    Phase 3: normalised substring — the loose "search the catalogue"
      mode, which legitimately can return >1.
    """
    qlow = query.lower().strip()
    if qlow:
        literal = [(k, v) for k, v in listing.items()
                   if qlow in v["name"].lower()]
        if len(literal) == 1:
            return literal
    qn = _normalize(query)
    if not qn:
        return []
    nexact = [(k, v) for k, v in listing.items()
              if _normalize(v["name"]) == qn]
    if len(nexact) == 1:
        return nexact
    return [(k, v) for k, v in listing.items() if qn in _normalize(v["name"])]


def _vendor_listing_data(vendor: str) -> dict:
    """Structured mirror of _print_vendor_listing: one self-describing record
    per (netfn, cmd[, prefix]) entry with the same fields the table shows."""
    listing = _vendor_listing(vendor)
    total, named = _vendor_stats(vendor)
    commands = []
    for key, info in sorted(listing.items()):
        netfn, cmd = key[0], key[1]
        prefix = key[2:]
        commands.append({
            "netfn": netfn, "cmd": cmd,
            "prefix": [b for b in prefix] if prefix else [],
            "name": info["name"],
            "priv": info.get("priv"),
            "desc": info.get("desc") or "",
            "args": info.get("args") or "",
            "src": info.get("src") or "",
            "missing": bool(info.get("missing")),
        })
    return {"vendor": vendor, "verb": _display_verb(vendor),
            "named": named, "total": total, "commands": commands}


def _print_vendor_listing(vendor: str) -> None:
    listing = _vendor_listing(vendor)
    if not listing:
        print(f"# {vendor}: no commands registered", file=sys.stderr)
        return
    total, named = _vendor_stats(vendor)
    if vendor == "ipmi":
        title = f"IPMI 2.0 standard commands (Table G-1) — {named} total"
    elif total != named:
        title = (f"{vendor} OEM commands — {named} named "
                 f"of {total} known dispatch slots")
    else:
        title = f"{vendor} OEM commands — {named} total"
    print(f"# {title}  (`zipmi oem {_display_verb(vendor)} <name> help` for per-cmd detail)")
    print("# " + "-" * (len(title)))
    # Three aligned columns: address, name, priv. The "(not present in
    # fw)" flag is rare (~4 of 192 Dell rows) — append it to the desc
    # instead of giving it its own padded column, otherwise every row
    # eats 19 chars of dead space.
    rows: list[tuple[str, str, str, str]] = []
    for key, info in sorted(listing.items()):
        # Key shapes:
        #   (netfn, cmd)                    — plain
        #   (netfn, cmd, sub)               — single-byte sub-cmd dispatch
        #   (netfn, cmd, b0, b1, ...)       — multi-byte prefix dispatch
        netfn, cmd = key[0], key[1]
        prefix_bytes = key[2:]
        shown_pfx = prefix_bytes[:4]
        addr_parts = [f"0x{netfn:02x}", f"0x{cmd:02x}"]
        addr_parts.extend(f"0x{b:02x}" for b in shown_pfx)
        if len(prefix_bytes) > 4:
            addr_parts.append("…")
        addr = " ".join(addr_parts)
        priv = f"[{info['priv']}]" if info.get("priv") else ""
        desc = info.get("desc") or ""
        # Smart description for SMCIPMITool entries (have `args`/`src`):
        # show the user what bytes to type and what subsystem owns the
        # cmd. Skip the raw "data prefix" repeat — the prefix is
        # already in the address column.
        if info.get("args") or info.get("src"):
            args_h = _human_args(info.get("args") or "")
            src = info.get("src") or ""
            d_parts = []
            if args_h:
                d_parts.append(f"args: {args_h}")
            if src:
                d_parts.append(f"subsystem: {src}")
            if desc:
                d_parts.insert(0, desc)
            desc = "; ".join(d_parts)
        if info.get("missing"):
            desc = ("(not present in fw) " + desc).rstrip()
        rows.append((addr, info["name"], priv, desc))
    addr_w = max(len(r[0]) for r in rows)
    name_w = max(len(r[1]) for r in rows)
    priv_w = max(len(r[2]) for r in rows)
    has_priv = any(r[2] for r in rows)
    has_desc = any(r[3] for r in rows)
    # Column headers — same widths so the divider underlines line up.
    addr_h = "NetFn Cmd"
    addr_w = max(addr_w, len(addr_h))
    hdr = f"  {addr_h:<{addr_w}s}  {'Name':<{name_w}s}"
    sep = f"  {'-'*addr_w}  {'-'*name_w}"
    if has_priv:
        hdr += f"  {'Priv':<{priv_w}s}"
        sep += f"  {'-'*priv_w}"
    if has_desc:
        hdr += "  Description"
        sep += "  -----------"
    print(hdr)
    print(sep)
    for addr, name, priv, desc in rows:
        line = f"  {addr:<{addr_w}s}  {name:<{name_w}s}"
        if has_priv:
            line += f"  {priv:<{priv_w}s}"
        if has_desc and desc:
            line += f"  {desc}"
        print(line.rstrip())
    print()
    _print_legend(vendor)


def _print_legend(vendor: str) -> None:
    print("# Legend")
    print("#   address column = wire bytes that go on the IPMI request:")
    print("#     <NetFn>  <cmd>  [<data prefix>...]")
    print("#     The data prefix is automatically prepended when you")
    print("#     resolve the cmd by name; for `raw` you supply it.")
    print("#   args column = user-supplied data bytes appended after the")
    print("#     prefix. Type tags:")
    print("#       NAME (1B)            single byte. hex `0x..` or decimal.")
    print("#       NAME (var bytes)     variable-length array. each byte is")
    print("#                            a separate CLI arg.")
    print("#       NAME (4B int LE)     4-byte little-endian integer. type")
    print("#                            it as 4 bytes (e.g. 0x00 0x10 0x00 0x00 = 4096).")
    print("#       NAME (1B bool 0/1)   single byte 0x00 or 0x01.")
    print("#       NAME (ASCII)         ASCII string. supply as bytes.")
    print("#   subsystem column = which Java class in SMCIPMITool dispatches")
    print("#     this cmd. Hint at attack surface (Intel NM, Raritan KVM,")
    print("#     AMI YAFU flash, MicroBlade chassis, ...).")
    print(f"# Run a command:  zipmi -H <host> -U <u> -P <p> "
          f"{_display_verb(vendor)} <name> [data ...]")
    print(f"# Per-cmd detail: zipmi oem {_display_verb(vendor)} <name> help")


def _print_vendor_catalog() -> None:
    print("# zipmi OEM dispatcher")
    print("# Available vendors (`zipmi oem <vendor>` to list cmds):")
    obmc = set(_openbmc_vendor_keys())
    for key, info in VENDORS.items():
        if key in obmc:
            continue  # OpenBMC flavors collapse into one `openbmc` line below
        total, named = _vendor_stats(key)
        if total == named:
            count = f"{named} cmds"
        else:
            count = f"{named} named / {total} known"
        iana = info["iana"]
        iana_str = f"IANA {iana:<6d}" if iana is not None else "IANA —    "
        print(f"  {key:<14s}  {iana_str}  "
              f"{count:<22s}  {info['blurb']}")
    # The OpenBMC vendor flavors are grouped under a single `openbmc` verb so
    # nine open-source flavors don't crowd out the proprietary vendors.
    n = len(obmc)
    print(f"  {'openbmc':<14s}  {'':<10s}  {f'{n} vendor flavors':<22s}  "
          f"OpenBMC OEM (per-vendor) — `zipmi oem openbmc` to list")
    print()
    print("# IANA = Private Enterprise Number (per-vendor namespace tag).")
    print("# 674 → Dell, 10876 → Supermicro. Same (NetFn 0x30, cmd 0xC0)")
    print("# means PROCHOTThrottle on Dell, something else on Supermicro.")
    print("# Get vendor: `zipmi scan asf-ping <bmc>` or `zipmi mc info`.")
    print()
    print("# Run by name:  zipmi oem <vendor> <cmd-name> [data-bytes ...]")
    print("#   proprietary: zipmi oem supermicro <cmd-name> [data ...]")
    print("#   OpenBMC:     zipmi oem openbmc-<vendor> <cmd-name> [data ...]  (e.g. openbmc-intel)")


def _print_openbmc_flavors() -> None:
    print("# OpenBMC OEM vendor flavors")
    print("# (OpenBMC's own baseline commands are standard IPMI — see `zipmi ipmi`.")
    print("#  There is no vanilla-OpenBMC OEM set; OEM commands are per-vendor.)")
    print("# Run: zipmi -H <bmc> -C 17 oem openbmc-<vendor> <cmd-name> [data ...]")
    print()
    for vkey in _openbmc_vendor_keys():
        info = VENDORS[vkey]
        total, named = _vendor_stats(vkey)
        count = f"{named} cmds" if total == named else f"{named} named / {total} known"
        iana = info["iana"]
        iana_str = f"IANA {iana:<6d}" if iana is not None else "IANA —    "
        print(f"  openbmc-{vkey:<11s}  {iana_str}  {count:<18s}  {info['blurb']}")
    print()
    print("# Short alias: `ob-<vendor>` also works (e.g. `ob-intel`).")


def cmd_openbmc_index(args: argparse.Namespace) -> int:
    """`zipmi openbmc` / `zipmi oem openbmc` — list the vendor flavors."""
    cmd_name = getattr(args, "cmd_name", None)
    if cmd_name:
        _msg.error("'openbmc' is a vendor-flavor index, not a command set — "
                   "OpenBMC OEM commands are per-vendor.")
        print(f"# Pick a flavor, e.g.: zipmi oem openbmc-intel {cmd_name!r}",
              file=sys.stderr)
        print("# Flavors: " + ", ".join(_openbmc_vendor_keys()), file=sys.stderr)
        return 2
    if emit(args, _openbmc_flavors_data()):
        return 0
    _print_openbmc_flavors()
    return 0


def _openbmc_flavors_data() -> dict:
    """Structured mirror of _print_openbmc_flavors (one record per flavor row)."""
    flavors = []
    for vkey in _openbmc_vendor_keys():
        info = VENDORS[vkey]
        total, named = _vendor_stats(vkey)
        flavors.append({"vendor": vkey, "verb": f"openbmc-{vkey}",
                        "iana": info["iana"], "named": named, "total": total,
                        "blurb": info["blurb"]})
    return {"flavors": flavors}


# --- entry points called by the CLI ---------------------------------------


def _vendor_catalog_data() -> dict:
    """Structured mirror of _print_vendor_catalog: one record per vendor row,
    plus the collapsed OpenBMC group row (same columns the table shows)."""
    obmc = set(_openbmc_vendor_keys())
    vendors = []
    for key, info in VENDORS.items():
        if key in obmc:
            continue
        total, named = _vendor_stats(key)
        vendors.append({"vendor": key, "iana": info["iana"],
                        "named": named, "total": total,
                        "blurb": info["blurb"]})
    vendors.append({"vendor": "openbmc", "iana": None,
                    "flavors": len(obmc), "blurb": "OpenBMC OEM (per-vendor)"})
    return {"vendors": vendors}


def cmd_oem_list_vendors(args: argparse.Namespace) -> int:
    """`zipmi oem` (no sub-vendor)."""
    # If a vendor was supplied via `oem <vendor> ...`, dispatch.
    vendor = getattr(args, "vendor", None)
    if vendor:
        return cmd_oem_run(args, vendor)
    if emit(args, _vendor_catalog_data()):
        return 0
    _print_vendor_catalog()
    return 0


def cmd_oem_run(args: argparse.Namespace, vendor: str) -> int:
    """`zipmi <vendor> [cmd-name [data ...]]`.

    No cmd_name → print the vendor's catalogue. Match → run the cmd.
    Multiple matches → list them and exit non-zero.
    Trailing `help` / `?` arg on the data list → show per-cmd info.
    """
    cmd_name = getattr(args, "cmd_name", None)
    if not cmd_name:
        if emit(args, _vendor_listing_data(vendor)):
            return 0
        _print_vendor_listing(vendor)
        return 0
    # Help intercept: `zipmi <vendor> <name> help` or `... ?`
    raw_data = list(getattr(args, "data", None) or [])
    show_help = raw_data and raw_data[-1].lower() in ("help", "?")
    if show_help:
        return _cmd_oem_help(vendor, cmd_name)

    # Structured OEM sub-verb intercept: `oem idrac9 maser {get,set [state]}`.
    # MASER / LifecycleController access-state is iDRAC9/10 custom decode (not a
    # raw opcode dispatch), so it routes to dedicated handlers instead of the
    # name->(netfn,cmd) table.
    if vendor in ("idrac9", "idrac10") and cmd_name.lower() == "maser":
        from .zipmi import cmd_maser_get, cmd_maser_set
        action = raw_data[0].lower() if raw_data else "get"
        if action == "get":
            return cmd_maser_get(args)
        if action == "set":
            if len(raw_data) < 2 or raw_data[1].lower() not in ("enabled", "disabled"):
                _msg.error("usage: oem dell maser set {enabled|disabled}")
                return 2
            args.state = raw_data[1].lower()
            return cmd_maser_set(args)
        _msg.error(f"unknown maser action {action!r} — use get | set")
        return 2

    # Resolve name → (netfn, cmd).
    try:
        listing = _vendor_listing(vendor)
    except KeyError as e:
        _msg.error(f"{e}")
        return 2
    hits = _find_cmd(listing, cmd_name)
    if not hits:
        _msg.error(f"no {vendor} command matches {cmd_name!r}")
        print(f"# Run `zipmi {_display_verb(vendor)}` to see the catalogue.",
              file=sys.stderr)
        return 1
    if len(hits) > 1:
        print(f"# {len(hits)} {vendor} commands match {cmd_name!r}:",
              file=sys.stderr)
        for key, info in sorted(hits):
            nf, c = key[0], key[1]
            prefix = key[2:]
            wire = " ".join([f"0x{nf:02x}", f"0x{c:02x}"]
                            + [f"0x{b:02x}" for b in prefix])
            print(f"  {wire}  {info['name']}", file=sys.stderr)
        return 1

    key, info = hits[0]
    netfn, cmd = key[0], key[1]
    # key[2:] is the disambiguating data prefix; it's also stored in
    # info["prefix"] (as bytes). Use info["prefix"] as the source of
    # truth so we don't reconstruct it.
    prefix = info.get("prefix") or b""
    raw_data = list(getattr(args, "data", None) or [])
    try:
        data_bytes = prefix + bytes(int(b, 0) & 0xFF for b in raw_data)
    except ValueError:
        bad = next((b for b in raw_data
                    if not _is_int_literal(b)), None)
        _msg.error(f"data byte {bad!r} is not numeric "
                   f"(use hex 0xNN or decimal)")
        print(f"# Hint: if you mean a user/channel ID, look it up first:",
              file=sys.stderr)
        print(f"#   zipmi -H <bmc> user list", file=sys.stderr)
        print(f"#   zipmi -H <bmc> raw 0x06 0x42 0x0e   # Get Channel Info",
              file=sys.stderr)
        return 2

    # Send. Imports kept inside to avoid module-load-time circular imports.
    import zipmi
    from .zipmi import _open_session  # noqa: WPS433 (intentional)

    if vendor != "ipmi":
        zipmi.load_vendor(vendor)   # standard cmds need no OEM table
    with _open_session(args) as s:
        cc, resp = s.send_raw(netfn, cmd, data_bytes)

    print(f"# {info['name']}  (NetFn 0x{netfn:02x} cmd 0x{cmd:02x})",
          file=sys.stderr)
    if cc != 0:
        cc_name = COMP_CODE.get(cc, f"0x{cc:02x}")
        _msg.error(f"completion code: {cc_name}")
        _suggest_for_cc(cc, netfn, cmd, info, vendor)
        return 1
    if emit(args, {"vendor": vendor, "netfn": netfn, "cmd": cmd,
                   "name": info["name"], "cc": cc, "data": resp.hex()}):
        return 0
    if resp:
        print(" ".join(f"{b:02x}" for b in resp))
    return 0


def _cmd_oem_help(vendor: str, query: str) -> int:
    """Print expanded info for a single (vendor, cmd-name) pair."""
    try:
        listing = _vendor_listing(vendor)
    except KeyError as e:
        _msg.error(f"{e}")
        return 2
    hits = _find_cmd(listing, query)
    if not hits:
        _msg.error(f"no {vendor} cmd matches {query!r}")
        return 1
    if len(hits) > 1:
        print(f"# {len(hits)} matches for {query!r}; listing each:")
    for key, info in hits:
        netfn, cmd = key[0], key[1]
        prefix = key[2:]
        prefix_s = " ".join(f"0x{b:02x}" for b in prefix) or "(none)"
        print(f"\n## {info['name']}")
        print(f"  NetFn:        0x{netfn:02x}")
        print(f"  Cmd:          0x{cmd:02x}")
        print(f"  Data prefix:  {prefix_s}   (auto-prepended on name-resolve)")
        if info.get("priv"):
            print(f"  Privilege:    {info['priv']}")
        args = info.get("args") or ""
        if args:
            print(f"  Args:         {_human_args(args)}")
            print(f"  (raw Java:    {args})")
        if info.get("src"):
            print(f"  Subsystem:    {info['src']}")
        if info.get("desc"):
            print(f"  Notes:        {info['desc']}")
        # Rich per-command doc (iDRAC10 catalog carries these).
        if info.get("request"):
            print(f"  Request:      {info['request']}")
        if info.get("response"):
            print(f"  Response:     {info['response']}")
        if info.get("security"):
            print(f"  Security:     {info['security']}")
        if info.get("backend_deps"):
            print(f"  Backend deps: {info['backend_deps']}")
        if info.get("inband"):
            print(f"  In-band only: yes (host-side / KCS, not remote LAN)")
        if info.get("lib"):
            print(f"  Library:      {info['lib']}")
        if info.get("confidence"):
            print(f"  Confidence:   {info['confidence']}")
        if info.get("reservation_from"):
            print(f"  Reservation:  {info['reservation_from']}")
        if info.get("live"):
            print(f"  Live status:  {info['live']}")
        if info.get("missing"):
            print(f"  Status:       (not present in this fw)")
        # Suggest example invocation.
        prefix_args = " ".join(f"0x{b:02x}" for b in prefix)
        print(f"\n  Invoke:")
        print(f"    zipmi -H <bmc> -U <user> -P <pw> {vendor} "
              f"{info['name']} <args...>")
        if prefix_args:
            print(f"    zipmi -H <bmc> -U <user> -P <pw> raw "
                  f"0x{netfn:02x} 0x{cmd:02x} {prefix_args} <args...>")
        else:
            print(f"    zipmi -H <bmc> -U <user> -P <pw> raw "
                  f"0x{netfn:02x} 0x{cmd:02x} <args...>")
    return 0


def _is_int_literal(s: str) -> bool:
    try:
        int(s, 0)
        return True
    except (ValueError, TypeError):
        return False


def _suggest_for_cc(cc: int, netfn: int, cmd: int,
                    info: dict, vendor: str) -> None:
    """Print a hint to stderr based on the completion code."""
    if cc == 0xC7:        # Request data length invalid
        print("# Hint: cmd needs different data bytes (length wrong).",
              file=sys.stderr)
        print(f"#   * Description: {info.get('desc') or '—'}",
              file=sys.stderr)
        print(f"#   * Try `zipmi -H <bmc> raw 0x{netfn:02x} 0x{cmd:02x} "
              "<bytes>` to experiment.", file=sys.stderr)
        print(f"#   * IPMI 2.0 spec / vendor doc has the request format.",
              file=sys.stderr)
    elif cc == 0xC8:      # Request data field length limit exceeded
        print("# Hint: too many data bytes — trim and retry.",
              file=sys.stderr)
    elif cc == 0xCC:      # Invalid data field in request
        print("# Hint: bad value in a data byte (e.g. user ID 0, "
              "reserved bits set).", file=sys.stderr)
        print("#   `zipmi -H <bmc> user list` for valid user IDs.",
              file=sys.stderr)
    elif cc == 0xC1:      # Invalid command
        print(f"# Hint: BMC doesn't implement this cmd. iDRAC6 lacks "
              f"DCMI / iDRAC9-only cmds; check `mc info` to confirm "
              f"target is in scope.", file=sys.stderr)
    elif cc == 0xD5:      # Cannot execute command, command disabled
        print("# Hint: cmd disabled on this channel/privilege; "
              "elevate or try a different channel.", file=sys.stderr)


# --- argparse wiring ------------------------------------------------------


def _add_vendor_parser(
    parent_sub,
    parser_name: str,
    blurb: str,
    *,
    vendor_key: str | None = None,
    aliases: list[str] | tuple[str, ...] = (),
    cmd_noun: str = "OEM cmd",
) -> argparse.ArgumentParser:
    """Register a vendor verb. `parser_name` is what the user types (may be a
    namespaced `openbmc-<v>`); `vendor_key` is the canonical key the dispatcher
    looks up (defaults to parser_name)."""
    vendor_key = vendor_key or parser_name
    sp = parent_sub.add_parser(parser_name, help=blurb, aliases=list(aliases))
    sp.add_argument("cmd_name", nargs="?",
                    help=f"{cmd_noun} name (substring match; omit to list)")
    sp.add_argument("data", nargs="*",
                    help="optional data bytes (hex like 0x01 or decimal)")
    sp.set_defaults(func=lambda a, v=vendor_key: cmd_oem_run(a, v))
    return sp


def _add_openbmc_group_parser(parent_sub) -> None:
    """The `openbmc` grouping verb — an index of vendor flavors, not a command
    set (OpenBMC has no vanilla OEM cmds; its baseline is standard IPMI)."""
    sp = parent_sub.add_parser(
        "openbmc",
        help="OpenBMC OEM vendor-flavor index (then pick openbmc-<vendor>)")
    sp.add_argument("cmd_name", nargs="?", help=argparse.SUPPRESS)
    sp.add_argument("data", nargs="*", help=argparse.SUPPRESS)
    sp.set_defaults(func=cmd_openbmc_index)


def _add_all_vendor_parsers(parent_sub) -> None:
    """Register proprietary vendors under their bare name and OpenBMC flavors
    under `openbmc-<v>` (canonical) + `ob-<v>` + bare `<v>` aliases. The bare
    name is accepted as an ALIAS, so `zipmi nvidia ...` works while the
    `oem`/flavor catalog still lists only the canonical `openbmc-<v>` rows
    (aliases don't add catalog entries — the original de-clutter intent)."""
    obmc = set(_openbmc_vendor_keys())
    _extra_aliases = {
        "megarac": ["ami"],
        "supermicro-x11": ["supermicro"],  # legacy `oem supermicro` → X11
    }
    for vkey, vinfo in VENDORS.items():
        if vkey in obmc:
            continue
        _add_vendor_parser(parent_sub, vkey, vinfo["blurb"],
                           aliases=_extra_aliases.get(vkey, ()))
    for vkey in _openbmc_vendor_keys():
        _add_vendor_parser(parent_sub, f"openbmc-{vkey}", VENDORS[vkey]["blurb"],
                           vendor_key=vkey, aliases=[f"ob-{vkey}", vkey])
    _add_openbmc_group_parser(parent_sub)


def add_oem_subparsers(top_sub) -> None:
    """Wire the OEM verbs onto the existing top-level subparser group."""
    # Vendors are reached ONLY via `zipmi oem <vendor>` (see below) — no top-level
    # per-vendor shortcuts, so the top-level --help stays legible. `zipmi oem`
    # lists the vendors; `zipmi oem <vendor>` lists/runs its commands.

    # Standard IPMI 2.0 (Table G-1) commands by name. A catalogue, not
    # an OEM vendor -> registered as a top-level verb only, never added
    # to VENDORS, so `zipmi oem` does not list it.
    _add_vendor_parser(
        top_sub, "ipmi",
        "standard IPMI cmd by name (omit to list Table G-1)",
        cmd_noun="IPMI cmd",
    )

    # Dispatcher: `zipmi oem` and `zipmi oem <vendor> ...`
    oem = top_sub.add_parser("oem",
                             help="OEM cmd dispatcher (omit args to list "
                                  "available vendors)")
    oem.set_defaults(func=cmd_oem_list_vendors)
    oem_sub = oem.add_subparsers(dest="vendor")
    _add_all_vendor_parsers(oem_sub)


__all__ = [
    "VENDORS",
    "add_oem_subparsers",
    "cmd_oem_list_vendors",
    "cmd_oem_run",
]
