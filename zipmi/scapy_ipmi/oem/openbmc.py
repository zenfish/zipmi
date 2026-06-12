"""
zipmi.scapy_ipmi.oem.openbmc — OpenBMC OEM umbrella / manifest.

WHAT     A manifest of every OpenBMC OEM flavor zipmi knows, plus helpers to
         load one or all of them and to drive vendor detection. OpenBMC is
         open source, so its "OEM" surface is really a set of vendor
         providers (intel-ipmi-oem, fb-ipmi-oem, google-ipmi-sys, ...), each
         of which is its own zipmi module. This module is the index over
         those modules — adding a new OpenBMC vendor is: write one
         `oem/<vendor>.py` that calls `register(...)`, then add one row here.

WHY      OpenBMC is the open BMC stack behind Meta/Google/Intel/IBM/Ampere/
         Nvidia fleets. Unlike a single proprietary BMC (Dell=674), OpenBMC
         spans many vendor IANAs and reuses the raw vendor NetFns 0x30..0x3E,
         so the same (NetFn,cmd) means different things per vendor. The
         manifest records, per vendor, how to load it and how to detect it.

FINGERPRINT
         OpenBMC advertises NO stable IANA over IPMI — the local romulus
         target reports Get Device ID manufacturer-id 0 ("Unknown") even
         though OpenPOWER OEM handlers are loaded. Remote identification is
         strongest over Redfish/bmcweb: GET /redfish/v1/Managers/bmc and look
         for Oem.OpenBmc and a manager named "bmc". Over IPMI, probe the
         per-vendor OEM bands below and treat a non-0xC1 ("invalid command")
         completion as "this vendor's provider is present". See
         /Users/zen/phd/bmc/openbmc/SURVEY-OPENBMC.md for the full playbook.

LOAD     `zipmi.load_vendor("openbmc")` loads ALL OpenBMC vendor tables
         (convenience for offline pcap dissection). For live targeting,
         prefer loading the single vendor you are talking to so colliding
         (NetFn,cmd) names resolve unambiguously — e.g.
         `zipmi.load_vendor("intel")`.

SOURCE   /Users/zen/phd/bmc/openbmc/OPENBMC_OEM_IPMI.md (per-source catalog).
"""

from __future__ import annotations

import importlib


# vendor_key → manifest row. `iana` is informational (most OpenBMC vendors
# put NO IANA on the wire — they ride raw NetFns 0x30..0x3E). `detect` is a
# harmless low-privilege probe used for vendor identification:
#   ("oem",   netfn, cmd)        — raw vendor-NetFn read
#   ("group", group_code, cmd)   — NetFn 0x2C group-extension read
#   ("oemsub", netfn, cmd, sub)  — NetFn 0x2E IANA OEM read with a sub-byte
# A reply whose completion code is NOT 0xC1 (invalid command) indicates the
# vendor's provider is present.
OPENBMC_VENDORS: dict[str, dict] = {
    "intel":     {"iana": 343,   "module": "intel",
                  "netfns": (0x30, 0x32, 0x3E, 0x08),
                  "detect": ("oem", 0x30, 0x01),
                  "repo": "openbmc/intel-ipmi-oem"},
    "facebook":  {"iana": 4337,  "module": "facebook",
                  "netfns": (0x30, 0x36, 0x38),
                  "detect": ("oem", 0x38, 0x01),
                  "repo": "openbmc/fb-ipmi-oem"},
    "google":    {"iana": 11129, "module": "google",
                  "netfns": (0x2E,),
                  "detect": ("oemsub", 0x2E, 0x32, 7),
                  "repo": "openbmc/google-ipmi-sys"},
    "ampere":    {"iana": 40981, "module": "ampere",
                  "netfns": (0x3C,),
                  "detect": ("oem", 0x3C, 0x02),
                  "repo": "openbmc/ampere-ipmi-oem"},
    "openpower": {"iana": 2,     "module": "openpower",
                  "netfns": (0x32, 0x3A),
                  "detect": None,   # SYSTEM_INTERFACE-priv writes only; no safe read
                  "repo": "openbmc/openpower-host-ipmi-oem"},
    "inspur":    {"iana": 37945, "module": "inspur",
                  "netfns": (0x3C,),
                  "detect": ("oem", 0x3C, 0x01),
                  "repo": "openbmc/inspur-ipmi-oem"},
    "foxconn":   {"iana": None,  "module": "foxconn",
                  "netfns": (0x34,),
                  "detect": ("oem", 0x34, 0x03),
                  "repo": "openbmc/foxconn-ipmi-oem"},
    "wistron":   {"iana": None,  "module": "wistron",
                  "netfns": (0x30,),
                  "detect": None,   # SYSTEM_INTERFACE-priv; collides with Intel 0x30
                  "repo": "openbmc/wistron-ipmi-oem"},
    "nvidia":    {"iana": None,  "module": "nvidia",
                  "netfns": (0x2C,),   # group 0x3C under NetFn 0x2C
                  "detect": ("group", 0x3C, 0x34),
                  "repo": "openbmc/phosphor-host-ipmid (oem/nvidia)"},
}


def load(vendor: str) -> None:
    """Load a single OpenBMC vendor's OEM table by key (see OPENBMC_VENDORS)."""
    if vendor not in OPENBMC_VENDORS:
        raise KeyError(
            f"unknown OpenBMC vendor {vendor!r}; "
            f"known: {', '.join(sorted(OPENBMC_VENDORS))}"
        )
    importlib.import_module(f"zipmi.scapy_ipmi.oem.{OPENBMC_VENDORS[vendor]['module']}")


def load_all() -> None:
    """Load every OpenBMC vendor table.

    Convenient for dissecting a mixed pcap. For live targeting, prefer
    `load()` of the single vendor you are talking to: several vendors reuse
    the same raw (NetFn,cmd) with different meanings, and last-loaded wins in
    the shared OEM name registry.
    """
    for vendor in OPENBMC_VENDORS:
        load(vendor)


# Importing the umbrella loads all vendor tables (matches load_vendor("openbmc")
# semantics: the user explicitly asked for OpenBMC, so register everything).
load_all()


__all__ = ["OPENBMC_VENDORS", "load", "load_all"]
