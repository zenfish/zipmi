"""
zipmi — Scapy-based IPMI library, CLI, and virtual BMC.

WHAT     Top-level package. Importing `zipmi` registers all base Scapy layers
         (RMCP, ASF, IPMI 1.5/2.0, RAKP, command payloads). OEM vendor modules
         are NOT auto-loaded — call `zipmi.load_vendor("dell")` to opt in.
WHY      Keep the base namespace clean and the OEM dispatch tables explicit so
         a packet capture from one vendor cannot accidentally be decoded with
         another vendor's command names.
SUCCESS  `python -c "import zipmi; from scapy.all import UDP; print(UDP(dport=623))"`
         shows RMCP as a known sublayer.
TARGET   IPMI 1.5/2.0 over UDP/623; ASF (DSP0136).
BUILD    pip install -e .
RELATED  docs/architecture.md, ~/.claude/plans/fizzy-skipping-biscuit.md
"""

from __future__ import annotations

import importlib

__version__ = "0.1.0"  # single source of truth; pyproject reads this via dynamic version

# Importing scapy_ipmi triggers layer registration via its __init__.py.
from . import scapy_ipmi  # noqa: F401  (side-effect import)


# CLI-facing vendor key → on-disk module name. Most are 1:1; the
# exception is `idrac6`, which is the user-facing key for the iDRAC6
# fullfw RE'd dispatch table that historically lived in `oem/dell.py`.
_VENDOR_ALIAS: dict[str, str] = {
    "idrac6": "dell",
    # OpenBMC vendor flavors — see scapy_ipmi/oem/openbmc.py for the manifest.
    "ibm": "openpower",
    "meta": "facebook",
    "fb": "facebook",
    "ami": "megarac",
    # Supermicro split: X11 (AMI+smcipmitool) vs X14 (AST2600 OpenBMC + SMC OEM).
    "supermicro-x11": "supermicro",
    "supermicro-x14": "supermicro_x14",
}


def load_vendor(name: str) -> None:
    """Register a vendor's OEM command tables into the dispatch registry.

    Example:
        >>> import zipmi
        >>> zipmi.load_vendor("idrac6")     # 192 cmds RE'd from iDRAC6 fw
        >>> zipmi.load_vendor("idrac9")     # 293 dispatch tuples, Dell IANA 674
        >>> zipmi.load_vendor("idrac10")    # 383 dispatch tuples, Dell IANA 674
        >>> zipmi.load_vendor("supermicro")
    """
    module = _VENDOR_ALIAS.get(name, name)
    importlib.import_module(f"zipmi.scapy_ipmi.oem.{module}")


__all__ = ["__version__", "load_vendor", "scapy_ipmi"]
