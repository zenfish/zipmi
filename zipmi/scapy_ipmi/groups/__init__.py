"""
zipmi.scapy_ipmi.groups — IPMI Group Extension cmd tables (NetFn 0x2C).

WHAT     One module per "defining body" that can hang commands off the
         IPMI Group Extension Network Function (0x2C/0x2D). The first
         data byte of every NetFn 0x2C request is the *group code*;
         the rest is body-specific cmd format.

         Group codes (IPMI 2.0 Appendix G + body specs):

           0x00 PICMG (PCI Industrial Computer Manufacturers' Group)
           0x03 VITA  (VITA 46.11 — VPX / OpenVPX)
           0x04 HPM   (PICMG HPM.x — Hardware Platform Management)
           0xDC DCMI  (Data Center Manageability Interface, Intel/DMTF)

WHY      OEM cmds (NetFn 0x30) are per-vendor and disambiguated by
         IANA. Group cmds (NetFn 0x2C) are *standardised across vendors*
         and disambiguated by the group code. Treating them as a
         separate namespace from OEM keeps the code honest about which
         registry the cmd lives in.

LOAD     `zipmi.load_group("dcmi")` — analogue of load_vendor(). Group
         codes are static, not IANA-vendor; loading just registers the
         name table.

RELATED  groups/_registry.py (registry + register()), oem/_registry.py
         (sister namespace), cli/oem_cmds.py (CLI dispatcher reused
         for groups).
"""
from . import _registry
from . import dcmi  # noqa: F401  — auto-register on package import

__all__ = ["_registry", "dcmi"]
