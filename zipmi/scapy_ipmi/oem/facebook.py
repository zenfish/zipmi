"""
zipmi.scapy_ipmi.oem.facebook — Facebook/Meta OpenBMC OEM commands.

WHAT     The `fb-ipmi-oem` provider used across Meta's OpenBMC platforms
         (Yosemite, Tioga Pass, etc). Commands ride raw vendor NetFns
         0x30, 0x36, 0x38. NetFn 0x38 is the Bridge-IC (BIC) passthrough
         family — many sleds put a satellite Bridge-IC behind the BMC.

WHY      Meta is one of the largest OpenBMC deployers. BIC passthrough
         (0x38/0x01,0x03) exposes per-sled GPIO/info, Set Host Power State
         (0x38/0x0C) is host power control, Crashdump (0x30/0x70) pulls host
         crash data, and Set System GUID (0x30/0xEF) rewrites identity.

WIRE     Raw vendor NetFns. Meta's IANA is 40981 — confirmed from source as
         `iana = {0x15, 0xA0, 0x0}` (LSB-first → 0xA015 = 40981) in fb-ipmi-oem
         `include/commandutils.hpp:30`. It is NOT a NetFn-0x2E selector; it
         rides as a 3-byte payload prefix inside some 0x38 (Bridge-IC)
         commands. Registered with None so it never claims a Get Device ID
         manuf-id slot. (The earlier "4337" was wrong.)

NOTE     fb-ipmi-oem also overrides the DCMI group (0x2C/0xDC) power cmds;
         those are already covered by groups/dcmi.py.

LOAD     `zipmi.load_vendor("facebook")`  (alias: "meta")

SOURCE   github.com/openbmc/fb-ipmi-oem (oemcommands.cpp, biccommands.cpp,
         appcommands.cpp). Catalogued in
         the OpenBMC OEM IPMI survey (upstream source review) §2.2.
"""

from __future__ import annotations

from ._registry import register


# Meta's IANA (commandutils.hpp:30 `{0x15,0xA0,0x0}` = 40981). Metadata only —
# registered as None below so a Get Device ID manuf-id lookup never resolves
# to "facebook"; the value rides as a payload prefix inside 0x38 cmds, not as
# a NetFn-0x2E selector.
FACEBOOK_IANA = 40981

FACEBOOK_CMD_NAMES: dict[tuple[int, int], str] = {
    (0x30, 0x49): "Facebook Get 80-Port POST Record",
    (0x30, 0x52): "Facebook Set Boot Order",
    (0x30, 0x53): "Facebook Get Boot Order",
    (0x30, 0x57): "Facebook Get HTTPS Boot Data",
    (0x30, 0x58): "Facebook Get HTTPS Boot Attr",
    (0x30, 0x70): "Facebook Crashdump",
    (0x30, 0xEF): "Facebook Set System GUID",
    (0x36, 0x10): "Facebook Q Set Proc Info",
    (0x36, 0x11): "Facebook Q Get Proc Info",
    (0x36, 0x12): "Facebook Q Set DIMM Info",
    (0x36, 0x13): "Facebook Q Get DIMM Info",
    # NetFn 0x38 (Bridge-IC) family: mandatory Meta IANA 40981 prefix on the
    # wire, LSB-first 0x15 0xA0 0x00 — baked so the CLI auto-supplies it. Some
    # (0x03/0x19/0x25) reject a wrong IANA (biccommands.cpp:219/302/353); the
    # rest unpack it positionally (biccommands.cpp:61/158/251/401). Variable
    # args (interface/status/target/...) follow the prefix.
    (0x38, 0x01, 0x15, 0xA0, 0x00): "Facebook BIC Info",
    (0x38, 0x03, 0x15, 0xA0, 0x00): "Facebook Get BIC GPIO State",
    (0x38, 0x08, 0x15, 0xA0, 0x00): "Facebook Send POST Buffer to BMC",
    (0x38, 0x0C, 0x15, 0xA0, 0x00): "Facebook Set Host Power State",
    (0x38, 0x19, 0x15, 0xA0, 0x00): "Facebook Get BIOS Flash Size",
    (0x38, 0x25, 0x15, 0xA0, 0x00): "Facebook Clear CMOS",
    (0x38, 0x33, 0x15, 0xA0, 0x00): "Facebook 1S 4-byte POST Buffer",
}


# Vendor detection: "BIC Info" (0x38/0x01) is a strong Meta positive — the
# Bridge-IC NetFn 0x38 family is Meta-specific.
FACEBOOK_DETECT_PROBE = (0x38, 0x01, 0x15, 0xA0, 0x00)  # BIC Info + Meta IANA


register("facebook", None, FACEBOOK_CMD_NAMES)


__all__ = ["FACEBOOK_IANA", "FACEBOOK_CMD_NAMES", "FACEBOOK_DETECT_PROBE"]
