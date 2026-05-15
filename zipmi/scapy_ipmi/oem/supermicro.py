"""
zipmi.scapy_ipmi.oem.supermicro — Supermicro X11 OEM commands (IANA 10876).

WHAT     Names + sub-command tables for Supermicro libipmi.so OEM
         dispatch surface, ingested from the smcipmi RE work at
         /Volumes/yyy/phd/bmc/supermicro/smcipmi-reversing/.

WHY      Supermicro X11SSZ-QF (192.168.0.24) — currently down — exposes
         four primary OEM cmds (0x30 0x68 / 0x6E / 0x70 / 0xA0) each
         dispatching ~30 sub-commands. Several have shell-injection
         attack surface documented in EXPLOITS.md (UtilRestoreConfig
         path traversal, LanConfigApply system() chain, ReceiveBTLData
         bootloader update path, htpasswd injection via UtilWsmanAddAccount).

LOAD     `zipmi.load_vendor("supermicro")` — populates OEM_CMD_NAMES.

REFS     /Volumes/yyy/phd/bmc/supermicro/smcipmi-reversing/oem-command-summary.md
         /Volumes/yyy/phd/bmc/supermicro/smcipmi-reversing/EXPLOITS.md
         /Volumes/yyy/phd/bmc/supermicro/smcipmi-reversing/supermicro-oem-complete.md
         /Volumes/yyy/phd/bmc/supermicro/smcipmi-reversing/ipmi_lan-oem-commands.md
         /Volumes/yyy/phd/bmc/supermicro/smcipmi-reversing/shell-injection-analysis.md

LIVE     X11SSZ-QF FW 00.48 (Pantsdown-vulnerable AST2400). Test target
         currently down; sub-cmd live status pending re-enumeration.
"""

from __future__ import annotations

from ._registry import register


SM_IANA = 10876


# Top-level OEM cmds. Most ride NetFn 0x30 and dispatch to a large
# sub-command table (see SM_SUBCMDS below); the NetFn 0x3e family is a
# self-contained 3-cmd sequence used by the ATEN AlUpdate firmware-
# update utility (sent in order, no sub-byte).
SM_TOP_CMDS = {
    (0x30, 0x68): "Supermicro OEMCommandSet_68 (Network/Web Config)",
    (0x30, 0x6E): "Supermicro OEMCommandSet_6E (debug/unknown)",
    (0x30, 0x70): "Supermicro OEMCommandSet_70 (File / FW / Hostname / Config)",
    (0x30, 0xA0): "Supermicro OEMCommandSet_A0 (diagnostic — newer FW only)",
    # ATEN AlUpdate live firmware exfil (X10/X11/X12/X13 ASPEED-based
    # Supermicro BMCs). Sequence: cmd 0x1d kicks off
    # `/bin/restore_file.sh 0` on the BMC, which dd's /dev/mtdblock5
    # ("all_part" — entire flash) to /tmp/dump_flash. cmd 0x1e polls
    # readiness, returning size when done. cmd 0x1f streams 55-byte
    # chunks until the whole image (~33 MB) is on the wire. Whole
    # exchange ~800k packets back and forth. Pre-auth: works once you
    # have RMCP+ session, even with cipher-0 / null integrity.
    # Reference: https://trouble.org/?p=1227 (Farmer, 2026-02-01)
    (0x3E, 0x1D): "Supermicro AlUpdate FwDumpStart (CRITICAL: live fw exfil → /tmp/dump_flash via mtdblock5)",
    (0x3E, 0x1E): "Supermicro AlUpdate FwDumpStatus (poll size, returns 0x01 + 24-bit BE size when ready)",
    (0x3E, 0x1F): "Supermicro AlUpdate FwDumpRead (55-byte chunks, repeated until /dev/mtdblock5 fully streamed)",
}


# Sub-command tables. The first request data byte selects the sub-cmd;
# we model these as a (parent_netfn, parent_cmd) -> {sub_byte: name} map.
# Names are taken verbatim from the smcipmi RE notes; "(unnamed)" entries
# are sub-cmds whose handler symbol wasn't recovered.

SM_SUBCMDS: dict[tuple[int, int], dict[int, str]] = {
    (0x30, 0x68): {
        0x00: "(empty)",
        0x01: "NTP config (needs params)",
        0x02: "Status",
        0x03: "Cert dates",
        0x04: "RADIUS status",
        0x05: "SMTP config (needs params)",
        0x06: "LDAP status",
        0x07: "IPv6 config — HIGH RISK (LanConfigApply path)",
        0x08: "DNS status",
        0x09: "Alert status",
        0x0A: "NTP server IP",
        0x10: "Network config — HIGH RISK (LanConfigApply path)",
        0x20: "iKVM reset",
        0x30: "ISO mount",
        0x31: "ISO mount (variant)",
        0x32: "ISO umount",
    },
    (0x30, 0x70): {
        # File transfer (Low risk)
        0x01: "StartFileUpload",
        0x02: "File status (returns 01)",
        0x04: "Upload status check",
        0x05: "Download init (returns 44)",
        0x0B: "Unknown",
        0x0C: "Debug/diag read (returns 00)",
        0x0D: "Debug/diag read (returns 00 00)",
        # Firmware upgrade (CRITICAL — calls system() in ReceiveBTLData)
        0x10: "OEMStartFWUpgradeCmd — CRITICAL",
        0x11: "OEMUploadFWCmd — CRITICAL",
        0x12: "OEMFlashFWCmd — CRITICAL (system() in ReceiveBTLData)",
        0x15: "OEMCancelFWUpgradeCmd",
        0x16: "OEMFinalizeFWUpgradCmd (returns 00)",
        # Hostname (HIGH; sanitized via EscapeShellCmd)
        0x26: "OEMHostNameOperationCmd (sub: 0x01 set, 0x02 get)",
        # Config backup/restore (CRITICAL — UtilRestoreConfig path traversal)
        0x30: "StartRestore — CRITICAL (path traversal via UtilRestoreConfig)",
        0x31: "RestoreStatus (empty resp)",
        0x32: "Unknown (empty resp)",
        0x33: "RestoreStatus (00 00 00 00)",
        0x39: "Unknown",
        # Platform / GPIO
        0x70: "Platform info (01 00 00 00 20 20 20 20)",
        0x71: "(empty)",
        0x72: "GPIO read (00 00)",
        0x74: "GPIO read",
        0x75: "GPIO read",
        0x76: "GPIO read",
        0x77: "GPIO write? (needs params)",
        # SSL / cert (HIGH)
        0xC0: "SSL config get",
        0xC1: "SSL config set",
        0xC2: "Cert operation",
        0xC3: "Cert status (returns 00)",
        0xC4: "Key operation",
        0xC5: "Port config (HTTP=0x50 / HTTPS=0x1bb)",
        # Production / debug
        0xED: "Production debug (needs params)",
        0xEE: "(empty)",
        0xEF: "error 0xFF",
        0xF0: "Buffer (16x 00)",
        0xF1: "(empty)",
        0xF4: "(empty)",
        0xF5: "(empty)",
        0xF6: "(empty)",
        0xF7: "(00 00)",
        0xFA: "(empty)",
        0xFB: "(empty)",
        0xFC: "Status (02 ff)",
        0xFD: "(empty)",
        0xFE: "(00)",
    },
    # 0x30 0x6E and 0x30 0xA0 sub-tables not yet enumerated in the RE.
}


# Shell-injection / privilege-escalation primitives documented in EXPLOITS.md.
# Useful for `zipmi scan` security probes once we wire those checks in.

SM_ATTACK_PRIMITIVES = {
    "config_restore_traversal": {
        "cmd": (0x30, 0x70),
        "sub": 0x30,
        "function": "UtilRestoreConfig (0x6ca80)",
        "shellfmt": "/bin/restore /tmp/%s/%s %d",
        "sanitization": "NONE — path traversal likely",
        "notes": "Upload malicious config via 0x70 0x01-0x05 then trigger 0x30 with traversal",
    },
    "lan_config_inject": {
        "cmd": (0x30, 0x68),
        "sub": [0x07, 0x10],
        "function": "LanConfigApply (0x94b48)",
        "shellfmt": "/sbin/ifconfig %s ... ; /sbin/udhcpc -b -i %s --hostname %s&",
        "sanitization": "UNKNOWN — needs verification",
        "notes": "Crafted interface name with shell metachars",
    },
    "fw_upgrade_chain": {
        "cmd": (0x30, 0x70),
        "sub": [0x10, 0x11, 0x12, 0x16],
        "function": "ReceiveBTLData (0x4fdec)",
        "shellfmt": "system() with firmware-derived paths",
        "sanitization": "Firmware signature validation (if present)",
        "notes": "Full BMC compromise via signed-image bypass",
    },
    "hostname_inject": {
        "cmd": (0x30, 0x70),
        "sub": 0x26,
        "function": "set_hostname (0x945d0)",
        "shellfmt": "hostname %s",
        "sanitization": "EscapeShellCmd blocks metachars",
        "notes": "Sanitized; not exploitable as-is",
    },
    "set_user_password_inject": {
        "cmd": (0x06, 0x47),
        "function": "UtilWsmanAddAccount (htpasswd injection)",
        "shellfmt": "htpasswd ... <password-with-shell-metachars>",
        "sanitization": "EscapeShellCmd NOT applied here",
        "notes": "Password field used unsanitized to invoke htpasswd",
        "poc": "ipmitool ... raw 0x06 0x47 0x03 0x02 'test;touch /tmp/pwned'",
    },
}


# Build the registry payload.
SM_CMD_NAMES = dict(SM_TOP_CMDS)
for parent, subs in SM_SUBCMDS.items():
    nf, cmd = parent
    parent_name = SM_TOP_CMDS.get(parent, f"Supermicro {nf:02x}/{cmd:02x}")
    for sub, sub_name in subs.items():
        # Encode sub-cmd as a synthetic key. Real wire dispatch is by data
        # byte 0; we stash sub-cmds under (parent_netfn, parent_cmd) in a
        # separate exposed dict (SM_SUBCMDS above) for callers that care.
        # Keep the top-level mapping focused on real (NetFn, cmd) pairs.
        pass


register("supermicro", SM_IANA, SM_CMD_NAMES)


__all__ = ["SM_IANA", "SM_TOP_CMDS", "SM_SUBCMDS", "SM_ATTACK_PRIMITIVES"]
