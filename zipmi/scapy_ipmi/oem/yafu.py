"""zipmi.scapy_ipmi.oem.yafu — AMI YAFU flash + memory protocol (NetFn 0x32).

WHAT     YAFU is AMI's "Yet Another Firmware Updater" IPMI protocol, the
         firmware-flash and BMC-side memory R/W command family that ships in
         every AMI-derived BMC stack (MegaRAC SP-X, Supermicro X10-X13,
         Advantech ASMB, HPE/HPE XD670, Quanta / GIGABYTE MegaRAC relabels).
         NOT a per-vendor OEM set — it's a *shared protocol family*, source-
         compiled from `links/libipmi/data/libipmi_AMIOEM.c` (path leaked in
         debug strings of every vendor's libipmi.so). Same NetFn + cmd bytes
         across every AMI-lineage BMC.

WIRE     NetFn 0x32. Cmd block 0x01–0x60 = YAFU proper (info / mode / flash-I/O
         / memory / boot / device-mgmt). Cmds 0x66–0xEF = privileged AMI OEM
         extensions that ride the same NetFn (RestoreFactoryDefaults, TFTP
         fwupdate, SetRootPassword, ReplaceSignedImageKey, ManageBMCConfig,
         SetSSLCert, ...). Anomaly: `RunInitAgent` is 0x0A/0x2C (Storage NetFn,
         not 0x32) — deliberate obscuring or a routing bug (see protocol.html).
         All handlers require Administrator privilege (BMC-side dispatch table
         priv byte 0x04, confirmed on ASMB-787 libipmimsghndlr.so g_AMI_CmdHndlr).

TRANSPORT-AGNOSTIC. Same NetFn 0x32 cmds ride FOUR transports (yafuflash-4.55.5
         source, Common/ComLine.c + main.c):
           -nw / NETWORK_MEDIUM  LAN IPMI 2.0 RMCP+ session (what zipmi speaks)
           -kcs / KCS_MEDIUM     in-band host → LPC KCS (no remote reach)
           -cd / USB_MEDIUM      BMC's USB IPMI gadget. Client bootstraps via
                                 KCS first, sends OnEnableUSBDevice() to
                                 activate the gadget, then switches medium
                                 to USB. Physical-USB attack surface bypasses
                                 LAN firewall entirely.
           -serial / SERIAL_MEDIUM  IPMI over serial (with -baudrate, -term).
         Same catalog below applies to any of these — only framing differs.
         zipmi currently drives the LAN path only.

TIERS    Each entry carries a `tier`:
           safe        read-only info / query — no BMC state change
           mutates     changes BMC runtime state (bounded / recoverable)
           destructive flash write, factory reset, root-password change,
                       fw update kickoff, signing-key replace — GUARDED
                       (client SHOULD confirm before sending)

STATE    OPCODES + wire framing from static RE of the AMI YAFU protocol:
         BMC-side handlers  = ASMB-787 (Advantech, MegaRAC SP-X 4.0)
                              libipmimsghndlr.so g_AMI_CmdHndlr, decomp by
                              Ghidra 12.0 DEV (see bmc/AMI/yafu/decomp/).
         Client-side names  = SMCIPMITool 2.30.0 (build 250915) Java decomp,
                              cross-checked with each vendor's libipmi.so
                              IPMICMD_AMI* wrappers. Names + arg lists match
                              across every AMI-lineage sample.
         Wire lens          = LIBIPMI_Send_RAW_IPMI2_0_Command dwReqLen /
                              respLen immediates (protocol.html §4).

LOAD     zipmi.load_vendor("yafu")

SOURCE   bmc/AMI/yafu/protocol.html + decomp/bmc_side_yafu_handlers.c
         AUTHORITATIVE: bmc/AMI/yafu/src/libipmi_headers/libipmi_AMIOEM.h
                        (132 IPMICMD_AMI* prototypes + struct types, ASUS ASMB9
                        GPL SP-X drop) and bmc/AMI/yafu/src/yafuflash-4.55.5/
                        (full C source of AMI's Yafuflash tool). Grep-first, not
                        decomp-first.
         Cross-refs: scapy_ipmi/oem/supermicro_smcipmi_names.py (client bytes),
                     scapy_ipmi/oem/megarac.py (sibling 0x30 AMI OEM surface).

GAP      A newer AMI Yafuflash Linux binary (~/Yafuflash, unstripped + DWARF)
         exposes 38 IPMICMD_AMIYAFU* symbols (vs 31 in the ASUS 2020 header).
         The 7 delta names are NOT in this catalog yet — cmd-byte mapping needs
         Ghidra of the arm libipmi.so from a newer fw:
           IPMICMD_AMIYAFUActivateFlashMode_BackwardCompatible  — legacy variant
           IPMICMD_AMIYAFUCheckMapDifference                    — image-diff check
           IPMICMD_AMIYAFUGetFlshStatus                         — flush status (?)
           IPMICMD_AMIYAFUGetImgSize                            — image-size query
           IPMICMD_AMIYAFUReplaceSignedImageKey                 — YAFU-prefixed variant of 0x32/0xA9
           IPMICMD_AMIYAFUStateless                             — session-less variant
           IPMICMD_AMIYAFUWritetoFile                           — direct file-write (bypasses flash-mode?)

LIVE     HPE XD670 (AMI MegaRAC / Gigabyte MfgID 15370) live-confirmed:
           GetFlashInfo (0x32/0x01)    req_len=12 → resp 32B (JEDEC-like at off 6-11)
           GetFirmwareInfo (0x32/0x02) req_len=12 → resp 40B (ASCII "Rom.ima" at off 24-30)
           GetFMHInfo (0x32/0x03)      req_len=12 → CC 0xCC (needs param byte selector)
           GetStatus (0x32/0x04)       req_len=12 → CC 0x25 (YAFU state code, idle)
         The AMI-standard YAFU req header is 12 bytes: [YafuCmd echo] [11B params].
"""

from __future__ import annotations

from ._registry import register


# Tier constants — semantic labels, not just doc strings.
SAFE = "safe"                # read-only info / query
MUTATES = "mutates"          # bounded BMC state change
DESTRUCTIVE = "destructive"  # flash write / reset / fw kickoff / cred change


# Canonical AMI YAFU catalog. Every AMI-lineage BMC uses these bytes.
# Key: (netfn, cmd)  — no sub-command byte at this layer.
# Priv: 'Admin' throughout (BMC dispatch table priv byte 0x04); one
# exception noted per-entry if BMC-side dispatch decode ever proves otherwise.
YAFU_COMMANDS: dict[tuple[int, int], dict] = {

    # ------------------------------------------------------------------
    # Info / query block (0x01–0x0F)   — SAFE reads, non-destructive
    # ------------------------------------------------------------------
    (0x32, 0x01): {
        "name": "GetFlashInfo", "priv": "Admin", "tier": SAFE, "block": "info",
        "req_len": 12, "resp_len": 32,
        "desc": "Return flash chip metadata (JEDEC ID, size, block layout). "
                "LIVE-CONFIRMED on HPE XD670 (AMI MegaRAC / Gigabyte MfgID "
                "15370): 12-byte request body (YafuCmd + 11B params), 32-byte "
                "response including JEDEC-like bytes at offset 6-11.",
        "request": "byte YafuCmd (echo=0x01) + 11B params (padding)",
        "response": "32B flash chip descriptor",
    },
    (0x32, 0x02): {
        "name": "GetFirmwareInfo", "priv": "Admin", "tier": SAFE, "block": "info",
        "req_len": 12, "resp_len": 40,
        "desc": "Return BMC firmware version + build metadata + image filename. "
                "LIVE-CONFIRMED on HPE XD670: 40-byte response includes ASCII "
                "'Rom.ima' at offset 24-30 (image filename), checksum bytes 8-11.",
        "request": "byte YafuCmd (echo=0x02) + 11B params",
        "response": "40B fw info blob (checksum + name + version fields)",
    },
    (0x32, 0x03): {
        "name": "GetFMHInfo", "priv": "Admin", "tier": SAFE, "block": "info",
        "req_len": 12, "resp_len": None,
        "desc": "Return Firmware Module Header (FMH) inventory — per-module "
                "offsets + checksums. HPE XD670: 12B body → CC 0xCC (Invalid "
                "data field) — parameter selector byte needed; iterate to find.",
        "request": "byte YafuCmd (echo=0x03) + 11B params (module selector TBD)",
        "response": "FMH table (per-module 64-byte entries)",
    },
    (0x32, 0x04): {
        "name": "GetStatus", "priv": "Admin", "tier": SAFE, "block": "info",
        "req_len": 12, "resp_len": None,
        "desc": "YAFU state machine status (flash-mode / idle / in-progress). "
                "HPE XD670 idle: CC 0x25 (YAFU-specific state code — likely "
                "STATE_NOT_ACTIVATED, precedes ActivateFlashMode).",
        "request": "byte YafuCmd (echo=0x04) + 11B params",
        "response": "status byte(s)",
    },

    # ------------------------------------------------------------------
    # Mode (0x10)
    # ------------------------------------------------------------------
    (0x32, 0x10): {
        "name": "ActivateFlashMode", "priv": "Admin", "tier": MUTATES, "block": "mode",
        "req_len": None, "resp_len": None,
        "desc": "Enter flash-programming mode. Precondition for WriteFlash / "
                "EraseFlash / EraseCopyFlash.",
        "request": "byte[] mode",
        "response": "cc",
    },

    # ------------------------------------------------------------------
    # Memory alloc + flash I/O (0x20–0x29)
    # ------------------------------------------------------------------
    (0x32, 0x20): {
        "name": "AllocateMemory", "priv": "Admin", "tier": MUTATES, "block": "flash_io",
        "req_len": 16, "resp_len": 17,
        "desc": "Allocate a BMC-side buffer. Returns 17-byte handle blob whose "
                "bytes [0x0d..0x10] are the RAW malloc() pointer — a live BMC "
                "heap address (defeats heap ASLR).",
        "security": "Infoleak: raw heap ptr returned to client. See "
                    "protocol.html §5 residual (1). Also CANDIDATE remote heap "
                    "R/W via error-path window-widening (residual 2).",
        "request": "byte[] size",
        "response": "17B handle (bytes [0x0d..0x10] = malloc ptr)",
    },
    (0x32, 0x21): {
        "name": "FreeMemory", "priv": "Admin", "tier": MUTATES, "block": "flash_io",
        "req_len": None, "resp_len": None,
        "desc": "Release a buffer previously granted by AllocateMemory.",
        "request": "byte[] addrToBeFreed",
        "response": "cc",
    },
    (0x32, 0x22): {
        "name": "ReadFlash", "priv": "Admin", "tier": SAFE, "block": "flash_io",
        "req_len": None, "resp_len": None,
        "desc": "Read from BMC flash. Read-only.",
        "request": "byte[] offsetToRead, byte readWidth, byte[] sizeToRead",
        "response": "flash bytes",
    },
    (0x32, 0x23): {
        "name": "WriteFlash", "priv": "Admin", "tier": DESTRUCTIVE, "block": "flash_io",
        "req_len": None, "resp_len": 15,
        "desc": "Write payload to BMC flash. Request length = Datalen + 0x11 "
                "(17-byte header + data). Gotcha: Datalen field is mutated "
                "in place (+= 5) before send; caller reusing the struct sees "
                "a corrupted length.",
        "security": "DESTRUCTIVE — modifies persistent flash. Requires prior "
                    "ActivateFlashMode.",
        "request": "byte[] offsetToWrite, byte writeWidth, byte[] rawToWrite",
        "response": "15B",
    },
    (0x32, 0x24): {
        "name": "EraseFlash", "priv": "Admin", "tier": DESTRUCTIVE, "block": "flash_io",
        "req_len": 16, "resp_len": 14,
        "desc": "Erase flash block(s).",
        "security": "DESTRUCTIVE — irreversible without WriteFlash restore.",
        "request": "byte[] blkNumToErase",
        "response": "14B",
    },
    (0x32, 0x25): {
        "name": "ProtectFlash", "priv": "Admin", "tier": MUTATES, "block": "flash_io",
        "req_len": None, "resp_len": None,
        "desc": "Set / clear flash write-protect on a block.",
        "request": "byte[] blkNum, byte protect",
        "response": "cc",
    },
    (0x32, 0x26): {
        "name": "EraseCopyFlash", "priv": "Admin", "tier": DESTRUCTIVE, "block": "flash_io",
        "req_len": None, "resp_len": None,
        "desc": "Erase-then-copy from BMC memory buffer into flash range.",
        "security": "DESTRUCTIVE — flash write.",
        "request": "byte[] memOffset, byte[] flashOffset, byte[] sizeToCopy",
        "response": "cc",
    },
    (0x32, 0x27): {
        "name": "VerifyFlash", "priv": "Admin", "tier": SAFE, "block": "flash_io",
        "req_len": None, "resp_len": None,
        "desc": "Verify flash content against BMC memory buffer.",
        "request": "byte[] memOffset, byte[] flashOffset, byte[] sizeToVerify",
        "response": "cc",
    },
    (0x32, 0x28): {
        "name": "GetECFStatus", "priv": "Admin", "tier": SAFE, "block": "flash_io",
        "req_len": 0, "resp_len": None,
        "desc": "Get EraseCopyFlash operation status.",
        "request": "empty",
        "response": "status",
    },
    (0x32, 0x29): {
        "name": "GetVerifyStatus", "priv": "Admin", "tier": SAFE, "block": "flash_io",
        "req_len": 0, "resp_len": None,
        "desc": "Get VerifyFlash operation status.",
        "request": "empty",
        "response": "status",
    },

    # ------------------------------------------------------------------
    # Memory (0x30–0x34)  — peek/poke primitive, gated by AllocateMemory
    # ------------------------------------------------------------------
    (0x32, 0x30): {
        "name": "ReadMemory", "priv": "Admin", "tier": SAFE, "block": "memory",
        "req_len": 19, "resp_len": 13,
        "desc": "Read from a client-allocated BMC heap buffer. BMC-side gate "
                "confines address to the AllocateMemory window (base ≤ addr < "
                "base+len, addr+readlen ≤ base+len) → CC 0x19 out-of-range on "
                "violation. Not read-anywhere.",
        "security": "Bounded to alloc window. See AllocateMemory heap-addr "
                    "infoleak + error-path window-widening candidates.",
        "request": "byte[] memOffset, byte readWidth, byte[] sizeToRead",
        "response": "13B (data area within window)",
    },
    (0x32, 0x31): {
        "name": "WriteMemory", "priv": "Admin", "tier": DESTRUCTIVE, "block": "memory",
        "req_len": None, "resp_len": 15,
        "desc": "Write into client-allocated BMC heap buffer. Same window "
                "gate as ReadMemory. Request length = Datalen + 0x11 (shares "
                "WriteFlash's 17-byte header).",
        "security": "DESTRUCTIVE if buffer overlaps sensitive heap state via "
                    "AllocateMemory error-path window-widening.",
        "request": "byte[] memOffset, byte writeWidth, byte[] rawToWrite",
        "response": "15B",
    },
    (0x32, 0x32): {
        "name": "CopyMemory", "priv": "Admin", "tier": MUTATES, "block": "memory",
        "req_len": 24, "resp_len": 17,
        "desc": "BMC-internal memcpy between two windows.",
        "request": "byte[] memOffsetSrc, byte[] memOffsetDest, byte[] sizeToCopy",
        "response": "17B",
    },
    (0x32, 0x33): {
        "name": "CompareMemory", "priv": "Admin", "tier": SAFE, "block": "memory",
        "req_len": None, "resp_len": None,
        "desc": "BMC-side memcmp between two windows. Handler not yet decompiled.",
        "request": "byte[] memOffset1, byte[] memOffset2, byte[] sizeToComp",
        "response": "cmp result",
    },
    (0x32, 0x34): {
        "name": "ClearMemory", "priv": "Admin", "tier": DESTRUCTIVE, "block": "memory",
        "req_len": 20, "resp_len": 17,
        "desc": "Zero a window inside the allocated buffer.",
        "request": "byte[] memOffToClear, byte[] sizeToClear",
        "response": "17B",
    },

    # ------------------------------------------------------------------
    # Boot config (0x40–0x42)
    # ------------------------------------------------------------------
    (0x32, 0x40): {
        "name": "GetBootConfig", "priv": "Admin", "tier": SAFE, "block": "boot",
        "req_len": None, "resp_len": None,
        "desc": "Get named boot-config variable (u-boot env).",
        "request": "byte[] varName",
        "response": "var value",
    },
    (0x32, 0x41): {
        "name": "SetBootConfig", "priv": "Admin", "tier": MUTATES, "block": "boot",
        "req_len": None, "resp_len": None,
        "desc": "Set named boot-config variable. Persists across BMC reboot.",
        "security": "u-boot env write — enables bootargs / boot-order tamper. "
                    "Not flash-corrupting but reconfigures next-boot.",
        "request": "byte[] varName, byte[] value",
        "response": "cc",
    },
    (0x32, 0x42): {
        "name": "GetAllBootVars", "priv": "Admin", "tier": SAFE, "block": "boot",
        "req_len": 0, "resp_len": None,
        "desc": "Enumerate every boot-config variable currently set.",
        "request": "empty",
        "response": "var list",
    },

    # ------------------------------------------------------------------
    # Device management (0x50–0x56)
    # ------------------------------------------------------------------
    (0x32, 0x50): {
        "name": "DeactivateFlash", "priv": "Admin", "tier": MUTATES, "block": "device_mgmt",
        "req_len": 0, "resp_len": None,
        "desc": "Exit flash-programming mode.",
        "request": "empty",
        "response": "cc",
    },
    (0x32, 0x51): {
        "name": "ResetDevice", "priv": "Admin", "tier": DESTRUCTIVE, "block": "device_mgmt",
        "req_len": None, "resp_len": None,
        "desc": "Reset the flash device. Also observed on smcipmi as an alias "
                "for DeactivateFlash (X10-X13 stack); handler split fw-dependent.",
        "security": "DESTRUCTIVE — service interruption during flash op.",
        "request": None,
        "response": "cc",
    },
    (0x32, 0x52): {
        "name": "SwitchFlashDevice", "priv": "Admin", "tier": DESTRUCTIVE, "block": "device_mgmt",
        "req_len": None, "resp_len": None,
        "desc": "Switch active flash device (dual-image / dual-flash board).",
        "security": "DESTRUCTIVE — swaps which flash the BMC boots from.",
        "request": "byte device",
        "response": "cc",
    },
    (0x32, 0x53): {
        "name": "RestoreFlashDevice", "priv": "Admin", "tier": MUTATES, "block": "device_mgmt",
        "req_len": None, "resp_len": None,
        "desc": "Restore previous flash-device selection.",
        "request": "byte device",
        "response": "cc",
    },
    (0x32, 0x54): {
        "name": "DualImageSupport", "priv": "Admin", "tier": SAFE, "block": "device_mgmt",
        "req_len": None, "resp_len": None,
        "desc": "Query / configure dual-image capability. Also exposed on "
                "NetFn 0x30 cmd 0x8f (AMIDualImageSupport, megarac.py).",
        "request": "byte op",
        "response": "capability info",
    },
    (0x32, 0x55): {
        "name": "FirmwareSelectFlash", "priv": "Admin", "tier": MUTATES, "block": "device_mgmt",
        "req_len": None, "resp_len": None,
        "desc": "Select which flash the next fw update targets.",
        "request": "byte flash",
        "response": "cc",
    },
    (0x32, 0x56): {
        "name": "ActivateFlashDevice", "priv": "Admin", "tier": DESTRUCTIVE, "block": "device_mgmt",
        "req_len": None, "resp_len": None,
        "desc": "Activate a flash device (post-write commit).",
        "security": "DESTRUCTIVE — commits a newly-written image as active.",
        "request": "byte device",
        "response": "cc",
    },

    # ------------------------------------------------------------------
    # Privileged AMI OEM extensions on the SAME NetFn 0x32 (0x66–0xEF)
    # Not YAFU-block-proper, but ride the same dispatch. Included so
    # `zipmi oem yafu` surfaces the full NetFn-0x32 attack surface.
    # ------------------------------------------------------------------
    (0x32, 0x66): {
        "name": "AMIRestoreFactoryDefaults", "priv": "Admin", "tier": DESTRUCTIVE,
        "block": "privileged",
        "req_len": 0, "resp_len": 1,
        "desc": "Full BMC config wipe. Zero payload — one authenticated packet. "
                "Most minimal privileged command in the binary.",
        "security": "DESTRUCTIVE — full config reset. Zero-arg = one-shot wipe.",
        "request": "NULL, length 0",
        "response": "1B cc",
    },
    (0x32, 0x87): {
        "name": "AMIStartTFTPFwupdate", "priv": "Admin", "tier": DESTRUCTIVE,
        "block": "privileged",
        "req_len": 2, "resp_len": 1,
        "desc": "Trigger BMC to fetch + flash firmware from pre-configured TFTP "
                "server. Artifact: debug printf('Size: %d', 2) left in prod.",
        "security": "DESTRUCTIVE — remote fw update from attacker-controlled TFTP "
                    "if PreserveCfg + server config were tampered.",
        "request": "byte PreserveCfg, byte (2B total)",
        "response": "1B cc",
    },
    (0x32, 0x91): {
        "name": "AMISetRootPassword", "priv": "Admin", "tier": DESTRUCTIVE,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "3-op state machine: Op 0x00 disable / 0x01 enable / 0x02 set "
                "cleartext Linux root password. Password is APPLICATION-LAYER "
                "CLEARTEXT (no hash) — on the wire only as protected as the "
                "session cipher (cipher 0 = plaintext).",
        "security": "DESTRUCTIVE — takes over BMC Linux root account. "
                    "Cleartext password over IPMI session.",
        "request": "byte Operation, byte[64] Password (null-terminated, strncpy cap 0x40)",
        "response": "cc",
    },
    (0x32, 0xa9): {
        "name": "AMIYAFUReplaceSignedImageKey", "priv": "Admin", "tier": DESTRUCTIVE,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "Replace firmware signing pubkey. UNCHECKED memcpy in the "
                "handler (see security.html).",
        "security": "DESTRUCTIVE — installs attacker key as fw-signing trust "
                    "root. Unchecked memcpy = candidate memory corruption.",
        "request": "byte[] key",
        "response": "cc",
    },
    (0x32, 0xac): {
        "name": "AMIAddLicenseKey", "priv": "Admin", "tier": MUTATES,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "Install AMI BMC license key.",
        "request": "byte[] key",
        "response": "cc",
    },
    (0x32, 0xad): {
        "name": "AMIGetLicenseValidity", "priv": "Admin", "tier": SAFE,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "Query license validity.",
        "request": "empty",
        "response": "validity blob",
    },
    (0x32, 0xe5): {
        "name": "AMIManageBMCConfig", "priv": "Admin", "tier": DESTRUCTIVE,
        "block": "privileged",
        "req_len": 0x12, "resp_len": None,
        "desc": "Broad config mgmt. Parameter 0x01=Backup, 0x02=Restore. "
                "Also exposed on NetFn 0x30 cmd 0xe5 (megarac.py).",
        "security": "DESTRUCTIVE if Restore param — overwrites live config.",
        "request": "18B struct (Parameter byte + payload)",
        "response": "cc + backup/restore data",
    },
    (0x32, 0xe6): {
        "name": "AMIRestartWebService", "priv": "Admin", "tier": DESTRUCTIVE,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "Restart BMC web server. Kills active web sessions.",
        "security": "Service interruption; may drop attacker's own webui session.",
        "request": "empty",
        "response": "cc",
    },
    (0x32, 0xec): {
        "name": "AMISetSSLCert", "priv": "Admin", "tier": MUTATES,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "Install SSL certificate.",
        "security": "Replaces web-mgmt cert — MITM chain if attacker installs "
                    "own cert + steers clients.",
        "request": "byte[] pem",
        "response": "cc",
    },
    (0x32, 0xee): {
        "name": "AMISwitchMUX", "priv": "Admin", "tier": MUTATES,
        "block": "privileged",
        "req_len": None, "resp_len": None,
        "desc": "MUX switch (USB / KVM multiplexing).",
        "request": "byte muxSel",
        "response": "cc",
    },
    (0x32, 0xef): {
        "name": "AMIGetRAIDConfig", "priv": "Admin", "tier": SAFE,
        "block": "privileged",
        "req_len": 0, "resp_len": None,
        "desc": "Retrieve RAID configuration.",
        "request": "empty",
        "response": "RAID config blob",
    },

    # ------------------------------------------------------------------
    # Cross-NetFn anomaly (0x0A/0x2C) — RunInitAgent lives on Storage
    # ------------------------------------------------------------------
    (0x0a, 0x2c): {
        "name": "RunInitAgent", "priv": "Admin", "tier": MUTATES, "block": "anomaly",
        "req_len": 1, "resp_len": 2,
        "desc": "1B RunStatus in, 2B out. Encoded NetFn 0x28 → decodes to "
                "Storage 0x0A, NOT the AMI OEM 0x32 used by every sibling. "
                "Deliberate obscuring or routing bug — BMC-side behavior "
                "opaque, see security.html.",
        "security": "Anomalous routing on Storage NetFn — audit target.",
        "request": "1B RunStatus",
        "response": "2B",
    },
}


# (netfn, cmd) → name — for _registry.register().
YAFU_CMD_NAMES: dict[tuple[int, int], str] = {
    k: v["name"] for k, v in YAFU_COMMANDS.items()
}

# Vendors known to link the AMI YAFU protocol. Used by lineage-probe and by
# `<name> help` to surface a "seen in" list. Membership = high-confidence
# based on RE / vendor lineage; per-fw reachability still needs live probe.
YAFU_SEEN_IN: tuple[str, ...] = (
    "AMI MegaRAC SP-X 13.x (HPE XD670, generic MegaRAC relabels)",
    "AMI MegaRAC SP-X 4.0 (Advantech ASMB-787 — BMC-side authoritative decomp)",
    "Supermicro X10 / X11 / X12 / X13 (smcipmi + libipmi_AMIOEM.c)",
    "Quanta / GIGABYTE / ByteBmc AMI-relabels (per lineage)",
)

# Block groupings — for catalog listing sort / display.
YAFU_BLOCKS: dict[str, str] = {
    "info":        "Info / query (0x01–0x0F)",
    "mode":        "Mode (0x10)",
    "flash_io":    "Flash I/O + memory alloc (0x20–0x29)",
    "memory":      "Memory (0x30–0x34)",
    "boot":        "Boot config (0x40–0x42)",
    "device_mgmt": "Device management (0x50–0x56)",
    "privileged":  "Privileged AMI extensions (0x66–0xEF)",
    "anomaly":     "Cross-NetFn anomaly (0x0A/0x2C)",
}

YAFU_TIER_COUNT: dict[str, int] = {
    SAFE:        sum(1 for e in YAFU_COMMANDS.values() if e["tier"] == SAFE),
    MUTATES:     sum(1 for e in YAFU_COMMANDS.values() if e["tier"] == MUTATES),
    DESTRUCTIVE: sum(1 for e in YAFU_COMMANDS.values() if e["tier"] == DESTRUCTIVE),
}


# YAFU is protocol-family, not a vendor — register with iana=None so the
# ENTERPRISE_IDS lookup never mis-attributes a Get-Device-ID manuf-id to YAFU.
register("yafu", None, YAFU_CMD_NAMES)


__all__ = [
    "YAFU_COMMANDS", "YAFU_CMD_NAMES", "YAFU_SEEN_IN",
    "YAFU_BLOCKS", "YAFU_TIER_COUNT",
    "SAFE", "MUTATES", "DESTRUCTIVE",
]
