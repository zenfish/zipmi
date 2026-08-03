"""zipmi.scapy_ipmi.oem.supermicro_x14 — Supermicro X14 (AST2600 OpenBMC) OEM cmds.

WHAT     Supermicro X14SBSC-RoT / E601MS OEM IPMI surface. UNLIKE the X11 stack
         (AMI MegaRAC + smcipmitool, see oem/supermicro.py), X14 is **Phosphor
         OpenBMC on ASPEED AST2600** with SMC's own provider .so's patched in.
         The OEM commands are phosphor `registerHandler`/`registerGroupHandler`
         registrations recovered by disassembling the provider libraries.

WIRE     Primary OEM surface is raw **NetFn 0x30** (libsupermicrooemcmds, 60
         registrations). Redfish Host-Interface bootstrap + DMTF live on the
         **group-extension NetFn 0x2C** (group id = first data byte: 0x52 = DMTF
         Redfish Device Enablement, 0xDC = DCMI-adjacent DMTF). NetFn 0x32 =
         RAS/crashdump. There is NO IANA-scoped OEM handler in the SMC libs —
         Supermicro rides raw 0x30 + DMTF groups, so registered iana=None. (The
         only true IANA handler is Intel Node Manager, IANA 343 / NetFn 0x2E —
         already covered by `zipmi oem intel`, not duplicated here.)

STATE    (NetFn,Cmd) + privilege are statically recovered immediates (high
         confidence). Many 0x30 cmd *purposes* are inferred from exported handler
         symbols / OEM string tables, not a published SMC spec — treat names as
         best-effort until live-probed. ~30 of the 60 0x30 registrations resolved
         to a concrete cmd byte; the rest were register/loop-loaded (see
         SUPERMICRO_X14_SYMBOLS for notable unmapped handler symbols).

PRIV     0=none/pre-auth, 2=User, 3=Operator, 4=Admin.

LOAD     zipmi.load_vendor("supermicro-x14")   (module: supermicro_x14)

SOURCE   Supermicro X14 IPMI OEM handler teardown (internal RE) — arm objdump of
         the provider .so's from fw BMC_X14AST2600-ROT-E601MS_20260306_01.01.06.07.
"""

from __future__ import annotations

from ._registry import register


# Rich catalog: key -> {name, priv, desc}. Key shapes:
#   (netfn, cmd)             raw command
#   (0x2c, cmd, group)       group-extension: `group` is the first data byte
#                            (auto-supplied as a prefix on send).
# `priv` is the min privilege the handler registered at; `desc` is best-effort.
SUPERMICRO_X14: dict[tuple, dict] = {
    # --- NetFn 0x30: SMC OEM (libsupermicrooemcmds) --------------------------
    (0x30, 0x20): {"name": "SMC OEM 0x30/0x20", "priv": "Admin", "desc": "OEM group"},
    (0x30, 0x21): {"name": "SMC OEM 0x30/0x21", "priv": "Admin", "desc": "OEM group"},
    (0x30, 0x30): {"name": "SMC OEM 0x30/0x30", "priv": "Admin", "desc": "OEM group"},
    (0x30, 0x45): {"name": "SMC OEM 0x30/0x45", "priv": "Admin", "desc": "OEM group"},
    (0x30, 0x51): {"name": "SMC OEM pre-auth 0x30/0x51", "priv": "none",
                   "desc": "★ pre-auth (priv 0) OEM — get info-class; audit for info-leak"},
    (0x30, 0x68): {"name": "SMC OEM pre-auth 0x30/0x68", "priv": "none",
                   "desc": "★ pre-auth (priv 0) OEM"},
    (0x30, 0x70): {"name": "SMC OEM pre-auth 0x30/0x70", "priv": "none",
                   "desc": "★ pre-auth (priv 0) OEM"},
    (0x30, 0x71): {"name": "SMC OEM 0x30/0x71", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x73): {"name": "SMC OEM 0x30/0x73", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x74): {"name": "SMC OEM 0x30/0x74", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x82): {"name": "SMC OEM Get/Set BIOS Data", "priv": "User",
                   "desc": "OEMSetBIOSDataCmd / GetSetBIOSInfo"},
    (0x30, 0x93): {"name": "SMC OEM 0x30/0x93", "priv": "User", "desc": "OEM"},
    (0x30, 0x97): {"name": "SMC OEM 0x30/0x97", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x9a): {"name": "SMC OEM 0x30/0x9a", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x9d): {"name": "SMC OEM 0x30/0x9d", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x9e): {"name": "SMC OEM 0x30/0x9e", "priv": "Admin", "desc": "OEM"},
    (0x30, 0x9f): {"name": "SMC OEM 0x30/0x9f", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xa0): {"name": "SMC OEM pre-auth 0x30/0xa0", "priv": "none",
                   "desc": "★ pre-auth (priv 0) OEM"},
    (0x30, 0xa1): {"name": "SMC OEM 0x30/0xa1", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xac): {"name": "SMC OEM 0x30/0xac", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xad): {"name": "SMC OEM pre-auth 0x30/0xad", "priv": "none",
                   "desc": "★ pre-auth (priv 0) OEM"},
    (0x30, 0xb3): {"name": "SMC OEM 0x30/0xb3", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xb5): {"name": "SMC OEM 0x30/0xb5", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xc3): {"name": "SMC OEM 0x30/0xc3", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xe2): {"name": "SMC OEM 0x30/0xe2", "priv": "Admin", "desc": "OEM"},
    (0x30, 0xe3): {"name": "SMC OEM 0x30/0xe3", "priv": "Admin", "desc": "OEM"},

    # --- Group-ext NetFn 0x2C, group 0x52: DMTF Redfish Device Enablement ----
    (0x2c, 0x01, 0x52): {"name": "Get Bootstrap Account Credentials", "priv": "Admin",
                         "desc": "★★ Redfish-HI: returns a Redfish user+password "
                                 "(DSP0270 bootstrap account) — host->BMC cred disclosure risk"},
    (0x2c, 0x02, 0x52): {"name": "Redfish HI bootstrap cmd 2", "priv": "Admin",
                         "desc": "DMTF Redfish Device Enablement"},
    (0x2c, 0x03, 0x52): {"name": "Redfish HI bootstrap cmd 3", "priv": "Admin",
                         "desc": "DMTF Redfish Device Enablement"},

    # --- Group-ext NetFn 0x2C, group 0xDC: DMTF (DCMI-adjacent) --------------
    (0x2c, 0x01, 0xdc): {"name": "SMC DMTF-group 0xdc/0x01", "priv": "User", "desc": "DMTF group"},
    (0x2c, 0x06, 0xdc): {"name": "SMC DMTF-group 0xdc/0x06", "priv": "User", "desc": "DMTF group"},
    (0x2c, 0x07, 0xdc): {"name": "SMC DMTF-group 0xdc/0x07", "priv": "Operator", "desc": "DMTF group"},
    (0x2c, 0x08, 0xdc): {"name": "SMC DMTF-group 0xdc/0x08", "priv": "Operator", "desc": "DMTF group"},
    (0x2c, 0x10, 0xdc): {"name": "SMC DMTF-group 0xdc/0x10", "priv": "User", "desc": "DMTF group"},

    # --- NetFn 0x32: RAS / crashdump (librasProvider, phosphor) --------------
    (0x32, 0x22): {"name": "RAS/Crashdump 0x32/0x22", "priv": "Admin", "desc": "OEM RAS (Intel-style)"},
    (0x32, 0x23): {"name": "RAS/Crashdump 0x32/0x23", "priv": "Admin", "desc": "OEM RAS"},
    (0x32, 0x24): {"name": "RAS/Crashdump 0x32/0x24", "priv": "Admin", "desc": "OEM RAS"},

    # --- Overrides of standard cmds (SMC reimplementations) ------------------
    (0x00, 0x02): {"name": "Chassis Control (SMC override)", "priv": "Operator",
                   "desc": "SMC reimpl of standard Chassis Control"},
    (0x0a, 0x48): {"name": "Get SEL Time (SMC override)", "priv": "User",
                   "desc": "SMC reimpl of standard Get SEL Time"},
}

# (netfn,cmd[,group]) -> name, registered into the OEM decode registry.
SUPERMICRO_X14_CMD_NAMES: dict[tuple, str] = {k: v["name"] for k, v in SUPERMICRO_X14.items()}

# Notable exported OEM handler symbols NOT yet mapped to a specific 0x30 cmd
# byte (register/loop-loaded). Security-relevant — resolve via deeper dataflow
# or a live `raw`-probe. Grouped by concern.
SUPERMICRO_X14_SYMBOLS: dict[str, tuple[str, ...]] = {
    "bios": ("OEMGetBIOSCap", "OEMSetBIOSCap", "GetSetBIOSInfo", "OEMSetBIOSDataCmd",
             "BRCMSetBIOSBootMode", "GetSetBiosOOBIdentify", "BIOSLicenseSource"),
    "users_creds": ("OEMAddDelUser", "ipmiSetSpecialUserPassword", "OEMGetHostFWUserPassword",
                    "UtilSaveUniquePassword", "UtilConfirmDefaultPassword",
                    "GetBootstrapAccountCredentials", "CreateBootStrapUser", "clearBootStrapUser"),
    "secrets": ("getRADIUSSecret", "setRADIUSSecret", "OEMGetMMBIHashKey", "OEMSetMMBIHashKey",
                "GetMgrCertFingerprint", "OEMSSLCertificateStatus", "validating_hsm_license"),
    "shell_rce": ("ExecInShell", "ExecInShellnRes"),                        # +/bin/sh in the lib
    "debug": ("EnableBRCMDebug", "SetOOBDebugFlag", "OEMReportDebugMessage", "GetOOBUpdateStatus"),
    "kvm_kcs": ("setKvmipStatus", "setKvmipPort", "GetKCSAccessCmd", "SetKCSAccessCmd"),
    "factory_reset": ("OEMCommandSetFactory", "SetFactoryFactoryOptions",
                      "ResetToFactoryDefaultSetting", "ResetToFactoryDefaultSettingNoLAN"),
    "misc": ("OEMHostNameOperationCmd", "OEMSELCircularBufCmd"),
}

register("supermicro-x14", None, SUPERMICRO_X14_CMD_NAMES)

__all__ = ["SUPERMICRO_X14", "SUPERMICRO_X14_CMD_NAMES", "SUPERMICRO_X14_SYMBOLS"]
