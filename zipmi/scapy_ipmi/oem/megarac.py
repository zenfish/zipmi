"""zipmi.scapy_ipmi.oem.megarac — AMI MegaRAC SP-X OEM handler inventory.

WHAT     Stock AMI MegaRAC SP-X 13.x LTS OEM command handlers (210 across
         40 modules), extracted from the .dynsym of the
         /usr/local/lib/ipmi/libipmiamioem<x>.so handler libraries. This is the
         provider behind "HPE/HPE XD670" and every other MegaRAC-on-* box —
         the HPE/Cray badge is packaging, the BMC code is all AMI.

WIRE     Raw vendor NetFns 0x30 (primary AMI range) and 0x3E (secondary), both
         live-confirmed via the IPMI firmware-firewall (raw 0x06 0x0a 0x0e). No
         IANA enterprise number rides on the wire, so registered with iana=None
         (never claims a Get Device ID manuf-id slot). AMI's own PEN is 20974,
         but the XD670's on-wire IPMI Manufacturer ID is 15370 (GIGA-BYTE), the
         board vendor — MegaRAC reports the OEM/board id, not AMI.

STATE    OPCODES RESOLVED. 95 registered IPMI OEM commands (MEGARAC_COMMANDS)
         recovered by static RE of each lib's registration table — every
         libipmiamioem*.so exports GetLibMetaInfo() -> a MetaInfo struct naming a
         g_<X>_CmdHndlr table; each 16-byte table entry is
         [u8 cmd][u8 priv][00 00][handler ptr (reloc)][flag 0x..00aaaa][flag].
         cmd + privilege come straight from the entry; NetFn is 0x30 (AMI primary
         OEM range, corroborated by AMIGetBiosCode = 0x30/0x73, the public AMI
         "Get BIOS POST Code"). MEGARAC_HANDLERS below still lists all 210 EXPORTED
         symbols per module — most are internal helpers; only the 95 that appear
         in a registration table are IPMI-dispatchable (the others are not
         reachable over IPMI). A subset of the 95 may sit on NetFn 0x3E (secondary
         AMI range) rather than 0x30 — no cmd-byte collisions were found (all 95
         unique), consistent with a single netfn; confirm the split with a live
         firmware-firewall probe if it matters.

LOAD     zipmi.load_vendor("megarac")   (alias: "ami")

SOURCE   MegaRAC SP-X OEM handler teardown (internal RE) — enumerated 2026-07-28
         (pyelftools .dynsym extraction + live IPMI firmware-firewall probe).
"""

from __future__ import annotations

from ._registry import register


SAFE = "safe"
MUTATES = "mutates"
DESTRUCTIVE = "destructive"


# module (libipmiamioem<x>.so) -> handler symbol names (from .dynsym).
MEGARAC_HANDLERS: dict[str, tuple[str, ...]] = {
    'Remotedebug': (  # ** remote debug server + TLS cert upload
        'get_server_info', 'AMIRemoteDebugSetInfo', 'control_remote_debug_server', 
        'AMIRemoteDebugGetInfo', 'check_status', 'upload_tls_cert',
    ),
    'accessredis': ('AMIAccessRedisDB', 'AMIOemSetRedisDB',),
    'acd': (  # * Intel Autonomous Crashdump
        'AMIACDGetInfo', 'control_acd', 'get_acd_info', 'set_data_area', 'run_acd', 
        'update_acd_status', 'get_data_area', 'get_acd_status', 'AMIACDSetInfo',
    ),
    'ad': ('AMIGetADConf', 'AMISetADConf',),
    'autohostlock': ('AMISetHostAutoLockStatus', 'AMIGetHostAutoLockStatus',),
    'autovideorcd': ('AMISetVideoRcdConf', 'pthTestMount', 'AMIGetVideoRcdConf', 'pthMountVideoRecordPath',),
    'backuprestore': (  # ** export/import entire BMC config
        'AMIGetBackupFlag', 'AMIManageBMCConfig', 'AMISetBackupFlag',
    ),
    'bioscode': ('AMIGetBiosCode',),
    'biosremotecontrol': (  # * BMC<->BIOS message channel
        'AMISetBiosFlag', 'AMISetBiosResponse', 'AMIGetBiosFlag', 'AMISendToBios', 
        'AMIGetBiosResponse', 'AMIGetBiosCommand',
    ),
    'ctldbg': (  # * low-level debug hooks
        'AMIControlDebugMsg', 'AMIGetDebugMsgStatus',
    ),
    'dualimg': (  # ** dual-image control
        'AMIDualImageSupport',
    ),
    'extendedsel': ('FilterExtendSEFiles', 'AMIGETExtendSelData', 'AMIPartialAddExtendSelEntries', 'DeleteNVRAMSELEntry', 'GetExtendedSELCount', 'AMIAddExtendSelEntries', 'AMIPartialGetExtendSelEntries',),
    'extpriv': ('AMIGetExtendedPrivilege', 'AMISetExtendedPrivilege',),
    'firewall': ('fill_request', 'AMIGetFirewall', 'AMISetFirewall',),
    'fwupdateprctl': (  # ** TFTP firmware update
        'AMIGetFWCfg', 'AMISetFWProtocol', 'AMISetFWCfg', 'AMIGetFWProtocol', 
        'AMIGetTftpProgressStatus', 'AMIStartTFTPFwUpdate',
    ),
    'hostlock': ('AMISetHostLockFeatureStatus', 'AMIGetHostLockFeatureStatus',),
    'ldap': ('SB_BD_Validate', 'checkidentifier', 'AMISetLDAPConf', 'AMIGetLDAPConf',),
    'media': ('AMIGetMediaInfo', 'AMISetMediaInfo', 'AMIGetVmediaCfg', 'Get_Lmedia_image_status', 'AMIGetRedirectedMediaInfo', 'AMISetVmediaCfg', 'AMIMediaRedirectionStartStop', 'VmediaRestartDelay',),
    'ntp': ('AMIGetNTPCfg', 'Isvalidserver', 'AMISetNTPCfg',),
    'pamreorder': ('AMISetPamOrder', 'SetNssFileOrder', 'GetAllFilesOrder', 'SetPamSqnceOrder', 'GetNssOrder', 'ValidateUsrInput', 'SetNssSqnceOrder', 'isPAMModuleExist', 'GetPamOrder', 'CompPamOrder', 'GetPamCount', 'AMIGetPamOrder', 'ArrangOrder', 'SetPamOrder',),
    'peci': (  # *** raw PECI passthrough to host CPU
        'AMIPECIWriteRead',
    ),
    'pldm': ('AMICtrlPLDM',),
    'pldmcmds': ('GetBIOSTableTags', 'GetNumOfBlocks', 'AMIPLDMBIOSMsg', 'SetBIOSTableTags', 'FillResponse', 'PLDMBiosFileName', 'PLDMTimerTask',),
    'prsvconf': ('AMIGetPreserveConfStatus', 'AMISetAllPreserveConfStatus', 'AMIGetAllPreserveConfStatus', 'AMISetPreserveConfStatus',),
    'pwdenc': (  # ** sets UserConfig password-encryption AES key
        'AMISetPwdEncryptionKey',
    ),
    'pwrcons': ('AMIVirtualDeviceSetStatus', 'AMIVirtualDeviceGetStatus', 'OngetSetVirtualDevice', 'OnPowerConsumptionMode',),
    'radius': ('AMISetRadiusConf', 'AMIGetRadiusConf',),
    'raidinfo': (  # RAID/SAS/enclosure mgmt (55 handlers)
        'ManageControllerSpareDrive', 'ClearSASITEventLog', 'CreateLUCache', 'SetPdState', 
        'ManageRAIDPersonality', 'GetDedicatedHotspareInfo', 'GetRAIDControllerInfo', 
        'GetLDProgress', 'ManageControllerArray', 'GetSASITEnclosureInfo', 
        'GetSASITRepositoryInfo', 'LocateDevice', 'GetTopologyInfo', 'Manage_SMART_Info', 
        'ClearForeignDev', 'GetPhysicalDevCount', 'LocateSASITDevice', 'GetRAIDCountInfo', 
        'ManagePatrolProperties', 'GetArrayInfo', 'Send_Command', 'GetLogicalDevInfo', 
        'GetArrayCount', 'GetSASITTempSensorInfo', 'GetSASITHealth', 'GetCtrlBBUInfo', 
        'GetCtrlErrno', 'ManageControllorProperties', 'GetEnclosureStatus', 
        'GetSE_EnclosureList', 'SetSASITCoolingInfo', 'GetSASITControllerInfo', 
        'Get_Ctrl_PD_Interface_Info', 'SetSASITTempSensorInfo', 'GetSASITEnclosureStatus', 
        'GetRAIDRepositoryInfo', 'GetRAIDCountInfo_agent', 'AMIGetRAIDInfo', 'SetSASITPSInfo', 
        'GetSASITPhyDevInfo', 'manageLDProperties', 'GetRAIDLevelPDCountInfo', 
        'GetSE_EnclosureStatus', 'GetLogicalDevCount', 'GetSASITCountInfo', 
        'ClearRAIDEventLog', 'GetSASITPhyDevCount', 'GetRLStripSizeInfo', 'SetSASITAlarmInfo', 
        'GetRAIDControllerInfo_agent', 'GetCtrlHealth', 'GetPhysicalDevInfo', 'GetLDLUNumber', 
        'GetEnclosureInfo', 'GetSASITTopologyInfo',
    ),
    'remotekvm': ('AMISetRemoteKVMCfg', 'AMIGetRemoteKVMCfg',),
    'restiface': (  # ** REST/host-interface bridge — CVE-2024-54085 neighbourhood
        'AMIRESTinterface', 'GenMD5Hash', 'GetBufferTrackInfo', 'HIInterfaceSupport', 
        'SetCommandExe', 'RestInterfaceTimer', 'AMIGeneratePassword', 
        'GenerateRandomAlpNumPasswd', 'Free_Track', 'StoreDataInRedisDB', 'DeleteUserSession',
    ),
    'ris': ('AMIRISStartStop', 'AMIGetRISConf', 'AMISetRMediaCfg', 'AMISetRISConf', 'SetBlockData', 'VerifyData', 'AMIGetRMediaCfg', 'RISSetServiceStatus',),
    'sd': ('AMISetSDCardPartition', 'AMIGetSDCardPartition',),
    'sensorthresholdacrossresets': ('ThresholdAcrossResets', 'AMISensorThresholdAcrossResets',),
    'serviceconf': ('isValidStandardPort', 'AMIGetServiceConf', 'AMISetServiceConf', 'isPortAllowed', 'IsSinglePortEnable',),
    'sessionmgmt': ('AMIGetAllActiveSessions', 'AMIActiveSessionClose',),
    'singleport': ('AMISetRunTimeSinglePortStatus', 'AMIGetRunTimeSinglePortStatus',),
    'snmp': ('SetEngineIDType', 'AMIGetSNMPConf', 'AMISetSNMPConf', 'GetDecryptPswd',),
    'timezone': ('AMIGetTimeZone', 'SetDefaultTimezone', 'AMISetTimeZone',),
    'uartlogging': ('AMISetSOLTriggerEvent', 'AMIGetSerialLogConf', 'AMIGetSOLArchiveData', 'AMISetSerialLogConf', 'AMIGetSOLTriggerEvent',),
    'ubootmemtest': (  # * u-boot memtest hook
        'AMIGetUBootMemtestStatus', 'AMISetUBootMemtest',
    ),
}


# (NetFn, Cmd) -> handler symbol. NetFn 0x30 (AMI primary OEM range) resolved by
# static RE of each lib's registration table (16-byte entries: [cmd][priv][00 00]
# [handler ptr][flag]); privileges + owning module in MEGARAC_COMMANDS below.
# A subset may live on NetFn 0x3E (secondary AMI range) — needs a live firewall
# split to confirm; no cmd-byte collisions were found, consistent with a single netfn.
MEGARAC_COMMANDS: dict[tuple[int, int], dict] = {

    # ------------------------------------------------------------------
    # RIS — Remote ISO / media share config (0x18–0x19, 0x9E–0xA0)
    # ------------------------------------------------------------------
    (0x30, 0x18): {
        'name': 'AMIGetRMediaCfg', 'priv': 'User', 'module': 'ris',
        'tier': SAFE, 'block': 'ris',
        'desc': "Get remote media (NFS/CIFS/HTTP ISO) share configuration.",
        'request': "byte MediaType",
        'response': "MediaConfig_T struct (share path, credentials, mount state)",
    },
    (0x30, 0x19): {
        'name': 'AMISetRMediaCfg', 'priv': 'Admin', 'module': 'ris',
        'tier': MUTATES, 'block': 'ris',
        'desc': "Set remote media share config (NFS/CIFS/HTTP mount point).",
        'request': "byte MediaType + MediaConfig_T (share path, user, pass)",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Redis DB — raw Redis command injection (0x2A, 0x2C)
    # ------------------------------------------------------------------
    (0x30, 0x2a): {
        'name': 'AMIAccessRedisDB', 'priv': 'Callback', 'module': 'accessredis',
        'tier': SAFE, 'block': 'redis',
        'desc': "Execute arbitrary Redis commands against the BMC's data store. "
                "Connects to /run/redis/redis.sock via libhiredis. Any valid "
                "Redis command string accepted (GET, KEYS, HGETALL, etc.). "
                "Priv byte 0x81 = host-interface (KCS/BT) access with no "
                "session auth required.",
        'request': "variable-length Redis command string",
        'response': "variable-length Redis response (strings, arrays, integers)",
        'security': "CRITICAL: unauthed from host KCS. Reads any Redis key "
                    "including AES-encrypted passwords (EncryptedPassword), "
                    "PBKDF2 hashes, session tokens, all config. Fleet-shared "
                    "AES key in firmware enables decryption.",
    },
    (0x30, 0x2c): {
        'name': 'AMIOemSetRedisDB', 'priv': 'Callback', 'module': 'accessredis',
        'tier': DESTRUCTIVE, 'block': 'redis',
        'desc': "Write arbitrary Redis key/value pairs. Same KCS/host-interface "
                "access as AccessRedisDB (priv 0x81). Can modify any BMC state "
                "stored in Redis.",
        'request': "variable-length Redis SET command string",
        'response': "cc",
        'security': "CRITICAL: unauthed writes from host. Can modify user "
                    "credentials, network config, session state, Redfish "
                    "account properties. Full BMC config takeover via KCS.",
    },

    # ------------------------------------------------------------------
    # Remote Debug server (0x43–0x44)
    # ------------------------------------------------------------------
    (0x30, 0x43): {
        'name': 'AMIRemoteDebugSetInfo', 'priv': 'Admin', 'module': 'Remotedebug',
        'tier': MUTATES, 'block': 'remotedebug',
        'desc': "Configure remote debug server + upload TLS certificates.",
        'request': "subcommand + config data (server enable, TLS cert)",
        'response': "cc",
    },
    (0x30, 0x44): {
        'name': 'AMIRemoteDebugGetInfo', 'priv': 'Admin', 'module': 'Remotedebug',
        'tier': SAFE, 'block': 'remotedebug',
        'desc': "Read remote debug server status and configuration.",
        'request': "subcommand selector",
        'response': "debug server config blob",
    },

    # ------------------------------------------------------------------
    # ACD — Intel Autonomous Crash Dump (0x47–0x48)
    # ------------------------------------------------------------------
    (0x30, 0x47): {
        'name': 'AMIACDSetInfo', 'priv': 'Admin', 'module': 'acd',
        'tier': MUTATES, 'block': 'acd',
        'desc': "Configure Intel ACD (Autonomous Crash Dump) — enable/disable, "
                "set data area, trigger crash dump collection.",
        'request': "subcommand + ACD config",
        'response': "cc",
    },
    (0x30, 0x48): {
        'name': 'AMIACDGetInfo', 'priv': 'User', 'module': 'acd',
        'tier': SAFE, 'block': 'acd',
        'desc': "Read ACD status, data area, and crash dump availability.",
        'request': "subcommand selector",
        'response': "ACD status + data area info",
    },

    # ------------------------------------------------------------------
    # Sensor threshold persistence (0x4A)
    # ------------------------------------------------------------------
    (0x30, 0x4a): {
        'name': 'AMISensorThresholdAcrossResets', 'priv': 'User',
        'module': 'sensorthresholdacrossresets',
        'tier': SAFE, 'block': 'sensor',
        'desc': "Get/set whether sensor thresholds persist across BMC resets.",
        'request': "subcommand + sensor ID + thresholds",
        'response': "threshold persistence state",
    },

    # ------------------------------------------------------------------
    # REST / host-interface bridge (0x5C–0x5D) — CVE-2024-54085 area
    # ------------------------------------------------------------------
    (0x30, 0x5c): {
        'name': 'AMIRESTinterface', 'priv': 'Admin', 'module': 'restiface',
        'tier': MUTATES, 'block': 'restiface',
        'desc': "Host-interface REST/Redfish bridge. Relays Redfish requests "
                "from the host OS to the BMC's REST service via named pipes "
                "(/var/RedFishReqQ, /var/RedFishResQ). Uses buffer tracking, "
                "MD5 hashing, and session management. Stores data in Redis.",
        'request': "transaction ID + Redfish request payload",
        'response': "transaction ID + Redfish response payload",
        'security': "CVE-2024-54085 neighbourhood. The host-interface Redfish "
                    "bridge is the entry point for the auth-bypass vuln. "
                    "GenMD5Hash + StoreDataInRedisDB + DeleteUserSession "
                    "are internal helpers. Buffer tracking limits concurrent "
                    "requests ('All Tracks are taken' = max 16?).",
    },
    (0x30, 0x5d): {
        'name': 'AMIGeneratePassword', 'priv': 'Callback', 'module': 'restiface',
        'tier': SAFE, 'block': 'restiface',
        'desc': "Generate a random alphanumeric password from /dev/urandom. "
                "Priv byte 0x81 = host-interface access, no session auth. "
                "Gated on WDT presence + OS boot state.",
        'request': "byte length (desired password length)",
        'response': "byte[] random password",
        'security': "Priv 0x81 (host/no-auth). Only callable when WDT is "
                    "present and OS is fully booted. Returns raw random bytes "
                    "from /dev/urandom — no credential leak, but reveals "
                    "BMC's PRNG state if called repeatedly.",
    },

    # ------------------------------------------------------------------
    # Service configuration (0x69–0x6A)
    # ------------------------------------------------------------------
    (0x30, 0x69): {
        'name': 'AMIGetServiceConf', 'priv': 'User', 'module': 'serviceconf',
        'tier': SAFE, 'block': 'serviceconf',
        'desc': "Read BMC service configuration (port numbers, enable/disable "
                "state for HTTPS, SSH, IPMI, KVM, etc.).",
        'request': "service selector",
        'response': "service config (port, enabled, single-port mode)",
    },
    (0x30, 0x6a): {
        'name': 'AMISetServiceConf', 'priv': 'Admin', 'module': 'serviceconf',
        'tier': MUTATES, 'block': 'serviceconf',
        'desc': "Set BMC service configuration. Validates port ranges and "
                "blocks port 80 ('Unsupported port 80').",
        'request': "service selector + port + enable flag",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # BIOS POST code (0x73)
    # ------------------------------------------------------------------
    (0x30, 0x73): {
        'name': 'AMIGetBiosCode', 'priv': 'User', 'module': 'bioscode',
        'tier': SAFE, 'block': 'bioscode',
        'desc': "Read current and previous BIOS POST codes from the SNOOP "
                "device (libsnoop.so). Returns diagnostic byte sequence "
                "showing host boot progress. Gate: "
                "CONFIG_SPX_FEATURE_BIOS_POST_CODE_IPMI_SUPPORT.",
        'request': "byte selector (0=current, 1=previous)",
        'response': "byte[] POST code sequence",
    },

    # ------------------------------------------------------------------
    # BMC firewall — iptables/ip6tables management (0x76–0x77)
    # ------------------------------------------------------------------
    (0x30, 0x76): {
        'name': 'AMISetFirewall', 'priv': 'Admin', 'module': 'firewall',
        'tier': MUTATES, 'block': 'firewall',
        'desc': "Add/delete iptables/ip6tables rules on the BMC. Validates "
                "IPv4/IPv6 ranges and timeouts. Calls flush_iptables(), "
                "operates on both IP and port rules.",
        'request': "subcommand (add/del) + rule type (IP/port) + rule data",
        'response': "cc",
        'security': "Can open/close BMC network ports. An attacker with admin "
                    "IPMI access can disable the BMC firewall entirely.",
    },
    (0x30, 0x77): {
        'name': 'AMIGetFirewall', 'priv': 'User', 'module': 'firewall',
        'tier': SAFE, 'block': 'firewall',
        'desc': "Read current iptables/ip6tables firewall rules and counts.",
        'request': "subcommand (count/entry) + rule type",
        'response': "rule count or GetIPRule/GetPortRule struct",
    },

    # ------------------------------------------------------------------
    # PAM reorder (0x7A–0x7B)
    # ------------------------------------------------------------------
    (0x30, 0x7a): {
        'name': 'AMISetPamOrder', 'priv': 'Admin', 'module': 'pamreorder',
        'tier': MUTATES, 'block': 'pamreorder',
        'desc': "Reorder PAM authentication modules (local, LDAP, AD, RADIUS). "
                "Calls SetPamSqnceOrder() + SetNssSqnceOrder(). Validates "
                "PAM module existence before reordering.",
        'request': "byte[] ordered list of PAM module indices",
        'response': "cc",
        'security': "Reordering PAM can prioritize a weaker auth backend "
                    "(e.g. move LDAP before local). Combined with SetLDAPConf, "
                    "an attacker could redirect auth to a rogue LDAP server.",
    },
    (0x30, 0x7b): {
        'name': 'AMIGetPamOrder', 'priv': 'User', 'module': 'pamreorder',
        'tier': SAFE, 'block': 'pamreorder',
        'desc': "Read current PAM module ordering and NSS configuration.",
        'request': "none",
        'response': "byte[] PAM module order + count",
    },

    # ------------------------------------------------------------------
    # SNMP (0x7C–0x7D)
    # ------------------------------------------------------------------
    (0x30, 0x7c): {
        'name': 'AMIGetSNMPConf', 'priv': 'User', 'module': 'snmp',
        'tier': SAFE, 'block': 'snmp',
        'desc': "Read SNMP configuration including community strings. "
                "GetDecryptPswd() decrypts stored SNMP v3 passwords for "
                "the response.",
        'request': "selector byte",
        'response': "SNMP config blob (community, users, engine ID)",
        'security': "Returns decrypted SNMP community strings / v3 passwords "
                    "to any User-level session.",
    },
    (0x30, 0x7d): {
        'name': 'AMISetSNMPConf', 'priv': 'Admin', 'module': 'snmp',
        'tier': MUTATES, 'block': 'snmp',
        'desc': "Set SNMP configuration (community, users, engine ID type).",
        'request': "SNMP config blob",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Preserve config across fw update (0x83–0x84, 0xBA–0xBB)
    # ------------------------------------------------------------------
    (0x30, 0x83): {
        'name': 'AMISetPreserveConfStatus', 'priv': 'Admin', 'module': 'prsvconf',
        'tier': MUTATES, 'block': 'prsvconf',
        'desc': "Set whether a specific config section persists across fw update.",
        'request': "byte selector + byte status (preserve/reset)",
        'response': "cc",
    },
    (0x30, 0x84): {
        'name': 'AMIGetPreserveConfStatus', 'priv': 'User', 'module': 'prsvconf',
        'tier': SAFE, 'block': 'prsvconf',
        'desc': "Read preserve-config status for a specific config section.",
        'request': "byte selector",
        'response': "byte status",
    },

    # ------------------------------------------------------------------
    # Firmware update via TFTP (0x87–0x8C)
    # ------------------------------------------------------------------
    (0x30, 0x87): {
        'name': 'AMIStartTFTPFwUpdate', 'priv': 'Admin', 'module': 'fwupdateprctl',
        'tier': DESTRUCTIVE, 'block': 'fwupdate',
        'desc': "Initiate firmware update from a TFTP server. Triggers full "
                "flash write cycle.",
        'request': "TFTP server IP + filename",
        'response': "cc",
        'security': "Remote firmware reflash. An attacker with admin IPMI "
                    "can point this at a malicious TFTP server to install "
                    "trojanized firmware.",
    },
    (0x30, 0x88): {
        'name': 'AMIGetTftpProgressStatus', 'priv': 'Admin', 'module': 'fwupdateprctl',
        'tier': SAFE, 'block': 'fwupdate',
        'desc': "Poll TFTP firmware update progress.",
        'request': "none",
        'response': "progress percentage + status code",
    },
    (0x30, 0x89): {
        'name': 'AMISetFWCfg', 'priv': 'Admin', 'module': 'fwupdateprctl',
        'tier': MUTATES, 'block': 'fwupdate',
        'desc': "Set firmware update configuration parameters.",
        'request': "FW config blob",
        'response': "cc",
    },
    (0x30, 0x8a): {
        'name': 'AMIGetFWCfg', 'priv': 'Admin', 'module': 'fwupdateprctl',
        'tier': SAFE, 'block': 'fwupdate',
        'desc': "Read firmware update configuration.",
        'request': "none",
        'response': "FW config blob",
    },
    (0x30, 0x8b): {
        'name': 'AMISetFWProtocol', 'priv': 'Admin', 'module': 'fwupdateprctl',
        'tier': MUTATES, 'block': 'fwupdate',
        'desc': "Set firmware update protocol (TFTP vs other).",
        'request': "protocol selector",
        'response': "cc",
    },
    (0x30, 0x8c): {
        'name': 'AMIGetFWProtocol', 'priv': 'Admin', 'module': 'fwupdateprctl',
        'tier': SAFE, 'block': 'fwupdate',
        'desc': "Read current firmware update protocol setting.",
        'request': "none",
        'response': "protocol byte",
    },

    # ------------------------------------------------------------------
    # Dual-image support (0x8F)
    # ------------------------------------------------------------------
    (0x30, 0x8f): {
        'name': 'AMIDualImageSupport', 'priv': 'Admin', 'module': 'dualimg',
        'tier': MUTATES, 'block': 'dualimg',
        'desc': "Control dual-image boot selection (active/backup image swap). "
                "Gate: CONFIG_SPX_FEATURE_DUAL_IMAGE_SUPPORT.",
        'request': "subcommand + image selector",
        'response': "cc or image status",
    },

    # ------------------------------------------------------------------
    # Password encryption key rotation (0x9B)
    # ------------------------------------------------------------------
    (0x30, 0x9b): {
        'name': 'AMISetPwdEncryptionKey', 'priv': 'Admin', 'module': 'pwdenc',
        'tier': DESTRUCTIVE, 'block': 'pwdenc',
        'desc': "Rotate the AES password encryption key. Decrypts all stored "
                "IPMI user passwords + SMTP passwords with old key, re-encrypts "
                "with new key, writes new key to /conf/pwdEncKey. Also updates "
                "LDAP and AD bind passwords. Gate: "
                "CONFIG_SPX_FEATURE_ENABLE_USERPSWD_ENCRYPTION.",
        'request': "byte[] new AES encryption key",
        'response': "cc",
        'security': "CRITICAL: (1) Debug mode logs the new key to syslog in "
                    "plaintext ('REQUEST Len=%d Bytes: %s'). (2) Reads "
                    "/conf/AESKey + /conf/AESIV (fleet-shared). (3) All IPMI "
                    "passwords are transiently in cleartext during re-encryption. "
                    "(4) Rejects duplicate key ('Both new and existing keys are "
                    "same') — timing oracle on the current key.",
    },

    # ------------------------------------------------------------------
    # U-Boot memtest (0x9C–0x9D)
    # ------------------------------------------------------------------
    (0x30, 0x9c): {
        'name': 'AMISetUBootMemtest', 'priv': 'Admin', 'module': 'ubootmemtest',
        'tier': MUTATES, 'block': 'ubootmemtest',
        'desc': "Enable/disable U-Boot memory test on next boot.",
        'request': "byte enable/disable",
        'response': "cc",
    },
    (0x30, 0x9d): {
        'name': 'AMIGetUBootMemtestStatus', 'priv': 'Admin', 'module': 'ubootmemtest',
        'tier': SAFE, 'block': 'ubootmemtest',
        'desc': "Read U-Boot memtest enable state.",
        'request': "none",
        'response': "byte status",
    },

    # ------------------------------------------------------------------
    # RIS — Remote ISO start/stop + config (0x9E–0xA0)
    # ------------------------------------------------------------------
    (0x30, 0x9e): {
        'name': 'AMIGetRISConf', 'priv': 'User', 'module': 'ris',
        'tier': SAFE, 'block': 'ris',
        'desc': "Read Remote Image Share configuration.",
        'request': "none",
        'response': "RIS config (image path, mount type)",
    },
    (0x30, 0x9f): {
        'name': 'AMISetRISConf', 'priv': 'Admin', 'module': 'ris',
        'tier': MUTATES, 'block': 'ris',
        'desc': "Set Remote Image Share configuration.",
        'request': "RIS config blob",
        'response': "cc",
    },
    (0x30, 0xa0): {
        'name': 'AMIRISStartStop', 'priv': 'Admin', 'module': 'ris',
        'tier': MUTATES, 'block': 'ris',
        'desc': "Start or stop Remote Image Share mounting.",
        'request': "byte start/stop",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Debug message control (0xA1–0xA2)
    # ------------------------------------------------------------------
    (0x30, 0xa1): {
        'name': 'AMIControlDebugMsg', 'priv': 'Admin', 'module': 'ctldbg',
        'tier': MUTATES, 'block': 'ctldbg',
        'desc': "Enable/disable runtime debug logging. Creates or removes "
                "/var/enable.debugmsg flag file. When enabled, all 20+ IPMI "
                "handler libs (via libdbgout.so Runtime_DbgOut) output verbose "
                "debug messages to syslog + stderr. Gate: "
                "CONFIG_SPX_FEATURE_RUN_TIME_DBG_MSG_SUPPORT.",
        'request': "byte action (0=disable [unlink], 1=enable [touch])",
        'response': "cc",
        'security': "Enables debug output that may leak: AES keys (PwdEnc "
                    "logs key to syslog), credentials, Redis queries, config "
                    "paths, LDAP/AD bind passwords, SMTP passwords. An "
                    "attacker who enables debug can then harvest secrets "
                    "from syslog.",
    },
    (0x30, 0xa2): {
        'name': 'AMIGetDebugMsgStatus', 'priv': 'User', 'module': 'ctldbg',
        'tier': SAFE, 'block': 'ctldbg',
        'desc': "Check if runtime debug logging is enabled (stat() on "
                "/var/enable.debugmsg).",
        'request': "none",
        'response': "byte status (0=disabled, 1=enabled)",
    },

    # ------------------------------------------------------------------
    # Extended privilege — per-user service ACLs (0xA3–0xA4)
    # ------------------------------------------------------------------
    (0x30, 0xa3): {
        'name': 'AMISetExtendedPrivilege', 'priv': 'Admin', 'module': 'extpriv',
        'tier': MUTATES, 'block': 'extpriv',
        'desc': "Set per-user extended privilege bitmask. Maps bits to Linux "
                "group membership controlling access to KVM (GID 109), vmedia "
                "(539), Redfish (542), SOL-SSH (540), SMASH (533), CLI (534), "
                "and per-channel IPMI privilege levels (lan/serial groups). "
                "Calls AddIPMIUsrtoFlagsGrp(). Gate: "
                "CONFIG_SPX_FEATURE_EXTENDED_PRIV.",
        'request': "byte UserID + u32 ExtendedPriv bitmask",
        'response': "cc",
        'security': "Can grant any user full access to all BMC services. Does "
                    "NOT override command-level interface restrictions (the "
                    "0x80 KCS flag is compile-time, not runtime). Persists in "
                    "NV config and in BackupRestore blobs.",
    },
    (0x30, 0xa4): {
        'name': 'AMIGetExtendedPrivilege', 'priv': 'Operator', 'module': 'extpriv',
        'tier': SAFE, 'block': 'extpriv',
        'desc': "Read per-user extended privilege bitmask. From header: "
                "IPMICMD_AMIGetExtendedPrivilege(pSession, uint8 uid, "
                "INT32U *ExtendedPriv, timeout).",
        'request': "byte UserID",
        'response': "u32 ExtendedPriv bitmask",
    },

    # ------------------------------------------------------------------
    # Timezone (0xA5–0xA6)
    # ------------------------------------------------------------------
    (0x30, 0xa5): {
        'name': 'AMISetTimeZone', 'priv': 'Admin', 'module': 'timezone',
        'tier': MUTATES, 'block': 'timezone',
        'desc': "Set BMC timezone. Falls back to SetDefaultTimezone().",
        'request': "timezone string",
        'response': "cc",
    },
    (0x30, 0xa6): {
        'name': 'AMIGetTimeZone', 'priv': 'User', 'module': 'timezone',
        'tier': SAFE, 'block': 'timezone',
        'desc': "Read BMC timezone setting.",
        'request': "none",
        'response': "timezone string",
    },

    # ------------------------------------------------------------------
    # NTP (0xA7–0xA8)
    # ------------------------------------------------------------------
    (0x30, 0xa7): {
        'name': 'AMIGetNTPCfg', 'priv': 'Operator', 'module': 'ntp',
        'tier': SAFE, 'block': 'ntp',
        'desc': "Read NTP server configuration.",
        'request': "none",
        'response': "NTP config (servers, enable state)",
    },
    (0x30, 0xa8): {
        'name': 'AMISetNTPCfg', 'priv': 'Admin', 'module': 'ntp',
        'tier': MUTATES, 'block': 'ntp',
        'desc': "Set NTP server configuration. Validates server hostnames.",
        'request': "NTP config blob",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Power consumption / virtual device (0xAA–0xAB)
    # ------------------------------------------------------------------
    (0x30, 0xaa): {
        'name': 'AMIVirtualDeviceSetStatus', 'priv': 'Admin', 'module': 'pwrcons',
        'tier': MUTATES, 'block': 'pwrcons',
        'desc': "Set virtual device status (power consumption mode).",
        'request': "device selector + status",
        'response': "cc",
    },
    (0x30, 0xab): {
        'name': 'AMIVirtualDeviceGetStatus', 'priv': 'User', 'module': 'pwrcons',
        'tier': SAFE, 'block': 'pwrcons',
        'desc': "Read virtual device status.",
        'request': "device selector",
        'response': "status byte",
    },

    # ------------------------------------------------------------------
    # Host lock (0xAE–0xAF)
    # ------------------------------------------------------------------
    (0x30, 0xae): {
        'name': 'AMIGetHostLockFeatureStatus', 'priv': 'User', 'module': 'hostlock',
        'tier': SAFE, 'block': 'hostlock',
        'desc': "Read host-lock feature status (keyboard/video lock state). "
                "Gate: CONFIG_SPX_FEATURE_RUNTIME_HOST_LOCK.",
        'request': "none",
        'response': "byte status",
    },
    (0x30, 0xaf): {
        'name': 'AMISetHostLockFeatureStatus', 'priv': 'Admin', 'module': 'hostlock',
        'tier': MUTATES, 'block': 'hostlock',
        'desc': "Enable/disable host-lock (lock keyboard/video from remote KVM). "
                "Posts PendTask via g_PDKRemoteKVMHandle.",
        'request': "byte command (enable/disable)",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Session management (0xB0–0xB1)
    # ------------------------------------------------------------------
    (0x30, 0xb0): {
        'name': 'AMIGetAllActiveSessions', 'priv': 'User', 'module': 'sessionmgmt',
        'tier': SAFE, 'block': 'sessionmgmt',
        'desc': "List all active sessions (IPMI, web, VNC, SOL). Calls "
                "racsessinfo_getallrecords(). Checks VNC via dlopen of "
                "libvnc_extn.so. Gate: "
                "CONFIG_SPX_FEATURE_SESSION_MANAGEMENT_SUPPORT.",
        'request': "none",
        'response': "array of session records (type, user, IP, duration)",
    },
    (0x30, 0xb1): {
        'name': 'AMIActiveSessionClose', 'priv': 'Admin', 'module': 'sessionmgmt',
        'tier': MUTATES, 'block': 'sessionmgmt',
        'desc': "Force-close an active session by ID. Calls safe_system() with "
                "'/etc/child.sh %d'. Removes /tmp/solsessionactive%d.",
        'request': "session ID",
        'response': "cc",
        'security': "Uses safe_system('/etc/child.sh %d') — the session ID "
                    "is an integer, so no shell injection. But killing "
                    "sessions is a DoS vector.",
    },

    # ------------------------------------------------------------------
    # PLDM control (0xB2)
    # ------------------------------------------------------------------
    (0x30, 0xb2): {
        'name': 'AMICtrlPLDM', 'priv': 'Operator', 'module': 'pldm',
        'tier': MUTATES, 'block': 'pldm',
        'desc': "Control PLDM (Platform Level Data Model) daemon.",
        'request': "subcommand",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Auto video recording (0xB5–0xB6)
    # ------------------------------------------------------------------
    (0x30, 0xb5): {
        'name': 'AMIGetVideoRcdConf', 'priv': 'User', 'module': 'autovideorcd',
        'tier': SAFE, 'block': 'autovideorcd',
        'desc': "Read auto video recording configuration.",
        'request': "none",
        'response': "video recording config",
    },
    (0x30, 0xb6): {
        'name': 'AMISetVideoRcdConf', 'priv': 'Admin', 'module': 'autovideorcd',
        'tier': MUTATES, 'block': 'autovideorcd',
        'desc': "Set auto video recording config. Mounts video record path.",
        'request': "video recording config blob",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Single-port mode (0xB7–0xB8)
    # ------------------------------------------------------------------
    (0x30, 0xb7): {
        'name': 'AMIGetRunTimeSinglePortStatus', 'priv': 'User', 'module': 'singleport',
        'tier': SAFE, 'block': 'singleport',
        'desc': "Read single-port mode status (all services on one port).",
        'request': "none",
        'response': "byte status",
    },
    (0x30, 0xb8): {
        'name': 'AMISetRunTimeSinglePortStatus', 'priv': 'Admin', 'module': 'singleport',
        'tier': MUTATES, 'block': 'singleport',
        'desc': "Enable/disable single-port mode.",
        'request': "byte command",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Preserve all config (0xBA–0xBB)
    # ------------------------------------------------------------------
    (0x30, 0xba): {
        'name': 'AMISetAllPreserveConfStatus', 'priv': 'Admin', 'module': 'prsvconf',
        'tier': MUTATES, 'block': 'prsvconf',
        'desc': "Set preserve-config status for ALL sections at once.",
        'request': "byte[] bulk status array",
        'response': "cc",
    },
    (0x30, 0xbb): {
        'name': 'AMIGetAllPreserveConfStatus', 'priv': 'User', 'module': 'prsvconf',
        'tier': SAFE, 'block': 'prsvconf',
        'desc': "Read preserve-config status for ALL sections.",
        'request': "none",
        'response': "byte[] bulk status array",
    },

    # ------------------------------------------------------------------
    # Auto host lock (0xBC–0xBD)
    # ------------------------------------------------------------------
    (0x30, 0xbc): {
        'name': 'AMIGetHostAutoLockStatus', 'priv': 'User', 'module': 'autohostlock',
        'tier': SAFE, 'block': 'autohostlock',
        'desc': "Read auto host-lock status. Gate: "
                "CONFIG_SPX_FEATURE_HOST_LOCK_AUTO.",
        'request': "none",
        'response': "byte status",
    },
    (0x30, 0xbd): {
        'name': 'AMISetHostAutoLockStatus', 'priv': 'Admin', 'module': 'autohostlock',
        'tier': MUTATES, 'block': 'autohostlock',
        'desc': "Enable/disable auto host-lock. Posts PendTask via "
                "g_PDKRemoteKVMHandle.",
        'request': "byte command",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # PECI passthrough (0xBF) — raw CPU register access
    # ------------------------------------------------------------------
    (0x30, 0xbf): {
        'name': 'AMIPECIWriteRead', 'priv': 'Admin', 'module': 'peci',
        'tier': MUTATES, 'block': 'peci',
        'desc': "Raw PECI (Platform Environment Control Interface) write/read "
                "to the host CPU. Passes arbitrary PECI commands through the "
                "BMC to the CPU's PECI interface. Can read/write CPU MSRs, "
                "PCI config, MMIO, and internal state.",
        'request': "PECI command blob (target, domain, cmd, write data)",
        'response': "PECI response blob (completion, read data)",
        'security': "Direct CPU register access via BMC. Can read CPU MSRs, "
                    "PCI config space, and crash-dump data. A BMC compromise "
                    "enables host CPU state inspection without OS involvement.",
    },

    # ------------------------------------------------------------------
    # Remote KVM config (0xC0–0xC1)
    # ------------------------------------------------------------------
    (0x30, 0xc0): {
        'name': 'AMIGetRemoteKVMCfg', 'priv': 'User', 'module': 'remotekvm',
        'tier': SAFE, 'block': 'remotekvm',
        'desc': "Read remote KVM configuration.",
        'request': "none",
        'response': "KVM config (port, encryption, bandwidth)",
    },
    (0x30, 0xc1): {
        'name': 'AMISetRemoteKVMCfg', 'priv': 'Admin', 'module': 'remotekvm',
        'tier': MUTATES, 'block': 'remotekvm',
        'desc': "Set remote KVM configuration.",
        'request': "KVM config blob",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Active Directory (0xC4–0xC5)
    # ------------------------------------------------------------------
    (0x30, 0xc4): {
        'name': 'AMIGetADConf', 'priv': 'User', 'module': 'ad',
        'tier': SAFE, 'block': 'ad',
        'desc': "Read Active Directory configuration (server, domain, role "
                "groups). Calls GetADConfig() + GetSSADConfig(). Validates "
                "addresses with getaddrinfo() + inet_pton().",
        'request': "selector byte",
        'response': "AD config blob (server, base DN, role groups)",
        'security': "Returns AD configuration including server addresses "
                    "and role group mappings to any User-level session.",
    },
    (0x30, 0xc5): {
        'name': 'AMISetADConf', 'priv': 'Admin', 'module': 'ad',
        'tier': MUTATES, 'block': 'ad',
        'desc': "Set Active Directory configuration. Calls SetADConfig(). "
                "Gate: CONFIG_SPX_FEATURE_AUTHENTICATION_AD_SUPPORT.",
        'request': "AD config blob (server, base DN, bind creds, role groups)",
        'response': "cc",
        'security': "Can redirect AD auth to a rogue server. Stores AD bind "
                    "credentials. Combined with PAM reorder, enables full "
                    "auth-backend takeover.",
    },

    # ------------------------------------------------------------------
    # RADIUS (0xC6–0xC7)
    # ------------------------------------------------------------------
    (0x30, 0xc6): {
        'name': 'AMIGetRadiusConf', 'priv': 'User', 'module': 'radius',
        'tier': SAFE, 'block': 'radius',
        'desc': "Read RADIUS authentication configuration.",
        'request': "selector byte",
        'response': "RADIUS config (server, port, secret)",
    },
    (0x30, 0xc7): {
        'name': 'AMISetRadiusConf', 'priv': 'Admin', 'module': 'radius',
        'tier': MUTATES, 'block': 'radius',
        'desc': "Set RADIUS authentication configuration.",
        'request': "RADIUS config blob",
        'response': "cc",
        'security': "Can redirect RADIUS auth to attacker-controlled server.",
    },

    # ------------------------------------------------------------------
    # LDAP (0xC8–0xC9)
    # ------------------------------------------------------------------
    (0x30, 0xc8): {
        'name': 'AMIGetLDAPConf', 'priv': 'User', 'module': 'ldap',
        'tier': SAFE, 'block': 'ldap',
        'desc': "Read LDAP configuration. Validates identifiers.",
        'request': "selector byte",
        'response': "LDAP config blob (server, base DN, bind DN)",
    },
    (0x30, 0xc9): {
        'name': 'AMISetLDAPConf', 'priv': 'Admin', 'module': 'ldap',
        'tier': MUTATES, 'block': 'ldap',
        'desc': "Set LDAP configuration. Calls SB_BD_Validate() for bind DN "
                "validation.",
        'request': "LDAP config blob (server, base DN, bind creds)",
        'response': "cc",
        'security': "Can redirect LDAP auth to a rogue server. Combined with "
                    "PAM reorder → full auth-backend takeover.",
    },

    # ------------------------------------------------------------------
    # Virtual media (0xCA–0xCB, 0xD7–0xD9, 0xDC)
    # ------------------------------------------------------------------
    (0x30, 0xca): {
        'name': 'AMIGetVmediaCfg', 'priv': 'User', 'module': 'media',
        'tier': SAFE, 'block': 'media',
        'desc': "Read virtual media configuration.",
        'request': "none",
        'response': "vmedia config (enabled, encryption, CD/HD count)",
    },
    (0x30, 0xcb): {
        'name': 'AMISetVmediaCfg', 'priv': 'Admin', 'module': 'media',
        'tier': MUTATES, 'block': 'media',
        'desc': "Set virtual media configuration.",
        'request': "vmedia config blob",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # Extended SEL (0xCC–0xCD, 0xF0–0xF1)
    # ------------------------------------------------------------------
    (0x30, 0xcc): {
        'name': 'AMIAddExtendSelEntries', 'priv': 'Admin', 'module': 'extendedsel',
        'tier': MUTATES, 'block': 'extsel',
        'desc': "Add entries to extended SEL (beyond standard 64KB IPMI SEL). "
                "Writes to NVRAM-backed extended SEL files.",
        'request': "SEL record data",
        'response': "cc + record ID",
    },
    (0x30, 0xcd): {
        'name': 'AMIGETExtendSelData', 'priv': 'User', 'module': 'extendedsel',
        'tier': SAFE, 'block': 'extsel',
        'desc': "Read extended SEL data.",
        'request': "record selector",
        'response': "extended SEL record(s)",
    },

    # ------------------------------------------------------------------
    # BIOS remote control — BMC<->BIOS message channel (0xCE–0xD4)
    # ------------------------------------------------------------------
    (0x30, 0xce): {
        'name': 'AMISendToBios', 'priv': 'User', 'module': 'biosremotecontrol',
        'tier': MUTATES, 'block': 'biosremotecontrol',
        'desc': "Send a command to the BIOS via the BMC<->BIOS message channel. "
                "Gate: CONFIG_SPX_FEATURE_BIOS_REMOTE_CONTROL.",
        'request': "byte[] command data for BIOS",
        'response': "cc",
    },
    (0x30, 0xcf): {
        'name': 'AMIGetBiosCommand', 'priv': 'Callback', 'module': 'biosremotecontrol',
        'tier': SAFE, 'block': 'biosremotecontrol',
        'desc': "Read pending BIOS command from the message channel. Intended "
                "for the BIOS to poll from KCS. Priv Callback = any user.",
        'request': "none",
        'response': "byte[] pending command data",
    },
    (0x30, 0xd1): {
        'name': 'AMISetBiosResponse', 'priv': 'Callback', 'module': 'biosremotecontrol',
        'tier': MUTATES, 'block': 'biosremotecontrol',
        'desc': "Set the BIOS response to a previously sent command.",
        'request': "byte[] response data from BIOS",
        'response': "cc",
    },
    (0x30, 0xd2): {
        'name': 'AMIGetBiosResponse', 'priv': 'User', 'module': 'biosremotecontrol',
        'tier': SAFE, 'block': 'biosremotecontrol',
        'desc': "Read the BIOS response after sending a command.",
        'request': "none",
        'response': "byte[] BIOS response data",
    },
    (0x30, 0xd3): {
        'name': 'AMISetBiosFlag', 'priv': 'User', 'module': 'biosremotecontrol',
        'tier': MUTATES, 'block': 'biosremotecontrol',
        'desc': "Set a BIOS control flag. Written to "
                "/conf/BMC%d/BIOS_FLAG.ini via IniGetUInt.",
        'request': "byte flag value",
        'response': "cc",
    },
    (0x30, 0xd4): {
        'name': 'AMIGetBiosFlag', 'priv': 'User', 'module': 'biosremotecontrol',
        'tier': SAFE, 'block': 'biosremotecontrol',
        'desc': "Read BIOS control flag from /conf/BMC%d/BIOS_FLAG.ini.",
        'request': "none",
        'response': "byte flag value",
    },

    # ------------------------------------------------------------------
    # PLDM BIOS messages (0xD5)
    # ------------------------------------------------------------------
    (0x30, 0xd5): {
        'name': 'AMIPLDMBIOSMsg', 'priv': 'User', 'module': 'pldmcmds',
        'tier': SAFE, 'block': 'pldm',
        'desc': "Send/receive PLDM BIOS table messages. Handles BIOS table "
                "tags, block-level transfers, and response assembly.",
        'request': "PLDM BIOS table request",
        'response': "PLDM BIOS table response (block data)",
    },

    # ------------------------------------------------------------------
    # Virtual media operations (0xD7–0xD9, 0xDC)
    # ------------------------------------------------------------------
    (0x30, 0xd7): {
        'name': 'AMIMediaRedirectionStartStop', 'priv': 'Admin', 'module': 'media',
        'tier': MUTATES, 'block': 'media',
        'desc': "Start or stop virtual media redirection.",
        'request': "byte command (start/stop) + media type",
        'response': "cc",
    },
    (0x30, 0xd8): {
        'name': 'AMIGetMediaInfo', 'priv': 'User', 'module': 'media',
        'tier': SAFE, 'block': 'media',
        'desc': "Read virtual media status and mounted image info.",
        'request': "media type selector",
        'response': "media info (image name, status, type)",
    },
    (0x30, 0xd9): {
        'name': 'AMISetMediaInfo', 'priv': 'Admin', 'module': 'media',
        'tier': MUTATES, 'block': 'media',
        'desc': "Set virtual media info (mount image, configure redirection).",
        'request': "media config blob",
        'response': "cc",
    },

    # ------------------------------------------------------------------
    # SD card partition (0xDA–0xDB)
    # ------------------------------------------------------------------
    (0x30, 0xda): {
        'name': 'AMIGetSDCardPartition', 'priv': 'User', 'module': 'sd',
        'tier': SAFE, 'block': 'sd',
        'desc': "Read SD card partition configuration.",
        'request': "none",
        'response': "partition config",
    },
    (0x30, 0xdb): {
        'name': 'AMISetSDCardPartition', 'priv': 'Admin', 'module': 'sd',
        'tier': DESTRUCTIVE, 'block': 'sd',
        'desc': "Set SD card partition layout.",
        'request': "partition config",
        'response': "cc",
    },

    (0x30, 0xdc): {
        'name': 'AMIGetRedirectedMediaInfo', 'priv': 'User', 'module': 'media',
        'tier': SAFE, 'block': 'media',
        'desc': "Read currently redirected media info.",
        'request': "none",
        'response': "redirected media status",
    },

    # ------------------------------------------------------------------
    # Backup / Restore BMC config (0xE3–0xE5)
    # ------------------------------------------------------------------
    (0x30, 0xe3): {
        'name': 'AMISetBackupFlag', 'priv': 'Admin', 'module': 'backuprestore',
        'tier': MUTATES, 'block': 'backuprestore',
        'desc': "Set backup/restore operation flag. Validates flag value. "
                "Gate: CONFIG_SPX_FEATURE_BACKUP_CONFIG_SUPPORT.",
        'request': "byte flag (backup-in-progress, restore-in-progress, etc.)",
        'response': "cc",
    },
    (0x30, 0xe4): {
        'name': 'AMIGetBackupFlag', 'priv': 'User', 'module': 'backuprestore',
        'tier': SAFE, 'block': 'backuprestore',
        'desc': "Read current backup/restore operation flag.",
        'request': "none",
        'response': "byte flag",
    },
    (0x30, 0xe5): {
        'name': 'AMIManageBMCConfig', 'priv': 'Admin', 'module': 'backuprestore',
        'tier': DESTRUCTIVE, 'block': 'backuprestore',
        'desc': "Trigger BMC config backup or restore. Delegates to "
                "libBackupConf.so which reads /conf/backup_cfg_list-AMI.ini "
                "for the list of 50+ config files to back up. Backup blob is "
                "AES-encrypted with fleet-shared key from /conf/AESKey + "
                "/conf/AESIV, written to /mnt/sdmmc0p*/confbkup/. Includes "
                "IPMIConfig.dat, /etc/shadow, network config, LDAP/AD/RADIUS "
                "config. 'Pend Task for ManageBMCConfig' prevents concurrent "
                "operations.",
        'request': "byte subcommand (0=backup, 1=restore)",
        'response': "cc (async — poll via GetBackupFlag for completion)",
        'security': "CRITICAL: Restore = config-level BMC takeover. An "
                    "attacker who crafts a backup blob (encrypted with the "
                    "fleet-shared AES key from firmware) can overwrite all "
                    "BMC credentials, network config, iptables rules, "
                    "LDAP/AD settings, and the shadow file.",
    },

    # ------------------------------------------------------------------
    # RAID info (0xEF)
    # ------------------------------------------------------------------
    (0x30, 0xef): {
        'name': 'AMIGetRAIDInfo', 'priv': 'Operator', 'module': 'raidinfo',
        'tier': SAFE, 'block': 'raidinfo',
        'desc': "Read RAID controller, logical drive, physical drive, and "
                "enclosure information. 55 internal handlers for SAS/IT and "
                "RAID controllers.",
        'request': "subcommand selector (controller/LD/PD/enclosure/topo)",
        'response': "variable-length RAID info blob",
    },

    # ------------------------------------------------------------------
    # Extended SEL partial operations (0xF0–0xF1)
    # ------------------------------------------------------------------
    (0x30, 0xf0): {
        'name': 'AMIPartialAddExtendSelEntries', 'priv': 'Admin',
        'module': 'extendedsel',
        'tier': MUTATES, 'block': 'extsel',
        'desc': "Add extended SEL entries in partial (chunked) writes.",
        'request': "offset + chunk data",
        'response': "cc",
    },
    (0x30, 0xf1): {
        'name': 'AMIPartialGetExtendSelEntries', 'priv': 'Admin',
        'module': 'extendedsel',
        'tier': SAFE, 'block': 'extsel',
        'desc': "Read extended SEL entries in partial (chunked) reads.",
        'request': "offset + length",
        'response': "chunk data",
    },

    # ------------------------------------------------------------------
    # UART / Serial logging + SOL triggers (0xF5–0xF8, 0xFE)
    # ------------------------------------------------------------------
    (0x30, 0xf5): {
        'name': 'AMISetSerialLogConf', 'priv': 'Admin', 'module': 'uartlogging',
        'tier': MUTATES, 'block': 'uartlogging',
        'desc': "Set serial/UART logging configuration.",
        'request': "serial log config blob",
        'response': "cc",
    },
    (0x30, 0xf6): {
        'name': 'AMIGetSerialLogConf', 'priv': 'Operator', 'module': 'uartlogging',
        'tier': SAFE, 'block': 'uartlogging',
        'desc': "Read serial/UART logging configuration.",
        'request': "none",
        'response': "serial log config",
    },
    (0x30, 0xf7): {
        'name': 'AMISetSOLTriggerEvent', 'priv': 'Admin', 'module': 'uartlogging',
        'tier': MUTATES, 'block': 'uartlogging',
        'desc': "Set SOL (Serial Over LAN) trigger event configuration. "
                "Stored in /conf/BMC1/SOLTriggerEvtConfig.ini.",
        'request': "trigger event config",
        'response': "cc",
    },
    (0x30, 0xf8): {
        'name': 'AMIGetSOLTriggerEvent', 'priv': 'Operator', 'module': 'uartlogging',
        'tier': SAFE, 'block': 'uartlogging',
        'desc': "Read SOL trigger event configuration.",
        'request': "none",
        'response': "trigger event config",
    },
    (0x30, 0xfe): {
        'name': 'AMIGetSOLArchiveData', 'priv': 'Operator', 'module': 'uartlogging',
        'tier': SAFE, 'block': 'uartlogging',
        'desc': "Read archived SOL session data.",
        'request': "offset + length",
        'response': "SOL archive data chunk",
    },
}
MEGARAC_CMD_NAMES: dict[tuple[int, int], str] = {k: v['name'] for k, v in MEGARAC_COMMANDS.items()}

MEGARAC_IANA = 20974      # AMI (American Megatrends, Inc.) PEN — metadata only; the OEM
                          # cmds ride raw NetFn 0x30/0x3E with no IANA on the wire, so the
                          # registry entry below is None (never claims a manuf-id slot).
MEGARAC_MANUF_ID = 15370  # on-wire IPMI Manufacturer ID on the XD670 (GIGA-BYTE board vendor)
MEGARAC_HANDLER_COUNT = 210  # total exported symbols across the 40 libs (inc. helpers)
MEGARAC_COMMAND_COUNT = len(MEGARAC_COMMANDS)  # registered IPMI OEM commands (opcode-resolved)

register("megarac", None, MEGARAC_CMD_NAMES)

__all__ = [
    "SAFE", "MUTATES", "DESTRUCTIVE",
    "MEGARAC_HANDLERS", "MEGARAC_COMMANDS", "MEGARAC_CMD_NAMES",
    "MEGARAC_IANA", "MEGARAC_MANUF_ID", "MEGARAC_HANDLER_COUNT", "MEGARAC_COMMAND_COUNT",
]
