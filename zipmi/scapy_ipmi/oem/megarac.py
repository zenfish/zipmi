"""zipmi.scapy_ipmi.oem.megarac — AMI MegaRAC SP-X OEM handler inventory.

WHAT     Stock AMI MegaRAC SP-X 13.x LTS OEM command handlers (210 across
         40 modules), extracted from the .dynsym of the
         /usr/local/lib/ipmi/libipmiamioem<x>.so handler libraries. This is the
         provider behind "HPE/Cray XD670" and every other MegaRAC-on-* box —
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
    (0x30, 0x18): {'name': 'AMIGetRMediaCfg', 'priv': 'User', 'module': 'ris'},
    (0x30, 0x19): {'name': 'AMISetRMediaCfg', 'priv': 'Admin', 'module': 'ris'},
    (0x30, 0x2a): {'name': 'AMIAccessRedisDB', 'priv': 'Callback', 'module': 'accessredis'},
    (0x30, 0x2c): {'name': 'AMIOemSetRedisDB', 'priv': 'Callback', 'module': 'accessredis'},
    (0x30, 0x43): {'name': 'AMIRemoteDebugSetInfo', 'priv': 'Admin', 'module': 'Remotedebug'},
    (0x30, 0x44): {'name': 'AMIRemoteDebugGetInfo', 'priv': 'Admin', 'module': 'Remotedebug'},
    (0x30, 0x47): {'name': 'AMIACDSetInfo', 'priv': 'Admin', 'module': 'acd'},
    (0x30, 0x48): {'name': 'AMIACDGetInfo', 'priv': 'User', 'module': 'acd'},
    (0x30, 0x4a): {'name': 'AMISensorThresholdAcrossResets', 'priv': 'User', 'module': 'sensorthresholdacrossresets'},
    (0x30, 0x5c): {'name': 'AMIRESTinterface', 'priv': 'Admin', 'module': 'restiface'},
    (0x30, 0x5d): {'name': 'AMIGeneratePassword', 'priv': 'Callback', 'module': 'restiface'},
    (0x30, 0x69): {'name': 'AMIGetServiceConf', 'priv': 'User', 'module': 'serviceconf'},
    (0x30, 0x6a): {'name': 'AMISetServiceConf', 'priv': 'Admin', 'module': 'serviceconf'},
    (0x30, 0x73): {'name': 'AMIGetBiosCode', 'priv': 'User', 'module': 'bioscode'},
    (0x30, 0x76): {'name': 'AMISetFirewall', 'priv': 'Admin', 'module': 'firewall'},
    (0x30, 0x77): {'name': 'AMIGetFirewall', 'priv': 'User', 'module': 'firewall'},
    (0x30, 0x7a): {'name': 'AMISetPamOrder', 'priv': 'Admin', 'module': 'pamreorder'},
    (0x30, 0x7b): {'name': 'AMIGetPamOrder', 'priv': 'User', 'module': 'pamreorder'},
    (0x30, 0x7c): {'name': 'AMIGetSNMPConf', 'priv': 'User', 'module': 'snmp'},
    (0x30, 0x7d): {'name': 'AMISetSNMPConf', 'priv': 'Admin', 'module': 'snmp'},
    (0x30, 0x83): {'name': 'AMISetPreserveConfStatus', 'priv': 'Admin', 'module': 'prsvconf'},
    (0x30, 0x84): {'name': 'AMIGetPreserveConfStatus', 'priv': 'User', 'module': 'prsvconf'},
    (0x30, 0x87): {'name': 'AMIStartTFTPFwUpdate', 'priv': 'Admin', 'module': 'fwupdateprctl'},
    (0x30, 0x88): {'name': 'AMIGetTftpProgressStatus', 'priv': 'Admin', 'module': 'fwupdateprctl'},
    (0x30, 0x89): {'name': 'AMISetFWCfg', 'priv': 'Admin', 'module': 'fwupdateprctl'},
    (0x30, 0x8a): {'name': 'AMIGetFWCfg', 'priv': 'Admin', 'module': 'fwupdateprctl'},
    (0x30, 0x8b): {'name': 'AMISetFWProtocol', 'priv': 'Admin', 'module': 'fwupdateprctl'},
    (0x30, 0x8c): {'name': 'AMIGetFWProtocol', 'priv': 'Admin', 'module': 'fwupdateprctl'},
    (0x30, 0x8f): {'name': 'AMIDualImageSupport', 'priv': 'Admin', 'module': 'dualimg'},
    (0x30, 0x9b): {'name': 'AMISetPwdEncryptionKey', 'priv': 'Admin', 'module': 'pwdenc'},
    (0x30, 0x9c): {'name': 'AMISetUBootMemtest', 'priv': 'Admin', 'module': 'ubootmemtest'},
    (0x30, 0x9d): {'name': 'AMIGetUBootMemtestStatus', 'priv': 'Admin', 'module': 'ubootmemtest'},
    (0x30, 0x9e): {'name': 'AMIGetRISConf', 'priv': 'User', 'module': 'ris'},
    (0x30, 0x9f): {'name': 'AMISetRISConf', 'priv': 'Admin', 'module': 'ris'},
    (0x30, 0xa0): {'name': 'AMIRISStartStop', 'priv': 'Admin', 'module': 'ris'},
    (0x30, 0xa1): {'name': 'AMIControlDebugMsg', 'priv': 'Admin', 'module': 'ctldbg'},
    (0x30, 0xa2): {'name': 'AMIGetDebugMsgStatus', 'priv': 'User', 'module': 'ctldbg'},
    (0x30, 0xa3): {'name': 'AMISetExtendedPrivilege', 'priv': 'Admin', 'module': 'extpriv'},
    (0x30, 0xa4): {'name': 'AMIGetExtendedPrivilege', 'priv': 'Operator', 'module': 'extpriv'},
    (0x30, 0xa5): {'name': 'AMISetTimeZone', 'priv': 'Admin', 'module': 'timezone'},
    (0x30, 0xa6): {'name': 'AMIGetTimeZone', 'priv': 'User', 'module': 'timezone'},
    (0x30, 0xa7): {'name': 'AMIGetNTPCfg', 'priv': 'Operator', 'module': 'ntp'},
    (0x30, 0xa8): {'name': 'AMISetNTPCfg', 'priv': 'Admin', 'module': 'ntp'},
    (0x30, 0xaa): {'name': 'AMIVirtualDeviceSetStatus', 'priv': 'Admin', 'module': 'pwrcons'},
    (0x30, 0xab): {'name': 'AMIVirtualDeviceGetStatus', 'priv': 'User', 'module': 'pwrcons'},
    (0x30, 0xae): {'name': 'AMIGetHostLockFeatureStatus', 'priv': 'User', 'module': 'hostlock'},
    (0x30, 0xaf): {'name': 'AMISetHostLockFeatureStatus', 'priv': 'Admin', 'module': 'hostlock'},
    (0x30, 0xb0): {'name': 'AMIGetAllActiveSessions', 'priv': 'User', 'module': 'sessionmgmt'},
    (0x30, 0xb1): {'name': 'AMIActiveSessionClose', 'priv': 'Admin', 'module': 'sessionmgmt'},
    (0x30, 0xb2): {'name': 'AMICtrlPLDM', 'priv': 'Operator', 'module': 'pldm'},
    (0x30, 0xb5): {'name': 'AMIGetVideoRcdConf', 'priv': 'User', 'module': 'autovideorcd'},
    (0x30, 0xb6): {'name': 'AMISetVideoRcdConf', 'priv': 'Admin', 'module': 'autovideorcd'},
    (0x30, 0xb7): {'name': 'AMIGetRunTimeSinglePortStatus', 'priv': 'User', 'module': 'singleport'},
    (0x30, 0xb8): {'name': 'AMISetRunTimeSinglePortStatus', 'priv': 'Admin', 'module': 'singleport'},
    (0x30, 0xba): {'name': 'AMISetAllPreserveConfStatus', 'priv': 'Admin', 'module': 'prsvconf'},
    (0x30, 0xbb): {'name': 'AMIGetAllPreserveConfStatus', 'priv': 'User', 'module': 'prsvconf'},
    (0x30, 0xbc): {'name': 'AMIGetHostAutoLockStatus', 'priv': 'User', 'module': 'autohostlock'},
    (0x30, 0xbd): {'name': 'AMISetHostAutoLockStatus', 'priv': 'Admin', 'module': 'autohostlock'},
    (0x30, 0xbf): {'name': 'AMIPECIWriteRead', 'priv': 'Admin', 'module': 'peci'},
    (0x30, 0xc0): {'name': 'AMIGetRemoteKVMCfg', 'priv': 'User', 'module': 'remotekvm'},
    (0x30, 0xc1): {'name': 'AMISetRemoteKVMCfg', 'priv': 'Admin', 'module': 'remotekvm'},
    (0x30, 0xc4): {'name': 'AMIGetADConf', 'priv': 'User', 'module': 'ad'},
    (0x30, 0xc5): {'name': 'AMISetADConf', 'priv': 'Admin', 'module': 'ad'},
    (0x30, 0xc6): {'name': 'AMIGetRadiusConf', 'priv': 'User', 'module': 'radius'},
    (0x30, 0xc7): {'name': 'AMISetRadiusConf', 'priv': 'Admin', 'module': 'radius'},
    (0x30, 0xc8): {'name': 'AMIGetLDAPConf', 'priv': 'User', 'module': 'ldap'},
    (0x30, 0xc9): {'name': 'AMISetLDAPConf', 'priv': 'Admin', 'module': 'ldap'},
    (0x30, 0xca): {'name': 'AMIGetVmediaCfg', 'priv': 'User', 'module': 'media'},
    (0x30, 0xcb): {'name': 'AMISetVmediaCfg', 'priv': 'Admin', 'module': 'media'},
    (0x30, 0xcc): {'name': 'AMIAddExtendSelEntries', 'priv': 'Admin', 'module': 'extendedsel'},
    (0x30, 0xcd): {'name': 'AMIGETExtendSelData', 'priv': 'User', 'module': 'extendedsel'},
    (0x30, 0xce): {'name': 'AMISendToBios', 'priv': 'User', 'module': 'biosremotecontrol'},
    (0x30, 0xcf): {'name': 'AMIGetBiosCommand', 'priv': 'Callback', 'module': 'biosremotecontrol'},
    (0x30, 0xd1): {'name': 'AMISetBiosResponse', 'priv': 'Callback', 'module': 'biosremotecontrol'},
    (0x30, 0xd2): {'name': 'AMIGetBiosResponse', 'priv': 'User', 'module': 'biosremotecontrol'},
    (0x30, 0xd3): {'name': 'AMISetBiosFlag', 'priv': 'User', 'module': 'biosremotecontrol'},
    (0x30, 0xd4): {'name': 'AMIGetBiosFlag', 'priv': 'User', 'module': 'biosremotecontrol'},
    (0x30, 0xd5): {'name': 'AMIPLDMBIOSMsg', 'priv': 'User', 'module': 'pldmcmds'},
    (0x30, 0xd7): {'name': 'AMIMediaRedirectionStartStop', 'priv': 'Admin', 'module': 'media'},
    (0x30, 0xd8): {'name': 'AMIGetMediaInfo', 'priv': 'User', 'module': 'media'},
    (0x30, 0xd9): {'name': 'AMISetMediaInfo', 'priv': 'Admin', 'module': 'media'},
    (0x30, 0xda): {'name': 'AMIGetSDCardPartition', 'priv': 'User', 'module': 'sd'},
    (0x30, 0xdb): {'name': 'AMISetSDCardPartition', 'priv': 'Admin', 'module': 'sd'},
    (0x30, 0xdc): {'name': 'AMIGetRedirectedMediaInfo', 'priv': 'User', 'module': 'media'},
    (0x30, 0xe3): {'name': 'AMISetBackupFlag', 'priv': 'Admin', 'module': 'backuprestore'},
    (0x30, 0xe4): {'name': 'AMIGetBackupFlag', 'priv': 'User', 'module': 'backuprestore'},
    (0x30, 0xe5): {'name': 'AMIManageBMCConfig', 'priv': 'Admin', 'module': 'backuprestore'},
    (0x30, 0xef): {'name': 'AMIGetRAIDInfo', 'priv': 'Operator', 'module': 'raidinfo'},
    (0x30, 0xf0): {'name': 'AMIPartialAddExtendSelEntries', 'priv': 'Admin', 'module': 'extendedsel'},
    (0x30, 0xf1): {'name': 'AMIPartialGetExtendSelEntries', 'priv': 'Admin', 'module': 'extendedsel'},
    (0x30, 0xf5): {'name': 'AMISetSerialLogConf', 'priv': 'Admin', 'module': 'uartlogging'},
    (0x30, 0xf6): {'name': 'AMIGetSerialLogConf', 'priv': 'Operator', 'module': 'uartlogging'},
    (0x30, 0xf7): {'name': 'AMISetSOLTriggerEvent', 'priv': 'Admin', 'module': 'uartlogging'},
    (0x30, 0xf8): {'name': 'AMIGetSOLTriggerEvent', 'priv': 'Operator', 'module': 'uartlogging'},
    (0x30, 0xfe): {'name': 'AMIGetSOLArchiveData', 'priv': 'Operator', 'module': 'uartlogging'},
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
    "MEGARAC_HANDLERS", "MEGARAC_COMMANDS", "MEGARAC_CMD_NAMES",
    "MEGARAC_IANA", "MEGARAC_MANUF_ID", "MEGARAC_HANDLER_COUNT", "MEGARAC_COMMAND_COUNT",
]
