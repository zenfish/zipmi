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

STATE    Handler NAMES only (below). Per-command (NetFn,Cmd) OPCODE bytes are
         NOT yet mapped — the firmware-firewall returns near-full bitmasks for
         OEM NetFns (no granular per-cmd firewalling), so opcodes come from each
         .so's registration table, not the live mask. Recover them by unsquashing
         the BMC rootfs (rootfs.sqfs -> libipmiamioem*.so) and parsing the
         handler-pointer table, or live via GetLibMetaInfo on the booted box.
         Fill MEGARAC_CMD_NAMES as they land — the CLI/registry pick them up
         automatically then.

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


# (NetFn, Cmd) -> name. EMPTY for now: opcode bytes need the per-.so registration
# -table parse (see STATE in the module docstring). Names live in MEGARAC_HANDLERS
# above; add (netfn, cmd) rows here as opcodes are recovered and they light up in
# `zipmi oem megarac` + the decode registry automatically.
MEGARAC_CMD_NAMES: dict[tuple[int, int], str] = {}

MEGARAC_IANA = 20974      # AMI (American Megatrends, Inc.) PEN — metadata only; the OEM
                          # cmds ride raw NetFn 0x30/0x3E with no IANA on the wire, so the
                          # registry entry below is None (never claims a manuf-id slot).
MEGARAC_MANUF_ID = 15370  # on-wire IPMI Manufacturer ID on the XD670 (GIGA-BYTE board vendor)
MEGARAC_HANDLER_COUNT = 210

register("megarac", None, MEGARAC_CMD_NAMES)

__all__ = [
    "MEGARAC_HANDLERS", "MEGARAC_CMD_NAMES",
    "MEGARAC_IANA", "MEGARAC_MANUF_ID", "MEGARAC_HANDLER_COUNT",
]
