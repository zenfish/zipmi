# AMI MegaRAC SP-X — OEM IPMI command catalog

Auto-generated from `zipmi.scapy_ipmi.oem.megarac` and `zipmi.scapy_ipmi.oem.yafu`.
**DO NOT EDIT BY HAND.**

Source: Static RE of AMI MegaRAC SP-X 13.04 (HPE XD670 BMC v1.27, AST2600)

## Summary

**95** OEM commands across 39 handler modules, plus **42** YAFU firmware-update protocol commands.

| Metric | Count |
|--------|-------|
| Safe (read-only / query) | 47 |
| Mutates (changes state) | 43 |
| Destructive (irreversible) | 5 |
| Security notes | 18 |

## Blocks

| Block | Cmds | Commands |
|-------|------|----------|
| acd | 2 | AMIACDSetInfo, AMIACDGetInfo |
| ad | 2 | AMIGetADConf, AMISetADConf |
| autohostlock | 2 | AMIGetHostAutoLockStatus, AMISetHostAutoLockStatus |
| autovideorcd | 2 | AMIGetVideoRcdConf, AMISetVideoRcdConf |
| backuprestore | 3 | AMISetBackupFlag, AMIGetBackupFlag, AMIManageBMCConfig |
| bioscode | 1 | AMIGetBiosCode |
| biosremotecontrol | 6 | AMISendToBios, AMIGetBiosCommand, AMISetBiosResponse, ... |
| ctldbg | 2 | AMIControlDebugMsg, AMIGetDebugMsgStatus |
| dualimg | 1 | AMIDualImageSupport |
| extpriv | 2 | AMISetExtendedPrivilege, AMIGetExtendedPrivilege |
| extsel | 4 | AMIAddExtendSelEntries, AMIGETExtendSelData, AMIPartialAddExtendSelEntries, ... |
| firewall | 2 | AMISetFirewall, AMIGetFirewall |
| fwupdate | 6 | AMIStartTFTPFwUpdate, AMIGetTftpProgressStatus, AMISetFWCfg, ... |
| hostlock | 2 | AMIGetHostLockFeatureStatus, AMISetHostLockFeatureStatus |
| ldap | 2 | AMIGetLDAPConf, AMISetLDAPConf |
| media | 6 | AMIGetVmediaCfg, AMISetVmediaCfg, AMIMediaRedirectionStartStop, ... |
| ntp | 2 | AMIGetNTPCfg, AMISetNTPCfg |
| pamreorder | 2 | AMISetPamOrder, AMIGetPamOrder |
| peci | 1 | AMIPECIWriteRead |
| pldm | 2 | AMICtrlPLDM, AMIPLDMBIOSMsg |
| prsvconf | 4 | AMISetPreserveConfStatus, AMIGetPreserveConfStatus, AMISetAllPreserveConfStatus, ... |
| pwdenc | 1 | AMISetPwdEncryptionKey |
| pwrcons | 2 | AMIVirtualDeviceSetStatus, AMIVirtualDeviceGetStatus |
| radius | 2 | AMIGetRadiusConf, AMISetRadiusConf |
| raidinfo | 1 | AMIGetRAIDInfo |
| redis | 2 | AMIAccessRedisDB, AMIOemSetRedisDB |
| remotedebug | 2 | AMIRemoteDebugSetInfo, AMIRemoteDebugGetInfo |
| remotekvm | 2 | AMIGetRemoteKVMCfg, AMISetRemoteKVMCfg |
| restiface | 2 | AMIRESTinterface, AMIGeneratePassword |
| ris | 5 | AMIGetRMediaCfg, AMISetRMediaCfg, AMIGetRISConf, ... |
| sd | 2 | AMIGetSDCardPartition, AMISetSDCardPartition |
| sensor | 1 | AMISensorThresholdAcrossResets |
| serviceconf | 2 | AMIGetServiceConf, AMISetServiceConf |
| sessionmgmt | 2 | AMIGetAllActiveSessions, AMIActiveSessionClose |
| singleport | 2 | AMIGetRunTimeSinglePortStatus, AMISetRunTimeSinglePortStatus |
| snmp | 2 | AMIGetSNMPConf, AMISetSNMPConf |
| timezone | 2 | AMISetTimeZone, AMIGetTimeZone |
| uartlogging | 5 | AMISetSerialLogConf, AMIGetSerialLogConf, AMISetSOLTriggerEvent, ... |
| ubootmemtest | 2 | AMISetUBootMemtest, AMIGetUBootMemtestStatus |

## OEM Commands (NetFn 0x30)

| Cmd | Name | Priv | Tier | Module | Description | Sec |
|-----|------|------|------|--------|-------------|-----|
| 0x18 | AMIGetRMediaCfg | User | safe | ris | Get remote media (NFS/CIFS/HTTP ISO) share configuration. |  |
| 0x19 | AMISetRMediaCfg | Admin | mutates | ris | Set remote media share config (NFS/CIFS/HTTP mount point). |  |
| 0x2A | AMIAccessRedisDB | Callback | safe | accessredis | Execute arbitrary Redis commands against the BMC's data store. Connects to /r... | ⚠️ |
| 0x2C | AMIOemSetRedisDB | Callback | destructive | accessredis | Write arbitrary Redis key/value pairs. Same KCS/host-interface access as Acce... | ⚠️ |
| 0x43 | AMIRemoteDebugSetInfo | Admin | mutates | Remotedebug | Configure remote debug server + upload TLS certificates. |  |
| 0x44 | AMIRemoteDebugGetInfo | Admin | safe | Remotedebug | Read remote debug server status and configuration. |  |
| 0x47 | AMIACDSetInfo | Admin | mutates | acd | Configure Intel ACD (Autonomous Crash Dump) — enable/disable, set data area, ... |  |
| 0x48 | AMIACDGetInfo | User | safe | acd | Read ACD status, data area, and crash dump availability. |  |
| 0x4A | AMISensorThresholdAcrossResets | User | safe | sensorthresholdacrossresets | Get/set whether sensor thresholds persist across BMC resets. |  |
| 0x5C | AMIRESTinterface | Admin | mutates | restiface | Host-interface REST/Redfish bridge. Relays Redfish requests from the host OS ... | ⚠️ |
| 0x5D | AMIGeneratePassword | Callback | safe | restiface | Generate a random alphanumeric password from /dev/urandom. Priv byte 0x81 = h... | ⚠️ |
| 0x69 | AMIGetServiceConf | User | safe | serviceconf | Read BMC service configuration (port numbers, enable/disable state for HTTPS,... |  |
| 0x6A | AMISetServiceConf | Admin | mutates | serviceconf | Set BMC service configuration. Validates port ranges and blocks port 80 ('Uns... |  |
| 0x73 | AMIGetBiosCode | User | safe | bioscode | Read current and previous BIOS POST codes from the SNOOP device (libsnoop.so)... |  |
| 0x76 | AMISetFirewall | Admin | mutates | firewall | Add/delete iptables/ip6tables rules on the BMC. Validates IPv4/IPv6 ranges an... | ⚠️ |
| 0x77 | AMIGetFirewall | User | safe | firewall | Read current iptables/ip6tables firewall rules and counts. |  |
| 0x7A | AMISetPamOrder | Admin | mutates | pamreorder | Reorder PAM authentication modules (local, LDAP, AD, RADIUS). Calls SetPamSqn... | ⚠️ |
| 0x7B | AMIGetPamOrder | User | safe | pamreorder | Read current PAM module ordering and NSS configuration. |  |
| 0x7C | AMIGetSNMPConf | User | safe | snmp | Read SNMP configuration including community strings. GetDecryptPswd() decrypt... | ⚠️ |
| 0x7D | AMISetSNMPConf | Admin | mutates | snmp | Set SNMP configuration (community, users, engine ID type). |  |
| 0x83 | AMISetPreserveConfStatus | Admin | mutates | prsvconf | Set whether a specific config section persists across fw update. |  |
| 0x84 | AMIGetPreserveConfStatus | User | safe | prsvconf | Read preserve-config status for a specific config section. |  |
| 0x87 | AMIStartTFTPFwUpdate | Admin | destructive | fwupdateprctl | Initiate firmware update from a TFTP server. Triggers full flash write cycle. | ⚠️ |
| 0x88 | AMIGetTftpProgressStatus | Admin | safe | fwupdateprctl | Poll TFTP firmware update progress. |  |
| 0x89 | AMISetFWCfg | Admin | mutates | fwupdateprctl | Set firmware update configuration parameters. |  |
| 0x8A | AMIGetFWCfg | Admin | safe | fwupdateprctl | Read firmware update configuration. |  |
| 0x8B | AMISetFWProtocol | Admin | mutates | fwupdateprctl | Set firmware update protocol (TFTP vs other). |  |
| 0x8C | AMIGetFWProtocol | Admin | safe | fwupdateprctl | Read current firmware update protocol setting. |  |
| 0x8F | AMIDualImageSupport | Admin | mutates | dualimg | Control dual-image boot selection (active/backup image swap). Gate: CONFIG_SP... |  |
| 0x9B | AMISetPwdEncryptionKey | Admin | destructive | pwdenc | Rotate the AES password encryption key. Decrypts all stored IPMI user passwor... | ⚠️ |
| 0x9C | AMISetUBootMemtest | Admin | mutates | ubootmemtest | Enable/disable U-Boot memory test on next boot. |  |
| 0x9D | AMIGetUBootMemtestStatus | Admin | safe | ubootmemtest | Read U-Boot memtest enable state. |  |
| 0x9E | AMIGetRISConf | User | safe | ris | Read Remote Image Share configuration. |  |
| 0x9F | AMISetRISConf | Admin | mutates | ris | Set Remote Image Share configuration. |  |
| 0xA0 | AMIRISStartStop | Admin | mutates | ris | Start or stop Remote Image Share mounting. |  |
| 0xA1 | AMIControlDebugMsg | Admin | mutates | ctldbg | Enable/disable runtime debug logging. Creates or removes /var/enable.debugmsg... | ⚠️ |
| 0xA2 | AMIGetDebugMsgStatus | User | safe | ctldbg | Check if runtime debug logging is enabled (stat() on /var/enable.debugmsg). |  |
| 0xA3 | AMISetExtendedPrivilege | Admin | mutates | extpriv | Set per-user extended privilege bitmask. Maps bits to Linux group membership ... | ⚠️ |
| 0xA4 | AMIGetExtendedPrivilege | Operator | safe | extpriv | Read per-user extended privilege bitmask. From header: IPMICMD_AMIGetExtended... |  |
| 0xA5 | AMISetTimeZone | Admin | mutates | timezone | Set BMC timezone. Falls back to SetDefaultTimezone(). |  |
| 0xA6 | AMIGetTimeZone | User | safe | timezone | Read BMC timezone setting. |  |
| 0xA7 | AMIGetNTPCfg | Operator | safe | ntp | Read NTP server configuration. |  |
| 0xA8 | AMISetNTPCfg | Admin | mutates | ntp | Set NTP server configuration. Validates server hostnames. |  |
| 0xAA | AMIVirtualDeviceSetStatus | Admin | mutates | pwrcons | Set virtual device status (power consumption mode). |  |
| 0xAB | AMIVirtualDeviceGetStatus | User | safe | pwrcons | Read virtual device status. |  |
| 0xAE | AMIGetHostLockFeatureStatus | User | safe | hostlock | Read host-lock feature status (keyboard/video lock state). Gate: CONFIG_SPX_F... |  |
| 0xAF | AMISetHostLockFeatureStatus | Admin | mutates | hostlock | Enable/disable host-lock (lock keyboard/video from remote KVM). Posts PendTas... |  |
| 0xB0 | AMIGetAllActiveSessions | User | safe | sessionmgmt | List all active sessions (IPMI, web, VNC, SOL). Calls racsessinfo_getallrecor... |  |
| 0xB1 | AMIActiveSessionClose | Admin | mutates | sessionmgmt | Force-close an active session by ID. Calls safe_system() with '/etc/child.sh ... | ⚠️ |
| 0xB2 | AMICtrlPLDM | Operator | mutates | pldm | Control PLDM (Platform Level Data Model) daemon. |  |
| 0xB5 | AMIGetVideoRcdConf | User | safe | autovideorcd | Read auto video recording configuration. |  |
| 0xB6 | AMISetVideoRcdConf | Admin | mutates | autovideorcd | Set auto video recording config. Mounts video record path. |  |
| 0xB7 | AMIGetRunTimeSinglePortStatus | User | safe | singleport | Read single-port mode status (all services on one port). |  |
| 0xB8 | AMISetRunTimeSinglePortStatus | Admin | mutates | singleport | Enable/disable single-port mode. |  |
| 0xBA | AMISetAllPreserveConfStatus | Admin | mutates | prsvconf | Set preserve-config status for ALL sections at once. |  |
| 0xBB | AMIGetAllPreserveConfStatus | User | safe | prsvconf | Read preserve-config status for ALL sections. |  |
| 0xBC | AMIGetHostAutoLockStatus | User | safe | autohostlock | Read auto host-lock status. Gate: CONFIG_SPX_FEATURE_HOST_LOCK_AUTO. |  |
| 0xBD | AMISetHostAutoLockStatus | Admin | mutates | autohostlock | Enable/disable auto host-lock. Posts PendTask via g_PDKRemoteKVMHandle. |  |
| 0xBF | AMIPECIWriteRead | Admin | mutates | peci | Raw PECI (Platform Environment Control Interface) write/read to the host CPU.... | ⚠️ |
| 0xC0 | AMIGetRemoteKVMCfg | User | safe | remotekvm | Read remote KVM configuration. |  |
| 0xC1 | AMISetRemoteKVMCfg | Admin | mutates | remotekvm | Set remote KVM configuration. |  |
| 0xC4 | AMIGetADConf | User | safe | ad | Read Active Directory configuration (server, domain, role groups). Calls GetA... | ⚠️ |
| 0xC5 | AMISetADConf | Admin | mutates | ad | Set Active Directory configuration. Calls SetADConfig(). Gate: CONFIG_SPX_FEA... | ⚠️ |
| 0xC6 | AMIGetRadiusConf | User | safe | radius | Read RADIUS authentication configuration. |  |
| 0xC7 | AMISetRadiusConf | Admin | mutates | radius | Set RADIUS authentication configuration. | ⚠️ |
| 0xC8 | AMIGetLDAPConf | User | safe | ldap | Read LDAP configuration. Validates identifiers. |  |
| 0xC9 | AMISetLDAPConf | Admin | mutates | ldap | Set LDAP configuration. Calls SB_BD_Validate() for bind DN validation. | ⚠️ |
| 0xCA | AMIGetVmediaCfg | User | safe | media | Read virtual media configuration. |  |
| 0xCB | AMISetVmediaCfg | Admin | mutates | media | Set virtual media configuration. |  |
| 0xCC | AMIAddExtendSelEntries | Admin | mutates | extendedsel | Add entries to extended SEL (beyond standard 64KB IPMI SEL). Writes to NVRAM-... |  |
| 0xCD | AMIGETExtendSelData | User | safe | extendedsel | Read extended SEL data. |  |
| 0xCE | AMISendToBios | User | mutates | biosremotecontrol | Send a command to the BIOS via the BMC<->BIOS message channel. Gate: CONFIG_S... |  |
| 0xCF | AMIGetBiosCommand | Callback | safe | biosremotecontrol | Read pending BIOS command from the message channel. Intended for the BIOS to ... |  |
| 0xD1 | AMISetBiosResponse | Callback | mutates | biosremotecontrol | Set the BIOS response to a previously sent command. |  |
| 0xD2 | AMIGetBiosResponse | User | safe | biosremotecontrol | Read the BIOS response after sending a command. |  |
| 0xD3 | AMISetBiosFlag | User | mutates | biosremotecontrol | Set a BIOS control flag. Written to /conf/BMC%d/BIOS_FLAG.ini via IniGetUInt. |  |
| 0xD4 | AMIGetBiosFlag | User | safe | biosremotecontrol | Read BIOS control flag from /conf/BMC%d/BIOS_FLAG.ini. |  |
| 0xD5 | AMIPLDMBIOSMsg | User | safe | pldmcmds | Send/receive PLDM BIOS table messages. Handles BIOS table tags, block-level t... |  |
| 0xD7 | AMIMediaRedirectionStartStop | Admin | mutates | media | Start or stop virtual media redirection. |  |
| 0xD8 | AMIGetMediaInfo | User | safe | media | Read virtual media status and mounted image info. |  |
| 0xD9 | AMISetMediaInfo | Admin | mutates | media | Set virtual media info (mount image, configure redirection). |  |
| 0xDA | AMIGetSDCardPartition | User | safe | sd | Read SD card partition configuration. |  |
| 0xDB | AMISetSDCardPartition | Admin | destructive | sd | Set SD card partition layout. |  |
| 0xDC | AMIGetRedirectedMediaInfo | User | safe | media | Read currently redirected media info. |  |
| 0xE3 | AMISetBackupFlag | Admin | mutates | backuprestore | Set backup/restore operation flag. Validates flag value. Gate: CONFIG_SPX_FEA... |  |
| 0xE4 | AMIGetBackupFlag | User | safe | backuprestore | Read current backup/restore operation flag. |  |
| 0xE5 | AMIManageBMCConfig | Admin | destructive | backuprestore | Trigger BMC config backup or restore. Delegates to libBackupConf.so which rea... | ⚠️ |
| 0xEF | AMIGetRAIDInfo | Operator | safe | raidinfo | Read RAID controller, logical drive, physical drive, and enclosure informatio... |  |
| 0xF0 | AMIPartialAddExtendSelEntries | Admin | mutates | extendedsel | Add extended SEL entries in partial (chunked) writes. |  |
| 0xF1 | AMIPartialGetExtendSelEntries | Admin | safe | extendedsel | Read extended SEL entries in partial (chunked) reads. |  |
| 0xF5 | AMISetSerialLogConf | Admin | mutates | uartlogging | Set serial/UART logging configuration. |  |
| 0xF6 | AMIGetSerialLogConf | Operator | safe | uartlogging | Read serial/UART logging configuration. |  |
| 0xF7 | AMISetSOLTriggerEvent | Admin | mutates | uartlogging | Set SOL (Serial Over LAN) trigger event configuration. Stored in /conf/BMC1/S... |  |
| 0xF8 | AMIGetSOLTriggerEvent | Operator | safe | uartlogging | Read SOL trigger event configuration. |  |
| 0xFE | AMIGetSOLArchiveData | Operator | safe | uartlogging | Read archived SOL session data. |  |

## YAFU Commands (NetFn 0x30, multiplexed via AMIYAFUxxx)

**42** firmware-update protocol commands.

| Cmd | Name | Description |
|-----|------|-------------|
| 0x2C | RunInitAgent | 1B RunStatus in, 2B out. Encoded NetFn 0x28 → decodes to Storage 0x0A, NOT the AMI OEM 0x32 used ... |
| 0x01 | GetFlashInfo | Return flash chip metadata (JEDEC ID, size, block layout). LIVE-CONFIRMED on HPE XD670 (AMI MegaR... |
| 0x02 | GetFirmwareInfo | Return BMC firmware version + build metadata + image filename. LIVE-CONFIRMED on HPE XD670: 40-by... |
| 0x03 | GetFMHInfo | Return Firmware Module Header (FMH) inventory — per-module offsets + checksums. HPE XD670: 12B bo... |
| 0x04 | GetStatus | YAFU state machine status (flash-mode / idle / in-progress). HPE XD670 idle: CC 0x25 (YAFU-specif... |
| 0x10 | ActivateFlashMode | Enter flash-programming mode. Precondition for WriteFlash / EraseFlash / EraseCopyFlash. |
| 0x20 | AllocateMemory | Allocate a BMC-side buffer. Returns 17-byte handle blob whose bytes [0x0d..0x10] are the RAW mall... |
| 0x21 | FreeMemory | Release a buffer previously granted by AllocateMemory. |
| 0x22 | ReadFlash | Read from BMC flash. Read-only. |
| 0x23 | WriteFlash | Write payload to BMC flash. Request length = Datalen + 0x11 (17-byte header + data). Gotcha: Data... |
| 0x24 | EraseFlash | Erase flash block(s). |
| 0x25 | ProtectFlash | Set / clear flash write-protect on a block. |
| 0x26 | EraseCopyFlash | Erase-then-copy from BMC memory buffer into flash range. |
| 0x27 | VerifyFlash | Verify flash content against BMC memory buffer. |
| 0x28 | GetECFStatus | Get EraseCopyFlash operation status. |
| 0x29 | GetVerifyStatus | Get VerifyFlash operation status. |
| 0x30 | ReadMemory | Read from a client-allocated BMC heap buffer. BMC-side gate confines address to the AllocateMemor... |
| 0x31 | WriteMemory | Write into client-allocated BMC heap buffer. Same window gate as ReadMemory. Request length = Dat... |
| 0x32 | CopyMemory | BMC-internal memcpy between two windows. |
| 0x33 | CompareMemory | BMC-side memcmp between two windows. Handler not yet decompiled. |
| 0x34 | ClearMemory | Zero a window inside the allocated buffer. |
| 0x40 | GetBootConfig | Get named boot-config variable (u-boot env). |
| 0x41 | SetBootConfig | Set named boot-config variable. Persists across BMC reboot. |
| 0x42 | GetAllBootVars | Enumerate every boot-config variable currently set. |
| 0x50 | DeactivateFlash | Exit flash-programming mode. |
| 0x51 | ResetDevice | Reset the flash device. Also observed on smcipmi as an alias for DeactivateFlash (X10-X13 stack);... |
| 0x52 | SwitchFlashDevice | Switch active flash device (dual-image / dual-flash board). |
| 0x53 | RestoreFlashDevice | Restore previous flash-device selection. |
| 0x54 | DualImageSupport | Query / configure dual-image capability. Also exposed on NetFn 0x30 cmd 0x8f (AMIDualImageSupport... |
| 0x55 | FirmwareSelectFlash | Select which flash the next fw update targets. |
| 0x56 | ActivateFlashDevice | Activate a flash device (post-write commit). |
| 0x66 | AMIRestoreFactoryDefaults | Full BMC config wipe. Zero payload — one authenticated packet. Most minimal privileged command in... |
| 0x87 | AMIStartTFTPFwupdate | Trigger BMC to fetch + flash firmware from pre-configured TFTP server. Artifact: debug printf('Si... |
| 0x91 | AMISetRootPassword | 3-op state machine: Op 0x00 disable / 0x01 enable / 0x02 set cleartext Linux root password. Passw... |
| 0xA9 | AMIYAFUReplaceSignedImageKey | Replace firmware signing pubkey. UNCHECKED memcpy in the handler (see security.html). |
| 0xAC | AMIAddLicenseKey | Install AMI BMC license key. |
| 0xAD | AMIGetLicenseValidity | Query license validity. |
| 0xE5 | AMIManageBMCConfig | Broad config mgmt. Parameter 0x01=Backup, 0x02=Restore. Also exposed on NetFn 0x30 cmd 0xe5 (mega... |
| 0xE6 | AMIRestartWebService | Restart BMC web server. Kills active web sessions. |
| 0xEC | AMISetSSLCert | Install SSL certificate. |
| 0xEE | AMISwitchMUX | MUX switch (USB / KVM multiplexing). |
| 0xEF | AMIGetRAIDConfig | Retrieve RAID configuration. |

## Security-Notable Commands

Commands with `security` annotations — credential exposure, privilege escalation,
debug leaks, or destructive capability:

### 0x2A — AMIAccessRedisDB (Callback, safe)

CRITICAL: unauthed from host KCS. Reads any Redis key including AES-encrypted passwords (EncryptedPassword), PBKDF2 hashes, session tokens, all config. Fleet-shared AES key in firmware enables decryption.

### 0x2C — AMIOemSetRedisDB (Callback, destructive)

CRITICAL: unauthed writes from host. Can modify user credentials, network config, session state, Redfish account properties. Full BMC config takeover via KCS.

### 0x5C — AMIRESTinterface (Admin, mutates)

CVE-2024-54085 neighbourhood. The host-interface Redfish bridge is the entry point for the auth-bypass vuln. GenMD5Hash + StoreDataInRedisDB + DeleteUserSession are internal helpers. Buffer tracking limits concurrent requests ('All Tracks are taken' = max 16?).

### 0x5D — AMIGeneratePassword (Callback, safe)

Priv 0x81 (host/no-auth). Only callable when WDT is present and OS is fully booted. Returns raw random bytes from /dev/urandom — no credential leak, but reveals BMC's PRNG state if called repeatedly.

### 0x76 — AMISetFirewall (Admin, mutates)

Can open/close BMC network ports. An attacker with admin IPMI access can disable the BMC firewall entirely.

### 0x7A — AMISetPamOrder (Admin, mutates)

Reordering PAM can prioritize a weaker auth backend (e.g. move LDAP before local). Combined with SetLDAPConf, an attacker could redirect auth to a rogue LDAP server.

### 0x7C — AMIGetSNMPConf (User, safe)

Returns decrypted SNMP community strings / v3 passwords to any User-level session.

### 0x87 — AMIStartTFTPFwUpdate (Admin, destructive)

Remote firmware reflash. An attacker with admin IPMI can point this at a malicious TFTP server to install trojanized firmware.

### 0x9B — AMISetPwdEncryptionKey (Admin, destructive)

CRITICAL: (1) Debug mode logs the new key to syslog in plaintext ('REQUEST Len=%d Bytes: %s'). (2) Reads /conf/AESKey + /conf/AESIV (fleet-shared). (3) All IPMI passwords are transiently in cleartext during re-encryption. (4) Rejects duplicate key ('Both new and existing keys are same') — timing oracle on the current key.

### 0xA1 — AMIControlDebugMsg (Admin, mutates)

Enables debug output that may leak: AES keys (PwdEnc logs key to syslog), credentials, Redis queries, config paths, LDAP/AD bind passwords, SMTP passwords. An attacker who enables debug can then harvest secrets from syslog.

### 0xA3 — AMISetExtendedPrivilege (Admin, mutates)

Can grant any user full access to all BMC services. Does NOT override command-level interface restrictions (the 0x80 KCS flag is compile-time, not runtime). Persists in NV config and in BackupRestore blobs.

### 0xB1 — AMIActiveSessionClose (Admin, mutates)

Uses safe_system('/etc/child.sh %d') — the session ID is an integer, so no shell injection. But killing sessions is a DoS vector.

### 0xBF — AMIPECIWriteRead (Admin, mutates)

Direct CPU register access via BMC. Can read CPU MSRs, PCI config space, and crash-dump data. A BMC compromise enables host CPU state inspection without OS involvement.

### 0xC4 — AMIGetADConf (User, safe)

Returns AD configuration including server addresses and role group mappings to any User-level session.

### 0xC5 — AMISetADConf (Admin, mutates)

Can redirect AD auth to a rogue server. Stores AD bind credentials. Combined with PAM reorder, enables full auth-backend takeover.

### 0xC7 — AMISetRadiusConf (Admin, mutates)

Can redirect RADIUS auth to attacker-controlled server.

### 0xC9 — AMISetLDAPConf (Admin, mutates)

Can redirect LDAP auth to a rogue server. Combined with PAM reorder → full auth-backend takeover.

### 0xE5 — AMIManageBMCConfig (Admin, destructive)

CRITICAL: Restore = config-level BMC takeover. An attacker who crafts a backup blob (encrypted with the fleet-shared AES key from firmware) can overwrite all BMC credentials, network config, iptables rules, LDAP/AD settings, and the shadow file.

