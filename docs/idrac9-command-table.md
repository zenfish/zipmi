# iDRAC9 — IPMI handler catalog

Auto-generated from the iDRAC9 firmware RE. **DO NOT EDIT BY HAND.**
Regenerate with:

```
python -m zipmi.parsers.idrac9_md --markdown > docs/idrac9-command-table.md
```

Source: `/Volumes/yyy/phd/bmc/idrac9-firmware/IPMI_COMMAND_ENUMERATION.md`  
Entries: **313**

**Note:** the source doc lists cmd names + handlers without their NetFn/cmd
byte codes (those live in the central dispatch table
`G_asOEMIPMIReqeustHandleTable` inside `libipmicmdtableapi.so`, not yet
fully cracked). The catalog below is a name-only reference — useful when a
fuzz crash trace surfaces a handler symbol.

## Chassis

Library: `libchassiscmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Chassis Control | `CmdChassisControl` |  |
| Get Chassis Capabilities | `CmdGetChassisCapabilities` |  |
| Get Chassis Status | `CmdGetChassisStatus` |  |
| Get System Boot Options | `CmdGetSystemBootOptions` |  |
| Get System Restart Cause | `CmdGetSystemRestartCause` |  |
| Set Chassis Capabilities | `CmdSetChassisCapabilities` |  |
| Set Power Cycle Interval | `CmdSetPowerCycleInterval` |  |
| Set System Boot Options | `CmdSetSystemBootOptions` |  |

## App / Global

Library: `libglobalcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Cold Reset | `CmdColdReset` |  |
| Get ACPI Power State | `CmdGetACPIPowerState` |  |
| Get Device GUID | `CmdGetDeviceGUID` |  |
| Get Device ID | `CmdGetDeviceID` |  |
| Get Self Test Results | `CmdGetSelfTestResults` |  |
| Manufacturing Test On | `CmdManufacturingTestOn` |  |
| Set ACPI Power State | `CmdSetACPIPowerState` |  |

## Messaging

Library: `libmessage.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Clear Msg Flags | `CmdClearMsgFlags` |  |
| Enable Msg Channel Recv | `CmdEnableMsgChannelRecv` |  |
| Get BMC Global Enable | `CmdGetBMCGlobalEnable` |  |
| Get Message | `CmdGetMsg` |  |
| Get Msg Flags | `CmdGetMsgFlags` |  |
| Read Event Msg Buffer | `CmdReadEventMsgBuf` |  |
| Set BMC Global Enable | `CmdSetBMCGlobalEnable` |  |

## Session / Payload

Library: `libpayloadcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Activate Payload | `CmdActivatePayload` |  |
| Close Session | `CmdCloseSession` |  |
| Deactivate Payload | `CmdDeactivatePayload` |  |
| Get Auth Code | `CmdGetAuthCode` |  |
| Get Channel Access | `CmdGetChannelAccess` |  |
| Get Channel Auth Capability | `CmdGetChannelAuthCapability` |  |
| Get Channel Cipher Suites | `CmdGetChannelCipherSuites` |  |
| Get Channel Info | `CmdGetChannelInfo` |  |
| Get Channel OEM Payload Info | `CmdGetChannelOEMPayloadInfo` |  |
| Get Channel Payload Support | `CmdGetChannelPayloadSupport` |  |
| Get Channel Payload Version | `CmdGetChannelPayloadVersion` |  |
| Get Payload Activation Status | `CmdGetPayloadActivationStatus` |  |
| Get Payload Instance Info | `CmdGetPayloadInstanceInfo` |  |
| Get Session Info | `CmdGetSessionInfo` |  |
| Get System GUID | `CmdGetSystemGUID` |  |
| Get User Access | `CmdGetUserAccess` |  |
| Get User Name | `CmdGetUserName` |  |
| Get User Payload Access | `CmdGetUserPayloadAccess` |  |
| Set Channel Access | `CmdSetChannelAccess` |  |
| Set Channel Security Keys | `CmdSetChannelSecurityKeys` |  |
| Set User Access | `CmdSetUserAccess` |  |
| Set User Name | `CmdSetUserName` |  |
| Set User Password | `CmdSetUserPassword` |  |
| Set User Payload Access | `CmdSetUserPayloadAccess` |  |
| Suspend/Resume Payload Encryption | `CmdSuspendResumePayloadEncryption` |  |

## SDR Repository

Library: `libsdr.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Clear SDR | `CmdClrSDR` |  |
| Get SDR | `CmdGetSDR` |  |
| Get SDR Repo Info | `CmdGetSDRRepoInfo` |  |
| Get SDR Repo Time | `CmdGetSDRRepoTime` |  |
| Partial Add SDR | `CmdPartAddSDR` |  |
| Reserve SDR Repo | `CmdResvSDRRepo` |  |
| Run Init Agent | `CmdRunInitAgent` |  |
| Set SDR Repo Time | `CmdSetSDRRepoTime` |  |

## SEL

Library: `libselcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Add SEL Entry | `CmdAddSELEntry` |  |
| Clear SEL | `CmdClearSEL` |  |
| Get SEL Entry | `CmdGetSELEntry` |  |
| Get SEL Info | `CmdGetSELInfo` |  |
| Get SEL Time | `CmdGetSELTime` |  |
| Reserve SEL | `CmdReserveSEL` |  |
| Set SEL Time | `CmdSetSELTime` |  |

## Sensor/Event

Library: `libsensorcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get Sensor Event Enable | `CmdGetSensorEventEnable` |  |
| Get Sensor Event Status | `CmdGetSensorEventStatus` |  |
| Get Sensor Hysteresis | `CmdGetSensorHysteresis` |  |
| Get Sensor Reading | `CmdGetSensorReading` |  |
| Get Sensor Reading Factors | `CmdGetSensorReadingFactors` |  |
| Get Sensor Thresholds | `CmdGetSensorThresholds` |  |
| Get Sensor Type | `CmdGetSensorType` |  |
| Rearm Sensor Events | `CmdRearmSensorEvents` |  |
| Set Sensor Event Enable | `CmdSetSensorEventEnable` |  |
| Set Sensor Hysteresis | `CmdSetSensorHysteresis` |  |
| Set Sensor Reading | `CmdSetSensorReading` |  |
| Set Sensor Thresholds | `CmdSetSensorThresholds` |  |

## Sensor Event

Library: `libsensorevent.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get Event Receiver | `CmdGetEventReceiver` |  |
| Platform Event | `CmdPlatformEvent` |  |
| Set Event Receiver | `CmdSetEventReceiver` |  |

## FRU

Library: `libifru.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get FRU Inv Area Info | `CmdGetFRUInvAreaInfo` |  |
| Read FRU Data | `CmdReadFRUData` |  |
| Write FRU Data | `CmdWriteFRUData` |  |

## LAN

Library: `liblancmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get IP Statistics | `CmdGetIPStatistics` |  |
| Get LAN Config Param | `CmdGetLANConfigParam` |  |
| Set LAN Config Param | `CmdSetLANConfigParam` |  |
| Suspend BMC ARPs | `CmdSuspendBMCARPs` |  |

## SOL

Library: `libchnl.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get SOL Configuration | `CmdGetSOLConfiguration` |  |
| Set SOL Configuration | `CmdSetSOLConfiguration` |  |

## Serial/Modem

Library: `libserialcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Callback | `CmdCallback` |  |
| Get PPP/UDP Proxy Tx Data | `CmdGetPPPUDPProxyTxData` |  |
| Get PPP/UDP Receive Data | `CmdGetPPPUDPReceiveData` |  |
| Get Serial/Modem Config Param | `CmdGetSerModemConfigParam` |  |
| Get System Boot Options | `CmdGetSystemBootOptions` |  |
| Get TAP Response Codes | `CmdGetTapResponseCodes` |  |
| Get User Callback Options | `CmdGetUserCallbackOptions` |  |
| Send PPP/UDP Proxy Packet | `CmdSendPPPUDPProxyPacket` |  |
| Set PPP/UDP Proxy Tx Data | `CmdSetPPPUDPProxyTxData` |  |
| Set Serial/Modem Config Param | `CmdSetSerModemConfigParam` |  |
| Set Serial/Modem Mux | `CmdSetSerModemMux` |  |
| Set Serial Routing Mux | `CmdSetSerRoutingMux` |  |
| Set System Boot Options | `CmdSetSystemBootOptions` |  |
| Set User Callback Options | `CmdSetUserCallbackOptions` |  |
| Terminal SYS | `CmdTerminalSYS` |  |
| Terminal SYSDRAC | `CmdTerminalSYSDRAC` |  |

## PEF

Library: `libpefcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| PEFC Alert Immediate | `CmdPEFCAlertImmediate` |  |
| PEFC Arm Postpone Timer | `CmdPEFCArmPostponeTimer` |  |
| PEFC Get Capabilities | `CmdPEFCGetCapabilities` |  |
| PEFC Get Config Params | `CmdPEFCGetConfigurationParameters` |  |
| PEFC Get Last Processed Event ID | `CmdPEFCGetLastProcessedEventID` |  |
| PEFC Set Config Params | `CmdPEFCSetConfigurationParameters` |  |
| PEFC Set Last Processed Event ID | `CmdPEFCSetLastProcessedEventID` |  |
| PETC Acknowledge | `CmdPETCAcknowledge` |  |

## Watchdog

Library: `libiwdg.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get Watchdog Timer | `CmdGetWatchdogTimer` |  |
| Reset Watchdog Timer | `CmdResetWatchdogTimer` |  |
| Set Watchdog Timer | `CmdSetWatchdogTimer` |  |

## Firmware Update

Library: `libosa.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Cancel Firmware Update | `CmdCancelFirmwareUpdate` |  |
| Firmware Update | `CmdFirmwareUpdate` |  |
| Firmware Update Phase 1 | `CmdFirmwareUpdatePhase1` |  |
| Firmware Update Phase 2 | `CmdFirmwareUpdatePhase2` |  |
| Get BMC SA | `CmdGetBMCSA` |  |
| Get Dyn Alloc Memory Size | `CmdGetDynaAllocMemorySize` |  |
| Get FW ID | `CmdGetFWID` |  |
| Get FW Version | `CmdGetFWVersion` |  |
| Get Firmware Update Status | `CmdGetFirmwareUpdateStatus` |  |
| Get Firmware Version | `CmdGetFirmwareVersion` |  |
| Memory Check | `CmdMemoryChk` |  |
| OSA OEM Cmd Handler | `CmdOSAOEMCmdHandler` |  |
| Reset To Default | `CmdResetToDefault` |  |
| Reset To Default OSA | `CmdResetToDefaultOSA` |  |
| Rollback Firmware Version | `CmdRollbackFirmwareVersion` |  |
| Sensor Test | `CmdSensorTest` |  |
| Set BMC SA | `CmdSetBMCSA` |  |
| Set FW Image Status | `CmdSetFWImageStatus` |  |
| Set Sys GUID | `CmdSetSysGUID` |  |

## Firewall

Library: `libfirewall.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get Command Enables | `CmdGetCommandEnables` |  |
| Get Command SubFn Enables | `CmdGetCommandSubFnEnables` |  |
| Get Command SubFn Support | `CmdGetCommandSubFnSupport` |  |
| Get Command Support | `CmdGetCommandSupport` |  |
| Get Configurable Command SubFn | `CmdGetConfigurableCommandSubFn` |  |
| Get Configurable Commands | `CmdGetConfigurableCommands` |  |
| Get NetFn Support | `CmdGetNetFnSupport` |  |
| Get OEM NetFn IANA Support | `CmdGetOEMNetFnIANASupport` |  |
| Set Command Enables | `CmdSetCommandEnables` |  |
| Set Command SubFn Enables | `CmdSetCommandSubFnEnables` |  |

## DCMI

Library: `libdcmi.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get DCMI Capability Info | `CmdDcmiGetDcmiCapabilityInfo` |  |
| Get DCMI Sensor Info | `CmdDcmiGetDcmiSensorInfo` |  |
| Get Asset Tag | `CmdDcmiGetAssetTag` |  |
| Set Asset Tag | `CmdDcmiSetAssetTag` |  |
| Get Management Controller ID | `CmdDcmiGetManagementControllerIdStr` |  |
| Set Management Controller ID | `CmdDcmiSetManagementControllerIdStr` |  |
| Get DCMI Config Param | `CmdDcmiGetDMCIConfigParam` |  |
| Set DCMI Config Param | `CmdDcmiSetDMCIConfigParam` |  |
| Get Power Reading | `CmdDcmiGetPowerReading` |  |
| Get Power Limit | `CmdDcmiGetPowerLimit` |  |
| Set Power Limit | `CmdDcmiSetPowerLimit` |  |
| Activate/Deactivate Power Limit | `CmdDcmiActDeactPowerLimit` |  |
| Get Temperature Readings | `CmdDcmiGetTemperatureReadings` |  |
| Get Thermal Limit | `CmdDcmiGetThermalLimit` |  |
| Set Thermal Limit | `CmdDcmiSetThermalLimit` |  |

## OEM Chassis / Identity

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| OEM Chassis Identify | `CmdOEMChassisIdentify` | LED control |
| Get Chassis Capabilities | `CmdOEMGetChassisCapabilities` |  |
| Set Chassis Capabilities | `CmdOEMSetChassisCapabilities` |  |
| Get Self Test Results | `CmdOEMGetSelfTestResults` |  |
| Get Command Support | `CmdOEMGetCommandSupport` |  |

## OEM I2C/Hardware Direct Access

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| I2C Write/Read | `CmdI2CWriteRead_OEM` | DIRECT I2C BUS ACCESS — can reach VRMs, SPDs, CPLD, PMBus devices |
| Manufacturing Test On | `CmdOEMManufacturingTestOn` | Enables factory test mode |
| Dell Factory | `CmdOEMDellFactory` | Factory provisioning — creates hw inventory, resets |

## OEM User / Auth

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Set User Password | `CmdOEMSetUserPassword` | OEM password change path |
| Remote Enablement | `CmdOEMRemoteEnablement` | Auto-discovery / zero-touch provisioning |
| Enable Msg Channel Recv | `CmdOEMEnableMsgChannelRecv` |  |
| Get Channel Info | `CmdOEMGetChannelInfo` |  |

## OEM MASER (Non-Volatile Storage)

Library: `libmaser.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get MASER Access State | `CmdOEMGetMASERAccessState` |  |
| Set MASER Access State | `CmdOEMSetMASERAccessState` |  |
| Get MASER Info | `CmdOEMGetMASERInfo` |  |
| Get MASER Type | `CmdOEMGetMASERType` |  |
| MASER LCL Access | `CmdOEMMASERLCLAccess` | Lifecycle controller access |
| MASER Partition Access | `CmdOEMMASERPartitionAccess` | eMMC partition control |
| MASER PM | `CmdOEMMASER_PM` |  |
| POST MASER Access | `CmdOEMPOSTMASERAccess` |  |
| Recreate MASER | `CmdOEMRecreateMASER` | Wipe/recreate storage |
| Lock MASER | `CmdOEMLockMASER` |  |
| Unlock MASER | `CmdOEMUnLockMASER` |  |
| MASER Lock WD Reset | `CmdOEMMASERLockWDreset` |  |
| Backup/Restore | `CmdOEMBackupRestore` |  |

## OEM MASER

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| LCL Get USC Version | `CmdOEMLCLGetUSCVer` |  |
| LCL Get Status | `CmdOEMLCLMASERGetLCLStatus` |  |
| LCL HW Inventory | `CmdOEMLCLMASERHWInventory` |  |
| LCL Factory HW Inventory Get | `CmdOEMLCLMASERFactoryHWInventoryGet` |  |
| LCL History | `CmdOEMLCLMASERHistory` |  |
| LCL Log Entry | `CmdOEMLCLMASERLogEntry` |  |
| LCL Query Current Records | `CmdOEMLCLMASERQueryCurrentRecords` |  |
| LCL Query Event Record | `CmdOEMLCLMASERQueryEventRecord` |  |
| LCL Query Record History | `CmdOEMLCLMASERQueryRecordHistory` |  |
| LCL Query Dependency | `CmdOEMLCLMASERQueryDependency` |  |
| LCL Update Entire Inventory | `CmdOEMLCLMASERUpdateEntireInventory` |  |
| LCL Update Inventory Records | `CmdOEMLCLMASERUpdateInventoryRecords` |  |
| LCL Update XML Records | `CmdOEMLCLMASERUpdateXMLRecords` |  |
| LCL Copy MUT Data | `CmdOEMLCLCopyMUTData` |  |
| LCL Wipe | `CmdOEMLCLWipe` | Wipes Lifecycle Controller |

## OEM vFlash (Virtual SD Card)

Library: `libmaser.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| vFlash Card Control | `CmdOEMVflashCardControl` | Enable/Disable/Initialize SD |
| vFlash Get Card Info | `CmdOEMVflashGetCardInfo` |  |
| vFlash Create Empty Partition | `CmdOEMVflashCreateEmptyPartition` | Supports FAT16/FAT32/EXT2/EXT3/RAW |
| vFlash Delete Partition | `CmdOEMVflashDeletePartition` |  |
| vFlash Format Partition | `CmdOEMVflashFormatPartition` |  |
| vFlash Attach Partitions | `CmdOEMVflashAttachPartitions` |  |
| vFlash Detach Partitions | `CmdOEMVflashDetachPartitions` |  |
| vFlash Change Access Type | `CmdOEMVflashChangePartitionAccessType` |  |
| vFlash Get Partition Info | `CmdOEMLVflashGetPartitionInfo` |  |
| vFlash Get Partition Index Info | `CmdOEMLVflashGetPartitionIndexInfo` |  |
| vFlash Get Boot Partition | `CmdOEMVflashGetBootPartition` |  |
| vFlash Set Boot Partition | `CmdOEMVflashSetBootPartition` | Controls which partition boots |
| vFlash Get Job Status | `CmdOEMVflashGetJobStatus` |  |
| vFlash Get Partition Status | `CmdOEMVflashGetPartitionStatus` |  |

## OEM Backup/Restore

Library: `libmaser.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Begin SECUPD | `CmdOEMBeginSECUPD` |  |
| End SECUPD | `CmdOEMEndSECUPD` |  |
| Process SECUPD | `CmdOEMProcessSECUPD` |  |
| Start SECUPD PM | `CmdOEMStartSECUPD_PM` |  |
| BnR Populate Backup Cmd | `CmdOEMBnRPopulateBackupCmd` |  |
| BnR Send Backup Cmd | `CmdOEMBnRSendBackupCmd` |  |
| BnR Populate Restore Cmd | `CmdOEMBnRPopulateRestoreCmd` |  |
| BnR Send Restore Cmd | `CmdOEMBnRSendRestoreCmd` |  |
| BnR Query Job ID | `CmdOEMBnRQueryJobID` |  |
| BnR Query Job Status | `CmdOEMBnRQueryJobStatus` |  |
| BnR Set Job Status | `CmdOEMBnRSetJobStatusCmd` |  |
| BnR Cancel | `CmdOEMBnRCancelCmd` |  |
| BnR Get Auto Feature Status | `CmdOEMBnRGetAutoFeatureStatus` |  |
| BnR Get Auto Restore VFL Cap | `CmdOEMBnRGetAutoRestoreVflCap` |  |
| Secure Update Partition | `CmdOEMSecureUpdatePartition` |  |
| Compliant Update Validate | `CmdOEMCmplntUpdValidate` |  |
| Compliant Update Status | `CmdOEMCmplntUpdValidateStatus` |  |
| Compliant Update | `CmdOEMCmplntUpdUpdate` |  |
| Compliant Update Query Status | `CmdOEMCmplntUpdQueryStatus` |  |

## OEM Licensing / Provisioning

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get Auto Discovery | `CmdOEMGetAutoDiscovery` |  |
| Set Auto Discovery | `CmdOEMSetAutoDiscovery` |  |
| Get Provisioning Server Info | `CmdOEMGetProvisioningServerInfo` |  |
| Set Provisioning Server Info | `CmdOEMSetProvisioningServerInfo` |  |
| Get Discovery Restart Options | `CmdOEMGetDiscoveryRestartOptions` |  |
| Set Discovery Restart Options | `CmdOEMSetDiscoveryRestartOptions` |  |
| Get RE Capabilities Bitmap | `CmdOEMGetRECapabilitiesBitmap` |  |
| Set RE Capabilities Bitmap | `CmdOEMSetRECapabilitiesBitmap` |  |
| RE Capability For DUP | `CmdOEMReCapabilityForDup` |  |
| Get PM Status | `CmdOEMGetPMStatus` |  |
| Get PM Default Brand | `CmdOEMGetPMDefaultBrand` |  |
| Get PM Rebrand | `CmdOEMGetPMRebrand` |  |
| Set PM Install | `CmdOEMSetPMInstall` |  |
| Get PM Update Flag | `CmdOEMGetPMUpdateFlag` |  |
| Clear PM Update Flag | `CmdOEMClrPMUpdateFlag` |  |
| Get Pkg Cache Update Flag | `CmdOEMGetPkgCacheUpdateFlag` |  |
| Get Certificate Status | `CmdOEMGetCertificateStatus` |  |
| Remove Certificate | `CmdOEMRemoveCertificate` |  |
| Sign Certificate | `CmdOEMSignCertificate` |  |
| Secure Default Password | `CmdOEMSecureDefaultPassword` |  |
| Bootstrap Credentials Control | `CmdCmdBootstrapCredentialsControl` |  |

## OEM CCR (Config Change Recording)

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get CCR Feature State | `CmdOEMGetCCRFeatureState` |  |
| Set CCR Feature State | `CmdOEMSetCCRFeatureState` |  |
| Get CCR Config State | `CmdOEMGetCCRConfigurationState` |  |
| Set CCR Config State | `CmdOEMSetCCRConfigurationState` |  |
| Get CCR Auto Sync State | `CmdOEMGetCCRAutoSyncState` |  |
| Set CCR Auto Sync State | `CmdOEMSetCCRAutoSyncState` |  |
| Get CCR Update FW Mode | `CmdOEMGetCCRUpdateFWMode` |  |
| Set CCR Update FW Mode | `CmdOEMSetCCRUpdateFWMode` |  |

## OEM SupportAssist

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| SupportAssist | `CmdOEMSupportAssist` |  |
| SA Collect Data | `CmdOEMSACollectData` |  |
| SA Collect Data Cancel | `CmdOEMSACollectDataCancel` |  |
| SA Get Collect Data Status | `CmdOEMSAGetCollectDataStatus` |  |
| SA Get Status | `CmdOEMSAGetStatus` |  |
| SA Expose iSM Installer | `CmdOEMSAExposeiSMInstaller` |  |
| SA Hide iSM Installer | `CmdOEMSAHideiSMInstaller` |  |
| SA Hide Collect Data Result | `CmdOEMSAHideCollectDataResult` |  |
| SA Native OS Collection | `CmdOEMSANativeOSCollection` |  |
| SA Native OS Collection Started | `CmdOEMSANativeOSCollectionStarted` |  |
| SA Native OS Collection Ended | `CmdOEMSANativeOSCollectionEnded` |  |
| SA Job In Progress Signal | `CmdOEMSAJobInProgressPendingSignal` |  |

## OEM Tool Set (TS)

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Tool Set | `CmdOEMToolSet` |  |
| TS Begin Marker | `CmdOEMTSBeginMarker` |  |
| TS End Marker | `CmdOEMTSEndMarker` |  |
| TS Update Marker | `CmdOEMTSUpdateMarker` |  |
| TS Collect Data | `CmdOEMTSCollectData` |  |
| TS Get Data Info | `CmdOEMTSGetDataInfo` |  |
| TS Get Status | `CmdOEMTSGetStatus` |  |
| TS Expose Execs | `CmdOEMTSExposeExecs` |  |
| TS Hide Execs | `CmdOEMTSHideExecs` |  |
| TS System Erase | `CmdOEMTSSystemErase` | System erase via IPMI |

## OEM BIOS/UEFI

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Get UEFI Flag | `CmdOEMGetUEFIFlag` |  |
| Set UEFI Flag | `CmdOEMSetUEFIFlag` |  |
| Get BIOS Password Info | `CmdOEMGetBIOSPasswordInfo` |  |
| POST Set BIOS Password | `CmdOEMPOSTSetBIOSPassword` |  |
| POST Set BIOS SHA Password | `CmdOEMPOSTSetBIOSSHAPassword` |  |
| POST Get Boot Vol Label | `CmdOEMPOSTGetBootVolLabel` |  |
| POST Log LCL Event | `CmdOEMPOSTLogLCLEvent` |  |
| POST MASER Attach Partition | `CmdOEMPOSTMASERAttachPartition` |  |
| POST MASER Detach Partition | `CmdOEMPOSTMASERDetachPartition` |  |
| POST MASER Get Prov Options | `CmdOEMPOSTMASERGetProvOptions` |  |
| POST MASER Set System Req | `CmdOEMPOSTMASERSetSystemReq` |  |
| UEFI Log Service | `CmdOEMUEFILOGService` |  |

## OEM Misc

Library: `libmisccmd.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| OEM Misc Cmd | `CmdOEMMiscCmd` | Dispatch for misc OEM sub-commands |
| OEM Power Avg Range | `CmdOEMPwrAvgRange` | Power consumption data |
| OEM Power Headroom | `CmdOEMPwrHeadroom` | Instantaneous + peak headroom (watts) |
| Get NIC Selection Failover | `CmdGetNICSelectionFailover` |  |
| Set NIC Selection Failover | `CmdSetNICSelectionFailover` |  |

## OEM SEL/FRU (via `libmodular.so`)

Library: `libmodular.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| OEM Get SEL Entry | `CmdOEMGetSELEntry` |  |
| OEM Read FRU Data | `CmdOEMReadFRUData` |  |
| OEM Set SEL Time | `CmdOEMSetSELTime` |  |

## OEM Extended Configure

Library: `liboemcmds.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Reserve Extended Configure | `CmdResvExtendedConfigure` |  |
| Get Extended Configure | `CmdGetExtendedConfigure` |  |
| Set Extended Configure | `CmdSetExtendedConfigure` | Modifies BMC configuration |
| Set Power Restore Policy | `CmdSetPowerRestorePolicy` |  |
| Set Sensor Thresholds Override | `CmdSetSensorThresholdsOverride` | Can override safety thresholds |
| POST Event | `CmdPOSTEvent` |  |
| Get Soft Lock Status | `CmdGetSoftLockStatus` |  |

## OEM Network ISO

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| Disconnect Network ISO | `CmdOEMDisconnectNetworkISO` |  |
| Skip ISO Boot | `CmdOEMSkipISOBoot` |  |

## OEM Utility

Library: `libmaser.so`

| Cmd Name | Handler | Notes |
|---------|---------|-------|
| OEM Utility | `CmdOEMUtility` | Sub-command dispatch: factory reset, secure default password, offline DB sync |
| Single IPMI | `CmdOEMSingleIPMI` |  |
| Forwarded Cmds | `CmdForwardedCmds` |  |
