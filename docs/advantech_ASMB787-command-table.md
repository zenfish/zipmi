# Advantech ASMB-787 — IPMI/OEM handler catalog

Static reverse-engineering of the ASMB-787 BMC firmware (**AMI MegaRAC SP-X 4.0 / ASPEED AST2600**, Linux 5.4.11-ami, ARM32 EABI5). Every `g_*_CmdHndlr` dispatch table was parsed out of the OEM `.so` set with pyelftools; NetFn bindings and the privilege model were confirmed in Ghidra (`libipmimsghndlr.so`: `GetMsgHndlrMap`, `GetCmdHndlr`, `SetSessionPrivLevel`).

**Tables: 50 · Commands: 369** across ~30 libraries. Unlike the iDRAC9 catalog (name-only), every entry here carries its real Cmd byte, privilege floor, and supported-interface mask.

## Dispatch struct (`CmdHndlr_T`, 16 bytes)

```
+0  u8  Cmd
+1  u8  ReqLen (min request length)
+4  ptr Handler (R_ARM_ABS32 → named symbol)
+8  u8  Priv  (privilege floor)
+10 u16 0xAAAA (poison / sentinel)
+12 u16 SuppIface (channel bitmask; 0xFFFF = all)
```

`GetCmdHndlr` matches on the **Cmd byte only** (no priv logic); the privilege floor at +8 is enforced by the IPMI core dispatcher against the session-established level.

## Privilege model

| Priv byte | Meaning |
|-----------|---------|
| `0x00` | **No minimum** — callable at any level, including the host-side KCS system interface where there is *no session and no auth*. |
| `0x01`–`0x05` | IPMI floor: Callback / User / Operator / Administrator / OEM. Enforced as `session_priv >= floor` (`SetSessionPrivLevel` uses the 1–5 scale; OEM=5 gated behind a feature flag). |
| `0xff` (`self*`) | Outside the 1–5 scale, so it can never satisfy a numeric `>=` floor — it is a **sentinel: the handler enforces its own privilege** (AMI convention). Used by the password handlers. |

> **KCS caveat:** a `0x00`-floor command reachable on the system interface is issuable by any local OS-admin with zero BMC credentials. This is exactly the ASUS ASMB9 `ipmitool raw 0x32 0x66` factory-reset note.

## NetFn → table map

**Confirmed** — read directly out of the static PDK registration array (an over-read of `g_Oem_NetFn30` walked into `(NetFn, table_ptr)` pairs):

| NetFn | Table |
|-------|-------|
| 0x02 | `g_Bridge` |
| 0x06 | `g_App_CmdHndlr` |
| 0x0a | `g_Storage_CmdHndlr` |
| 0x2c | `g_HPM_CmdHndlr` |
| 0x30 | `g_Oem_NetFn30_CmdHndlr` |
| 0x32 | `g_AMI_CmdHndlr` |
| 0x3a | `g_Oem_ASMB260_CmdHndlr` |

The same array also names tables not extracted here: 0x3e `g_opma2`, 0x30 `g_pnm`.

**By convention** (standard IPMI NetFn + definitive symbol name; not in the visible array slice):

| NetFn | Table |
|-------|-------|
| 0x00 | `g_Chassis_CmdHndlr` |
| 0x04 | `g_SensorEvent_CmdHndlr` |
| 0x0c | `g_Config_CmdHndlr` |

`g_DCMI_CmdHndlr` / `g_HPM_CmdHndlr` are NetFn 0x2C group extensions (DCMI group 0xDC, PICMG/HPM group 0x00).

The ~30 AMI OEM feature libraries below register their NetFn dynamically at plugin-load via the PDK path (`GetMsgHndlrMap` reads a runtime-populated map), so their NetFn is not in the static array.

---

## Standard NetFns

### `g_Chassis_CmdHndlr` — libipmimsghndlr.so.13.22.0  · NetFn 0x00  · 13 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x00 | — none | all | 2 | `GetChassisCaps` |  |
| 0x01 | — none | all | 2 | `GetChassisStatus` |  |
| 0x02 | Callback | all | 3 | `ChassisControl` |  |
| 0x03 | — none | all | 3 | `UnImplementedFunc` |  |
| 0x04 | self* | all | 3 | `GetChassisIdentify` |  |
| 0x05 | self* | all | 4 | `SetChassisCaps` |  |
| 0x06 | Callback | all | 3 | `SetPowerRestorePolicy` | _Restore-related._ |
| 0x07 | — none | all | 2 | `GetSysRestartCause` |  |
| 0x08 | self* | all | 3 | `SetSysBOOTOptions` |  |
| 0x09 | Operator | all | 3 | `GetSysBOOTOptions` |  |
| 0x0f | — none | all | 2 | `GetPOHCounter` |  |
| 0x0a | Callback | all | 4 | `SetFPButtonEnables` |  |
| 0x0b | Callback | all | 4 | `SetPowerCycleInterval` |  |

### `g_SensorEvent_CmdHndlr` — libipmimsghndlr.so.13.22.0  · NetFn 0x04  · 27 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x00 | User | all | 4 | `SetEventReceiver` |  |
| 0x01 | — none | all | 2 | `GetEventReceiver` |  |
| 0x02 | self* | all | 3 | `PlatformEventMessage` |  |
| 0x10 | — none | all | 2 | `GetPEFCapabilities` |  |
| 0x11 | Callback | all | 4 | `ArmPEFPostponeTimer` |  |
| 0x12 | self* | all | 4 | `SetPEFConfigParams` |  |
| 0x13 | Operator | all | 3 | `GetPEFConfigParams` |  |
| 0x14 | Operator | all | 4 | `SetLastProcessedEventId` |  |
| 0x15 | — none | all | 4 | `GetLastProcessedEventId` |  |
| 0x16 | self* | all | 4 | `AlertImmediate` | _Media-related._ |
| 0x17 | 0x0c? | all | 0 | `PETAcknowledge` |  |
| 0x20 | self* | all | 129 | `GetDevSDRInfo` |  |
| 0x21 | 0x06? | all | 129 | `GetDevSDR` |  |
| 0x22 | — none | all | 129 | `ReserveDevSDRRepository` |  |
| 0x23 | User | all | 2 | `GetSensorReadingFactors` |  |
| 0x24 | Admin | all | 3 | `SetSensorHysterisis` |  |
| 0x25 | User | all | 2 | `GetSensorHysterisis` |  |
| 0x26 | 0x08? | all | 3 | `SetSensorThresholds` |  |
| 0x27 | Callback | all | 2 | `GetSensorThresholds` |  |
| 0x28 | self* | all | 3 | `SetSensorEventEnable` |  |
| 0x29 | Callback | all | 2 | `GetSensorEventEnable` |  |
| 0x2a | self* | all | 3 | `ReArmSensor` |  |
| 0x2b | Callback | all | 2 | `GetSensorEventStatus` |  |
| 0x2d | Callback | all | 2 | `GetSensorReading` |  |
| 0x2e | Operator | all | 3 | `SetSensorType` |  |
| 0x2f | Callback | all | 2 | `GetSensorType` |  |
| 0x30 | self* | all | 2 | `SetSensorReading` |  |

### `g_App_CmdHndlr` — libipmimsghndlr.so.13.22.0  · NetFn 0x06  · 63 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x01 | — none | all | 2 | `GetDevID` |  |
| 0x01 | — none | all | 129 | `UnImplementedFunc` |  |
| 0x02 | — none | all | 4 | `ColdReset` | _Reset-related._ |
| 0x03 | — none | all | 4 | `WarmReset` | _Reset-related._ |
| 0x04 | — none | all | 2 | `GetSelfTestResults` |  |
| 0x05 | self* | all | 4 | `MfgTestOn` |  |
| 0x06 | User | all | 4 | `SetACPIPwrState` |  |
| 0x07 | — none | all | 2 | `GetACPIPwrState` |  |
| 0x08 | — none | all | 2 | `GetDevGUID` |  |
| 0x09 | Callback | all | 2 | `GetNetFnSup` |  |
| 0x0a | self* | all | 2 | `GetCmdSup` |  |
| 0x0b | self* | all | 2 | `GetSubFnSup` |  |
| 0x0c | self* | all | 2 | `GetConfigCmds` |  |
| 0x0d | self* | all | 2 | `GetConfigSubFns` |  |
| 0x60 | self* | all | 2 | `SetCmdEnables` |  |
| 0x61 | self* | all | 2 | `GetCmdEnables` |  |
| 0x62 | 0x08? | all | 2 | `SetSubFnEnables` |  |
| 0x63 | Admin | all | 2 | `GetSubFnEnables` |  |
| 0x64 | Operator | all | 2 | `GetOEMNetFnIANASupport` |  |
| 0x22 | — none | all | 3 | `ResetWDT` | _Reset-related._ |
| 0x24 | 0x06? | all | 3 | `SetWDT` |  |
| 0x25 | — none | all | 2 | `GetWDT` |  |
| 0x2e | Callback | all | 129 | `SetBMCGlobalEnables` |  |
| 0x2f | — none | all | 2 | `GetBMCGlobalEnables` |  |
| 0x30 | Callback | all | 129 | `ClrMsgFlags` |  |
| 0x31 | — none | all | 129 | `GetMsgFlags` |  |
| 0x32 | User | all | 129 | `EnblMsgChannelRcv` |  |
| 0x33 | — none | all | 129 | `GetMessage` |  |
| 0x34 | self* | all | 2 | `SendMessage` |  |
| 0x35 | — none | all | 129 | `ReadEvtMsgBuffer` |  |
| 0x36 | — none | all | 2 | `GetBTIfcCap` |  |
| 0x37 | — none | all | 0 | `GetSystemGUID` |  |
| 0x38 | User | all | 0 | `GetChAuthCap` |  |
| 0x39 | 0x11? | all | 0 | `GetSessionChallenge` | _Session-related._ |
| 0x3a | 0x16? | all | 0 | `ActivateSession` | _Session-related._ |
| 0x3b | Callback | all | 2 | `SetSessionPrivLevel` | _Priv-related._ |
| 0x3c | self* | all | 1 | `CloseSession` | _Session-related._ |
| 0x3d | self* | all | 2 | `GetSessionInfo` | _Session-related._ |
| 0x3f | 0x13? | all | 3 | `GetAuthCode` |  |
| 0x40 | Operator | all | 4 | `SetChAccess` |  |
| 0x41 | User | all | 2 | `GetChAccess` |  |
| 0x42 | Callback | all | 2 | `GetChInfo` |  |
| 0x43 | self* | all | 4 | `SetUserAccess` |  |
| 0x44 | User | all | 3 | `GetUserAccess` |  |
| 0x45 | 0x11? | all | 4 | `SetUserName` |  |
| 0x46 | Callback | all | 3 | `GetUserName` |  |
| 0x47 | self* | all | 4 | `SetUserPassword` | _Password-related._ |
| 0x52 | self* | all | 3 | `MasterWriteRead` |  |
| 0x58 | self* | all | 4 | `SetSystemInfoParam` |  |
| 0x59 | Admin | all | 2 | `GetSystemInfoParam` |  |
| 0x48 | 0x06? | all | 1 | `ActivatePayload` |  |
| 0x49 | 0x06? | all | 1 | `DeactivatePayload` |  |
| 0x4a | Callback | all | 2 | `GetPayldActStatus` |  |
| 0x4b | User | all | 2 | `GetPayldInstInfo` |  |
| 0x4c | 0x06? | all | 4 | `SetUsrPayloadAccess` |  |
| 0x4d | User | all | 3 | `GetUsrPayloadAccess` |  |
| 0x4e | Callback | all | 2 | `GetChPayloadSupport` |  |
| 0x4f | User | all | 2 | `GetChPayloadVersion` |  |
| 0x50 | 0x07? | all | 2 | `GetChOemPayloadInfo` |  |
| 0x54 | Operator | 0x0001 | 0 | `GetChCipherSuites` |  |
| 0x55 | Operator | all | 2 | `SusResPayldEncrypt` |  |
| 0x56 | self* | all | 4 | `SetChSecurityKeys` | _Key-related._ |
| 0x57 | Callback | all | 2 | `GetSysIfcCaps` |  |

### `g_Storage_CmdHndlr` — libipmimsghndlr.so.13.22.0  · NetFn 0x0a  · 30 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x10 | Callback | all | 2 | `GetFRUAreaInfo` |  |
| 0x11 | Admin | all | 2 | `ReadFRUData` |  |
| 0x12 | self* | all | 3 | `WriteFRUData` |  |
| 0x20 | — none | all | 2 | `GetSDRRepositoryInfo` |  |
| 0x21 | — none | all | 2 | `GetSDRRepositoryAllocInfo` |  |
| 0x22 | — none | all | 2 | `ReserveSDRRepository` |  |
| 0x23 | 0x06? | all | 2 | `GetSDR` |  |
| 0x24 | self* | all | 3 | `AddSDR` |  |
| 0x25 | self* | all | 3 | `PartialAddSDR` |  |
| 0x26 | Admin | all | 3 | `DeleteSDR` |  |
| 0x27 | 0x06? | all | 3 | `ClearSDRRepository` |  |
| 0x28 | — none | all | 2 | `GetSDRRepositoryTime` |  |
| 0x29 | Admin | all | 3 | `UnImplementedFunc` |  |
| 0x2a | — none | all | 3 | `UnImplementedFunc` |  |
| 0x2b | — none | all | 3 | `UnImplementedFunc` |  |
| 0x2c | Callback | all | 3 | `RunInitializationAgent` |  |
| 0x40 | — none | all | 2 | `GetSELInfo` |  |
| 0x41 | — none | all | 2 | `GetSELAllocationInfo` |  |
| 0x42 | — none | all | 2 | `ReserveSEL` |  |
| 0x43 | 0x06? | all | 2 | `GetSELEntry` |  |
| 0x44 | 0x10? | all | 3 | `AddSELEntry` |  |
| 0x45 | self* | all | 3 | `PartialAddSELEntry` |  |
| 0x46 | Admin | all | 3 | `DeleteSELEntry` |  |
| 0x47 | 0x06? | all | 3 | `ClearSEL` |  |
| 0x48 | — none | all | 2 | `GetSELTime` |  |
| 0x49 | Admin | all | 3 | `SetSELTime` |  |
| 0x5a | self* | all | 2 | `UnImplementedFunc` |  |
| 0x5b | self* | all | 4 | `UnImplementedFunc` |  |
| 0x5c | — none | all | 2 | `GetSELTimeUTC_Offset` |  |
| 0x5d | User | all | 3 | `SetSELTimeUTC_Offset` |  |

### `g_Config_CmdHndlr` — libipmimsghndlr.so.13.22.0  · NetFn 0x0c  · 14 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x01 | self* | 0x0001 | 4 | `SetLanConfigParam` |  |
| 0x02 | Admin | 0x0001 | 3 | `GetLanConfigParam` |  |
| 0x03 | User | 0x0001 | 4 | `SuspendBMCArps` |  |
| 0x04 | self* | 0x0001 | 4 | `UnImplementedFunc` |  |
| 0x10 | self* | 0x0004 | 4 | `SetSerialModemConfig` |  |
| 0x11 | Admin | 0x0004 | 3 | `GetSerialModemConfig` |  |
| 0x12 | User | 0x0004 | 3 | `SetSerialModemMUX` |  |
| 0x18 | User | 0x0004 | 3 | `UnImplementedFunc` |  |
| 0x19 | User | 0x0004 | 4 | `CallBack` |  |
| 0x1a | 0x07? | 0x0004 | 4 | `SetUserCallBackOptions` |  |
| 0x1b | User | 0x0004 | 2 | `GetUserCallBackOptions` |  |
| 0x13 | Callback | 0x0004 | 2 | `GetTAPResponseCodes` |  |
| 0x22 | Admin | 0x0002 | 2 | `GetSOLConfig` |  |
| 0x21 | self* | 0x0002 | 4 | `SetSOLConfig` |  |

### `g_DCMI_CmdHndlr` — libipmidcmi.so.13.0.0  · 15 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x01 | User | none | 2 | `GetDCMICapabilityInfo` |  |
| 0x02 | Admin | none | 2 | `GetPowerReading` |  |
| 0x03 | Operator | none | 2 | `GetPowerLimit` |  |
| 0x04 | 0x0f? | none | 3 | `SetPowerLimit` |  |
| 0x05 | Admin | none | 3 | `ActivatePowerLimit` |  |
| 0x06 | Operator | none | 2 | `GetAssetTag` |  |
| 0x07 | OEM | none | 3 | `GetDCMISensorInfo` |  |
| 0x08 | self* | none | 3 | `SetAssetTag` |  |
| 0x09 | Operator | none | 2 | `GetManagementControllerIdString` |  |
| 0x0a | self* | none | 4 | `SetManagementControllerIdString` |  |
| 0x0b | 0x07? | none | 3 | `SetThermalLimit` |  |
| 0x0c | Operator | none | 2 | `GetThermalLimit` |  |
| 0x10 | OEM | none | 2 | `GetTemperatureReading` |  |
| 0x12 | self* | none | 4 | `SetDCMIConfigParameters` |  |
| 0x13 | Operator | none | 2 | `GetDCMIConfigParameters` |  |

### `g_HPM_CmdHndlr` — libipmihpm.so.13.6.0  · NetFn 0x2c  · 11 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x2e | Callback | all | 2 | `GetTargetUpgradeCapablities` |  |
| 0x2f | Operator | all | 2 | `GetComponentProperties` |  |
| 0x31 | Operator | all | 2 | `InitiateUpgradeAction` |  |
| 0x36 | Callback | all | 2 | `QuerySelfTestResults` |  |
| 0x30 | Callback | all | 2 | `AbortFirmwareUpgrade` | _Firmware-related._ |
| 0x32 | self* | all | 2 | `UploadFirmwareBlock` | _Firmware-related._ |
| 0x33 | 0x06? | all | 2 | `FinishFirmwareUpload` | _Firmware-related._ |
| 0x34 | Callback | all | 2 | `GetUpgradeStatus` |  |
| 0x35 | Callback | all | 2 | `ActivateFirmware` | _Firmware-related._ |
| 0x37 | Callback | all | 2 | `QueryRollbackStatus` |  |
| 0x38 | Callback | all | 2 | `InitiateManualRollback` |  |

### `g_HighPayload_CmdHndlr` — libipmihpm.so.13.6.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x82 | self* | all | 2 | `IncreasePayloadSize` |  |

---

## AMI OEM — NetFn 0x32 (`g_AMI_CmdHndlr`)

The AMI MegaRAC OEM command set. **This is the ASUS-style backdoor surface.**

### `g_AMI_CmdHndlr` — libipmimsghndlr.so.13.22.0  · NetFn 0x32  · 85 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x52 | Callback | 0x0008 | 4 | `AMIYAFUSwitchFlashDevice` |  |
| 0x56 | Callback | 0x0008 | 4 | `AMIYAFUActivateFlashDevice` |  |
| 0x53 | Callback | 0x0008 | 4 | `AMIYAFURestoreFlashDevice` | _Restore-related._ |
| 0x01 | 0x0c? | 0x0008 | 4 | `AMIYAFUGetFlashInfo` |  |
| 0x02 | 0x0c? | 0x0008 | 4 | `AMIYAFUGetFirmwareInfo` | _Firmware-related._ |
| 0x03 | 0x0c? | 0x0008 | 4 | `AMIYAFUGetFMHInfo` |  |
| 0x04 | 0x0c? | 0x0008 | 4 | `AMIYAFUGetStatus` |  |
| 0x10 | self* | 0x0008 | 4 | `AMIYAFUActivateFlashMode` |  |
| 0x20 | 0x10? | 0x0008 | 4 | `AMIYAFUAllocateMemory` |  |
| 0x21 | 0x10? | 0x0008 | 4 | `AMIYAFUFreeMemory` |  |
| 0x22 | self* | 0x0008 | 4 | `AMIYAFUReadFlash` |  |
| 0x23 | self* | 0x0008 | 4 | `AMIYAFUWriteFlash` |  |
| 0x24 | 0x10? | 0x0008 | 4 | `AMIYAFUEraseFlash` |  |
| 0x25 | 0x11? | 0x0008 | 4 | `AMIYAFUProtectFlash` |  |
| 0x26 | 0x18? | 0x0008 | 4 | `AMIYAFUEraseCopyFlash` |  |
| 0x27 | 0x18? | 0x0008 | 4 | `AMIYAFUVerifyFlash` |  |
| 0x30 | 0x13? | 0x0008 | 4 | `AMIYAFUReadMemory` |  |
| 0x31 | self* | 0x0008 | 4 | `AMIYAFUWriteMemory` |  |
| 0x32 | 0x18? | 0x0008 | 4 | `AMIYAFUCopyMemory` |  |
| 0x33 | 0x18? | 0x0008 | 4 | `AMIYAFUCompareMemory` |  |
| 0x34 | 0x14? | 0x0008 | 4 | `AMIYAFUClearMemory` |  |
| 0x40 | 0x4d? | 0x0008 | 4 | `AMIYAFUGetBootConfig` |  |
| 0x41 | self* | 0x0008 | 4 | `AMIYAFUSetBootConfig` |  |
| 0x42 | self* | 0x0008 | 4 | `AMIYAFUGetBootVars` |  |
| 0x50 | 0x0c? | 0x0008 | 4 | `AMIYAFUDeactivateFlash` |  |
| 0x51 | 0x0e? | 0x0008 | 4 | `AMIYAFUResetDevice` | _Reset-related._ |
| 0x28 | 0x0c? | 0x0008 | 4 | `AMIYAFUGetECFStatus` |  |
| 0x29 | 0x0c? | 0x0008 | 4 | `AMIYAFUGetVerifyStatus` |  |
| 0x54 | 0x10? | 0x0008 | 4 | `AMIYAFUDualImgSup` |  |
| 0x55 | 0x0d? | 0x0008 | 4 | `AMIYAFUFWSelectFlash` |  |
| 0x59 | 0x11? | 0x0008 | 4 | `AMIYAFUMiscellaneousInfo` |  |
| 0x35 | 0x14? | 0x0008 | 4 | `AMIYAFUCompareMeVersion` |  |
| 0x1e | User | 0x0008 | 4 | `AMIYAFUGetImgSize` |  |
| 0x57 | self* | 0x0008 | 4 | `AMIFileUpload` |  |
| 0x58 | self* | 0x0008 | 4 | `AMIFileDownload` |  |
| 0x60 | — none | all | 2 | `AMIGetNMChNum` |  |
| 0x62 | Callback | all | 2 | `AMIGetEthIndex` |  |
| 0x78 | self* | all | 4 | `SetSMTPConfigParams` |  |
| 0x79 | Admin | all | 2 | `GetSMTPConfigParams` |  |
| 0x63 | Callback | all | 2 | `AMIGetEmailForUser` |  |
| 0x64 | 0x41? | all | 4 | `AMISetEmailForUser` |  |
| 0x81 | Callback | all | 2 | `AMIGetEmailFormatUser` |  |
| 0x82 | 0x41? | all | 4 | `AMISetEmailFormatUser` |  |
| 0x65 | self* | all | 2 | `AMIResetPassword` | Reset a user password (self-gated, priv=0xff). |
| 0x66 | — none | all | 4 | `AMIRestoreDefaults` | **Factory reset** → async restore task 0x3f. priv=0 = the ASUS `raw 0x32 0x66` backdoor. |
| 0x67 | — none | all | 2 | `AMIGetLogConf` |  |
| 0x68 | self* | all | 4 | `AMISetLogConf` |  |
| 0xe9 | Operator | all | 2 | `AMIGetReleaseNote` |  |
| 0xe8 | self* | all | 2 | `AMIFirmwareCommand` | _Firmware-related._ |
| 0x70 | Callback | none | 4 | `AMILinkDownResilent` |  |
| 0x6b | User | none | 2 | `AMIGetDNSConf` |  |
| 0x6c | self* | none | 4 | `AMISetDNSConf` |  |
| 0x72 | Operator | none | 3 | `AMIGetIfaceState` |  |
| 0x71 | self* | none | 4 | `AMISetIfaceState` |  |
| 0x80 | Callback | none | 2 | `AMIGetFruDetails` |  |
| 0x90 | — none | all | 3 | `AMIGetRootUserAccess` | Read root user access — **priv=0, unauth-readable**. |
| 0x91 | self* | all | 4 | `AMISetRootPassword` | Set root/admin password (self-gated). |
| 0x92 | Callback | all | 3 | `AMIGetUserShelltype` |  |
| 0x93 | User | all | 4 | `AMISetUserShelltype` |  |
| 0x94 | self* | all | 4 | `AMISetTriggerEvent` |  |
| 0x95 | Callback | all | 3 | `AMIGetTriggerEvent` |  |
| 0x96 | — none | all | 2 | `AMIGetSolConf` |  |
| 0x97 | OEM | all | 4 | `AMISetLoginAuditConfig` |  |
| 0x98 | — none | all | 2 | `AMIGetLoginAuditConfig` |  |
| 0x99 | Operator | all | 4 | `AMIGetAllIPv6Address` |  |
| 0xbe | Callback | all | 2 | `AMIGetChannelType` |  |
| 0x7e | — none | all | 2 | `AMIGetSELPolicy` |  |
| 0x7f | Callback | all | 4 | `AMISetSELPolicy` |  |
| 0x85 | Admin | all | 2 | `AMIGetSELEntires` |  |
| 0x86 | — none | all | 2 | `AMIGetSenforInfo` |  |
| 0x8d | — none | all | 2 | `AMIGetIPMISessionTimeOut` | _Session-related._ |
| 0x8e | 0x10? | all | 2 | `AMIGetUDSInfo` |  |
| 0x9a | self* | all | 2 | `AMIGetUDSSessionInfo` | _Session-related._ |
| 0xa9 | self* | all | 4 | `AMIYAFUReplaceSignedImageKey` | _Key-related._ |
| 0xc3 | Callback | all | 2 | `AMIGetSSLCertStatus` |  |
| 0xec | self* | all | 4 | `AMISetSSLCert` |  |
| 0xb4 | Callback | all | 2 | `AMIGetFwVersion` |  |
| 0xc2 | self* | all | 3 | `AMIGetFeatureStatus` |  |
| 0xe6 | — none | all | 4 | `AMIRestartWebService` | **Restart the web server — priv=0, unauth DoS/restart.** |
| 0xe7 | Admin | all | 3 | `AMIGetPendStatus` |  |
| 0xee | Callback | all | 4 | `AMISwitchMUX` |  |
| 0x2b | Callback | all | 4 | `AMISetPswdChangeStatus` |  |
| 0x3d | Operator | all | 4 | `AMIGetBMCInterfaceStatus` |  |
| 0x3e | Callback | all | 4 | `AMIGetKCSLANIfcSupport` |  |
| 0x3f | User | all | 4 | `AMISetKCSLANIfcSupport` |  |

---

## Advantech platform OEM (PDK)

### `g_Oem_NetFn30_CmdHndlr` — libipmipdkcmds.so.6.0.0  · NetFn 0x30  · 13 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x01 | User | all | 4 | `ControlMEUpdate` | Intel ME firmware update control. |
| 0x02 | Callback | all | 4 | `LockInputs` | Lock front-panel / input controls. |
| 0x03 | Callback | all | 2 | `ControlSysErrLED` | Drive the system error LED. |
| 0x04 | — none | all | 4 | `GetPlatformID` | Advantech platform ID — **priv=0, unauth fingerprint**. |
| 0x05 | Callback | all | 2 | `AMIPingFeature` | Feature-presence ping. |

### `g_Oem_ASMB260_CmdHndlr` — libipmipdkcmds.so.6.0.0  · NetFn 0x3a  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x01 | Callback | all | 4 | `PDK_SDRGetNominalReading` | SDR nominal reading helper. |
| 0x02 | Callback | all | 4 | `PDK_SDRGetAnalogFlags` | SDR analog flags helper. |

### `g_OEM_CmdHndlr` — libipmipdkcmds.so.6.0.0  · 0 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|

---

## AMI OEM feature libraries (PDK-registered)

### `g_AD_CmdHndlr` — libipmiamioemad.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xc4 | self* | all | 2 | `AMIGetADConf` |  |
| 0xc5 | self* | all | 4 | `AMISetADConf` |  |

### `g_AccessRedis_CmdHndlr` — libipmiamioemaccessredis.so.13.1.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x2a | self* | all | 129 | `AMIAccessRedisDB` | _Redis-related._ |

### `g_AutoHostLock_CmdHndlr` — libipmiamioemautohostlock.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xbc | — none | all | 2 | `AMIGetHostAutoLockStatus` | _Lock-related._ |
| 0xbd | Callback | all | 4 | `AMISetHostAutoLockStatus` | _Lock-related._ |

### `g_BackupRst_CmdHndlr` — libipmiamioembackuprestore.so.13.3.0  · 3 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xe3 | User | all | 4 | `AMISetBackupFlag` | _Backup-related._ |
| 0xe4 | self* | all | 2 | `AMIGetBackupFlag` | _Backup-related._ |
| 0xe5 | self* | all | 4 | `AMIManageBMCConfig` |  |

### `g_CtlDbg_CmdHndlr` — libipmiamioemctldbg.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xa1 | Callback | all | 4 | `AMIControlDebugMsg` | _Debug-related._ |
| 0xa2 | — none | all | 2 | `AMIGetDebugMsgStatus` | _Debug-related._ |

### `g_ExtPriv_CmdHndlr` — libipmiamioemextpriv.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xa3 | OEM | all | 4 | `AMISetExtendedPrivilege` | _Priv-related._ |
| 0xa4 | Callback | all | 3 | `AMIGetExtendedPrivilege` | _Priv-related._ |

### `g_ExtSEL_CmdHndlr` — libipmiamioemextendedsel.so.13.2.0  · 4 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xcc | self* | all | 4 | `AMIAddExtendSelEntries` |  |
| 0xcd | User | all | 2 | `AMIGETExtendSelData` |  |
| 0xf0 | self* | all | 4 | `AMIPartialAddExtendSelEntries` |  |
| 0xf1 | self* | all | 4 | `AMIPartialGetExtendSelEntries` |  |

### `g_Firewall_CmdHndlr` — libipmiamioemfirewall.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x77 | self* | none | 2 | `AMIGetFirewall` |  |
| 0x76 | self* | none | 4 | `AMISetFirewall` |  |

### `g_FirmwareRecovery_CmdHndlr` — libipmiamioemfirmwarerecovery.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xf3 | User | all | 3 | `AMIGetRecoveryInfo` | _Recovery-related._ |
| 0xf4 | self* | all | 3 | `AMISetRecoveryInfo` | _Recovery-related._ |

### `g_FrmUpdatePrctl_CmdHndlr` — libipmiamioemfwupdateprctl.so.13.0.0  · 6 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x87 | User | all | 4 | `AMIStartTFTPFwUpdate` | _FwUpdate-related._ |
| 0x88 | — none | all | 4 | `AMIGetTftpProgressStatus` |  |
| 0x89 | self* | all | 4 | `AMISetFWCfg` |  |
| 0x8a | Callback | all | 4 | `AMIGetFWCfg` |  |
| 0x8b | Callback | all | 4 | `AMISetFWProtocol` |  |
| 0x8c | — none | all | 4 | `AMIGetFWProtocol` |  |

### `g_GetBIOSCode_CmdHndlr` — libipmiamioembioscode.so.13.1.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x73 | Callback | all | 2 | `AMIGetBiosCode` |  |

### `g_GetBIOSRemoteCtrl_CmdHndlr` — libipmiamioembiosremotecontrol.so.13.0.0  · 6 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xce | self* | all | 2 | `AMISendToBios` |  |
| 0xcf | — none | all | 129 | `AMIGetBiosCommand` |  |
| 0xd1 | self* | all | 129 | `AMISetBiosResponse` |  |
| 0xd2 | Callback | all | 2 | `AMIGetBiosResponse` |  |
| 0xd3 | 0x08? | all | 2 | `AMISetBiosFlag` |  |
| 0xd4 | — none | all | 2 | `AMIGetBiosFlag` |  |

### `g_HostLock_CmdHndlr` — libipmiamioemhostlock.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xae | — none | all | 2 | `AMIGetHostLockFeatureStatus` | _Lock-related._ |
| 0xaf | Callback | all | 4 | `AMISetHostLockFeatureStatus` | _Lock-related._ |

### `g_Inventory_CmdHndlr` — libipmiamioeminventory.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x5b | Operator | all | 2 | `AMIGetInvenoryInfo` |  |
| 0x5a | self* | all | 4 | `AMISetInvenoryInfo` |  |

### `g_LDAP_CmdHndlr` — libipmiamioemldap.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xc8 | self* | all | 2 | `AMIGetLDAPConf` | _LDAP-related._ |
| 0xc9 | self* | all | 4 | `AMISetLDAPConf` | _LDAP-related._ |

### `g_Media_CmdHndlr` — libipmiamioemmedia.so.13.4.0  · 6 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xca | Callback | all | 2 | `AMIGetVmediaCfg` | _Media-related._ |
| 0xcb | User | all | 4 | `AMISetVmediaCfg` | _Media-related._ |
| 0xd7 | self* | all | 4 | `AMIMediaRedirectionStartStop` | _Media-related._ |
| 0xd8 | self* | all | 2 | `AMIGetMediaInfo` | _Media-related._ |
| 0xd9 | self* | all | 4 | `AMISetMediaInfo` | _Media-related._ |
| 0xdc | User | all | 2 | `AMIGetRedirectedMediaInfo` | _Media-related._ |

### `g_Memtest_CmdHndlr` — libipmiamioemubootmemtest.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x9c | Callback | all | 4 | `AMISetUBootMemtest` | _Memtest-related._ |
| 0x9d | — none | all | 4 | `AMIGetUBootMemtestStatus` | _Memtest-related._ |

### `g_NTP_CmdHndlr` — libipmiamioemntp.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xa7 | — none | all | 3 | `AMIGetNTPCfg` |  |
| 0xa8 | self* | all | 4 | `AMISetNTPCfg` |  |

### `g_PAMReorder_CmdHndlr` — libipmiamioempamreorder.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x7a | self* | all | 4 | `AMISetPamOrder` |  |
| 0x7b | — none | all | 2 | `AMIGetPamOrder` |  |

### `g_PLDM_CmdHndlr` — libipmiamioempldmcmds.so.13.4.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xd5 | self* | all | 2 | `AMIPLDMBIOSMsg` |  |

### `g_PLDM_CmdHndlr` — libpldmfwupdate.so.13.2.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xd6 | self* | all | 2 | `AMIPLDMFIRMWAREMsg` | _Firmware-related._ |

### `g_PTP_CmdHndlr` — libipmiamioemptp.so.13.1.0  · 7 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x36 | — none | all | 3 | `AMIGetPTPCfg` |  |
| 0x37 | 0x0a? | all | 4 | `AMISetPTPCfg` |  |
| 0x38 | — none | all | 3 | `AMIGetPTPInt` |  |
| 0x39 | 0x0a? | all | 4 | `AMISetPTPInt` |  |
| 0x3a | — none | all | 3 | `AMIGetPTPUnicastip` |  |
| 0x3b | 0x0f? | all | 4 | `AMISetPTPUnicastip` |  |
| 0x3c | Callback | all | 4 | `AMIPTPCtrl` |  |

### `g_PwdEnc_CmdHndlr` — libipmiamioempwdenc.so.13.0.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x9b | self* | all | 4 | `AMISetPwdEncryptionKey` | Set password-encryption key. |

### `g_PwrCons_CmdHndlr` — libipmiamioempwrcons.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xab | — none | all | 2 | `AMIVirtualDeviceGetStatus` |  |
| 0xaa | Callback | all | 4 | `AMIVirtualDeviceSetStatus` |  |

### `g_RAIDInfo_CmdHndlr` — libipmiamioemraidinfo.so.13.0.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xef | self* | all | 3 | `AMIGetRAIDInfo` | _RAID-related._ |

### `g_REMOTEKVM_CmdHndlr` — libipmiamioemremotekvm.so.13.2.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xc0 | Callback | all | 2 | `AMIGetRemoteKVMCfg` | _KVM-related._ |
| 0xc1 | self* | all | 4 | `AMISetRemoteKVMCfg` | _KVM-related._ |

### `g_RESTInterface_CmdHndlr` — libipmiamioemrestiface.so.13.4.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x5c | self* | 0x00ff | 4 | `AMIRESTinterface` |  |
| 0x5d | self* | all | 129 | `AMIGeneratePassword` | Generate a password. |

### `g_RIS_CmdHndlr` — libipmiamioemris.so.13.0.0  · 5 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x9e | User | all | 2 | `AMIGetRISConf` |  |
| 0x9f | self* | all | 4 | `AMISetRISConf` |  |
| 0xa0 | User | all | 4 | `AMIRISStartStop` |  |
| 0x18 | Callback | all | 2 | `AMIGetRMediaCfg` | _Media-related._ |
| 0x19 | self* | all | 4 | `AMISetRMediaCfg` | _Media-related._ |

### `g_Radius_CmdHndlr` — libipmiamioemradius.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xc6 | self* | all | 2 | `AMIGetRadiusConf` | _Radius-related._ |
| 0xc7 | self* | all | 4 | `AMISetRadiusConf` | _Radius-related._ |

### `g_SMASHLITE_CmdHndlr` — libipmiamioemsmashlitecorecmds.so.13.0.0  · 3 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xfb | — none | all | 3 | `GetActiveSessionCount` | _Session-related._ |
| 0xfc | User | all | 130 | `SetActiveSessionCount` | _Session-related._ |
| 0xfd | — none | all | 2 | `GetSysHealthFirmwareANDPowerCycle` | _Firmware-related._ |

### `g_SNMP_CmdHndlr` — libipmiamioemsnmp.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x7c | Callback | none | 2 | `AMIGetSNMPConf` | _SNMP-related._ |
| 0x7d | OEM | none | 4 | `AMISetSNMPConf` | _SNMP-related._ |

### `g_SSHConf_CmdHndlr` — libipmiamioemsshconf.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x11 | self* | all | 2 | `AMIGetSSHConf` | _SSH-related._ |
| 0x12 | self* | all | 4 | `AMISetSSHConf` | _SSH-related._ |

### `g_SensorThresholdAcrossResets_CmdHndlr` — libipmiamioemsensorthresholdacrossresets.so.13.0.0  · 1 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x4a | Callback | all | 2 | `AMISensorThresholdAcrossResets` | _Reset-related._ |

### `g_ServiceConf_CmdHndlr` — libipmiamioemserviceconf.so.13.1.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x69 | Admin | none | 2 | `AMIGetServiceConf` |  |
| 0x6a | 0x24? | none | 4 | `AMISetServiceConf` |  |

### `g_SessionMgmt_CmdHndlr` — libipmiamioemsessionmgmt.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xb0 | Callback | all | 2 | `AMIGetAllActiveSessions` | _Session-related._ |
| 0xb1 | Admin | all | 4 | `AMIActiveSessionClose` | _Session-related._ |

### `g_SinglePort_CmdHndlr` — libipmiamioemsingleport.so.13.0.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xb7 | — none | all | 2 | `AMIGetRunTimeSinglePortStatus` |  |
| 0xb8 | Callback | all | 4 | `AMISetRunTimeSinglePortStatus` |  |

### `g_TimeZone_CmdHndlr` — libipmiamioemtimezone.so.13.3.0  · 2 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0xa5 | self* | all | 4 | `AMISetTimeZone` |  |
| 0xa6 | — none | all | 2 | `AMIGetTimeZone` |  |

### `g_prsvconf_CmdHndlr` — libipmiamioemprsvconf.so.13.0.0  · 4 cmds

| Cmd | Priv | Iface | ReqLen | Handler | Notes |
|-----|------|-------|--------|---------|-------|
| 0x83 | User | all | 4 | `AMISetPreserveConfStatus` |  |
| 0x84 | Callback | all | 2 | `AMIGetPreserveConfStatus` |  |
| 0xba | User | all | 4 | `AMISetAllPreserveConfStatus` |  |
| 0xbb | — none | all | 2 | `AMIGetAllPreserveConfStatus` |  |

---

## Security rollup — priv 0x00 (no-minimum) handlers

Callable with no privilege floor. On the KCS/system interface these need no BMC credentials at all.

| Table | Cmd | Iface | Handler |
|-------|-----|-------|---------|
| `g_AMI_CmdHndlr` | 0x60 | all | `AMIGetNMChNum` |
| `g_AMI_CmdHndlr` | 0x66 | all | `AMIRestoreDefaults` |
| `g_AMI_CmdHndlr` | 0x67 | all | `AMIGetLogConf` |
| `g_AMI_CmdHndlr` | 0x90 | all | `AMIGetRootUserAccess` |
| `g_AMI_CmdHndlr` | 0x96 | all | `AMIGetSolConf` |
| `g_AMI_CmdHndlr` | 0x98 | all | `AMIGetLoginAuditConfig` |
| `g_AMI_CmdHndlr` | 0x7e | all | `AMIGetSELPolicy` |
| `g_AMI_CmdHndlr` | 0x86 | all | `AMIGetSenforInfo` |
| `g_AMI_CmdHndlr` | 0x8d | all | `AMIGetIPMISessionTimeOut` |
| `g_AMI_CmdHndlr` | 0xe6 | all | `AMIRestartWebService` |
| `g_App_CmdHndlr` | 0x01 | all | `GetDevID` |
| `g_App_CmdHndlr` | 0x01 | all | `UnImplementedFunc` |
| `g_App_CmdHndlr` | 0x02 | all | `ColdReset` |
| `g_App_CmdHndlr` | 0x03 | all | `WarmReset` |
| `g_App_CmdHndlr` | 0x04 | all | `GetSelfTestResults` |
| `g_App_CmdHndlr` | 0x07 | all | `GetACPIPwrState` |
| `g_App_CmdHndlr` | 0x08 | all | `GetDevGUID` |
| `g_App_CmdHndlr` | 0x22 | all | `ResetWDT` |
| `g_App_CmdHndlr` | 0x25 | all | `GetWDT` |
| `g_App_CmdHndlr` | 0x2f | all | `GetBMCGlobalEnables` |
| `g_App_CmdHndlr` | 0x31 | all | `GetMsgFlags` |
| `g_App_CmdHndlr` | 0x33 | all | `GetMessage` |
| `g_App_CmdHndlr` | 0x35 | all | `ReadEvtMsgBuffer` |
| `g_App_CmdHndlr` | 0x36 | all | `GetBTIfcCap` |
| `g_App_CmdHndlr` | 0x37 | all | `GetSystemGUID` |
| `g_AutoHostLock_CmdHndlr` | 0xbc | all | `AMIGetHostAutoLockStatus` |
| `g_Chassis_CmdHndlr` | 0x00 | all | `GetChassisCaps` |
| `g_Chassis_CmdHndlr` | 0x01 | all | `GetChassisStatus` |
| `g_Chassis_CmdHndlr` | 0x03 | all | `UnImplementedFunc` |
| `g_Chassis_CmdHndlr` | 0x07 | all | `GetSysRestartCause` |
| `g_Chassis_CmdHndlr` | 0x0f | all | `GetPOHCounter` |
| `g_CtlDbg_CmdHndlr` | 0xa2 | all | `AMIGetDebugMsgStatus` |
| `g_FrmUpdatePrctl_CmdHndlr` | 0x88 | all | `AMIGetTftpProgressStatus` |
| `g_FrmUpdatePrctl_CmdHndlr` | 0x8c | all | `AMIGetFWProtocol` |
| `g_GetBIOSRemoteCtrl_CmdHndlr` | 0xcf | all | `AMIGetBiosCommand` |
| `g_GetBIOSRemoteCtrl_CmdHndlr` | 0xd4 | all | `AMIGetBiosFlag` |
| `g_HostLock_CmdHndlr` | 0xae | all | `AMIGetHostLockFeatureStatus` |
| `g_Memtest_CmdHndlr` | 0x9d | all | `AMIGetUBootMemtestStatus` |
| `g_NTP_CmdHndlr` | 0xa7 | all | `AMIGetNTPCfg` |
| `g_Oem_NetFn30_CmdHndlr` | 0x04 | all | `GetPlatformID` |
| `g_PAMReorder_CmdHndlr` | 0x7b | all | `AMIGetPamOrder` |
| `g_PTP_CmdHndlr` | 0x36 | all | `AMIGetPTPCfg` |
| `g_PTP_CmdHndlr` | 0x38 | all | `AMIGetPTPInt` |
| `g_PTP_CmdHndlr` | 0x3a | all | `AMIGetPTPUnicastip` |
| `g_PwrCons_CmdHndlr` | 0xab | all | `AMIVirtualDeviceGetStatus` |
| `g_SMASHLITE_CmdHndlr` | 0xfb | all | `GetActiveSessionCount` |
| `g_SMASHLITE_CmdHndlr` | 0xfd | all | `GetSysHealthFirmwareANDPowerCycle` |
| `g_SensorEvent_CmdHndlr` | 0x01 | all | `GetEventReceiver` |
| `g_SensorEvent_CmdHndlr` | 0x10 | all | `GetPEFCapabilities` |
| `g_SensorEvent_CmdHndlr` | 0x15 | all | `GetLastProcessedEventId` |
| `g_SensorEvent_CmdHndlr` | 0x22 | all | `ReserveDevSDRRepository` |
| `g_SinglePort_CmdHndlr` | 0xb7 | all | `AMIGetRunTimeSinglePortStatus` |
| `g_Storage_CmdHndlr` | 0x20 | all | `GetSDRRepositoryInfo` |
| `g_Storage_CmdHndlr` | 0x21 | all | `GetSDRRepositoryAllocInfo` |
| `g_Storage_CmdHndlr` | 0x22 | all | `ReserveSDRRepository` |
| `g_Storage_CmdHndlr` | 0x28 | all | `GetSDRRepositoryTime` |
| `g_Storage_CmdHndlr` | 0x2a | all | `UnImplementedFunc` |
| `g_Storage_CmdHndlr` | 0x2b | all | `UnImplementedFunc` |
| `g_Storage_CmdHndlr` | 0x40 | all | `GetSELInfo` |
| `g_Storage_CmdHndlr` | 0x41 | all | `GetSELAllocationInfo` |
| `g_Storage_CmdHndlr` | 0x42 | all | `ReserveSEL` |
| `g_Storage_CmdHndlr` | 0x48 | all | `GetSELTime` |
| `g_Storage_CmdHndlr` | 0x5c | all | `GetSELTimeUTC_Offset` |
| `g_TimeZone_CmdHndlr` | 0xa6 | all | `AMIGetTimeZone` |
| `g_prsvconf_CmdHndlr` | 0xbb | all | `AMIGetAllPreserveConfStatus` |
