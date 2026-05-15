# Dell iDRAC6 — full dispatch table

Auto-generated from the Dell fullfw RE. **DO NOT EDIT BY HAND.**
Regenerate with:

```
python -m zipmi.parsers.md_table --markdown > docs/dell-command-table.md
```

Source: `/Volumes/yyy/phd/bmc/dell/fullfw-ipmi-commands.md`  
Entries: **192** unique (NetFn, cmd) pairs

## Summary

| NetFn | Group | Entries | Sessionless | Stubbed |
|------|-------|---------|-------------|---------|
| 0x00 | Chassis | 9 | 3 | 0 |
| 0x04 | Sensor / Event | 22 | 6 | 0 |
| 0x06 | App | 52 | 14 | 0 |
| 0x08 | Firmware | 8 | 7 | 0 |
| 0x0a | Storage | 18 | 1 | 0 |
| 0x0c | Transport | 8 | 3 | 0 |
| 0x2e | OEM / Group (extended) | 8 | 5 | 0 |
| 0x30 | Dell OEM | 67 | 28 | 8 |
| | **Total** | **192** | **67** | **8** |

## NetFn 0x00 — Chassis

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x00 | CmdGetChassisCapabilities | User |  |  | YES: 01 20 20 20 20 20 |  | Returns chassis capabilities: intrusion sensor, all devices at BMC 0x20 |
| 0x01 | CmdGetChassisStatus | User |  |  | YES: 21 10 00 50 |  | Power ON, restore=previous, last on via IPMI |
| 0x02 | CmdChassisControl | Operator |  |  | ? (WRITES) |  | Power off / on / cycle / hard reset / diagnostic interrupt / soft shutdown |
| 0x04 | DellCmdChassisIdentify | Operator | ✓ |  | ? (WRITES) |  | Blink chassis identify LED (Dell override of standard identify) |
| 0x05 | CmdSetChassisCapabilities | Administrator | ✓ |  | ? (WRITES) |  | Write chassis capability bytes |
| 0x07 | CmdGetSystemRestartCause | User |  |  | YES: 01 01 |  | Restart cause 0x01 = chassis control command, channel 0x01 |
| 0x08 | CmdSetSystemBootOptions | Operator | ✓ |  | ? (WRITES) |  | Set boot flags: boot device, BIOS quiet mode, lock out reset buttons |
| 0x09 | CmdGetSystemBootOptions | Operator |  |  | YES: 0xC7 (needs param byte) |  | Read current boot option parameters |
| 0x0b | CmdSetPowerCycleInterval | Administrator |  |  | ? (WRITES) |  | Set delay (seconds) between power-off and power-on during a power cycle |

## NetFn 0x04 — Sensor / Event

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x00 | CmdSetEventReceiver | Administrator |  |  | ? (WRITES) |  | Set IPMB address and LUN of event message receiver |
| 0x01 | CmdGetEventReceiver | User |  |  | YES: 20 00 |  | Event receiver at BMC (0x20), LUN 0 |
| 0x02 | CmdPlatformEvent | Operator | ✓ |  | ? (WRITES) |  | Generate a platform event message |
| 0x10 | CmdPEFCGetCapabilities | User |  |  | YES: 51 1f 28 |  | PEF v1.5, 31 filter entries, 40 alert policies |
| 0x11 | CmdPEFCArmPostponeTimer | Administrator |  |  | ? (WRITES) |  | Arm or postpone the PEF postpone timer |
| 0x12 | CmdPEFCSetConfigurationParameters | Administrator | ✓ |  | ? (WRITES) |  | Write PEF configuration |
| 0x13 | CmdPEFCGetConfigurationParameters | Operator | ✓ |  | YES: 0xC7 (needs param byte) |  | Read PEF configuration parameters |
| 0x14 | CmdPEFCSetLastProcessedEventID | Operator |  |  | ? (WRITES) |  | Set record ID of most recently processed SEL event |
| 0x15 | CmdPEFCGetLastProcessedEventID | User |  |  | YES: 81 5b c4 69 07 00 ff ff 07 00 |  | Last processed event IDs |
| 0x16 | CmdPEFCAlertImmediate | Operator |  |  | ? (WRITES) |  | Force immediate alert transmission |
| 0x17 | CmdPETCAcknowledge | Unspecified |  |  | YES: 0xC7 (needs data) |  | Acknowledge a PET SNMP trap |
| 0x23 | CmdGetSensorReadingFactors | User |  |  | DISABLED (0xC1) |  | Dell stub 0x00161140 — confirmed disabled on live BMC |
| 0x24 | CmdSetSensorHysteresis | Administrator |  |  | ? (WRITES) |  | Set hysteresis for threshold-based sensor |
| 0x25 | CmdGetSensorHysteresis | User |  |  | YES: 0xC7 (needs 2-byte sensor#) |  | Read hysteresis values |
| 0x26 | CmdSetSensorThresholds | Operator |  |  | ? (WRITES) |  | Write threshold values |
| 0x27 | CmdGetSensorThresholds | User |  |  | YES: 18 00 00 00 d5 da 00 (sensor 1) |  | Sensor 1 thresholds: UC=0xD5, UNR=0xDA |
| 0x28 | CmdSetSensorEventEnable | Operator | ✓ |  | ? (WRITES) |  | Enable/disable event generation per sensor |
| 0x29 | CmdGetSensorEventEnable | User |  |  | YES: 00 (sensor 1) |  | Sensor 1 events: none enabled |
| 0x2a | CmdRearmSensorEvents | Operator | ✓ |  | ? (WRITES) |  | Re-arm event generation |
| 0x2b | CmdGetSensorEventStatus | User |  |  | YES: 00 00 (sensor 1) |  | Sensor 1 event status: no events |
| 0x2d | CmdGetSensorReading | User |  |  | YES: 42 00 c0 (sensor 1) |  | Sensor 1 reading=0x42, scanning enabled |
| 0x30 | CmdSetSensorReading | Operator | ✓ |  | ? (WRITES) |  | Inject arbitrary reading/event status |

## NetFn 0x06 — App

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x01 | CmdGetDeviceID | User |  |  | YES: 20 80 01 70 02 df a2 02 00 ... |  | FW 1.70, IPMI 2.0, Dell IANA 674 |
| 0x02 | CmdColdReset | Administrator |  |  | ? (DESTRUCTIVE) |  | Unconditionally reset the BMC |
| 0x04 | CmdGetSelfTestResults | User |  |  | YES: 55 00 |  | Self-test passed, no errors |
| 0x05 | CmdManufacturingTestOn | Administrator |  |  | ? (WRITES) |  | Enable manufacturing test mode |
| 0x06 | CmdSetACPIPowerState | Administrator |  |  | ? (WRITES) |  | Set ACPI power state |
| 0x07 | CmdGetACPIPowerState | User |  |  | YES: 2a 2a |  | System=S0/G0(working), Device=D0(on) |
| 0x08 | CmdGetDeviceGUID | User |  |  | YES: 44 45 4c 4c 58 00 10 54 80 33 b5 c0 4f 47 51  |  | GUID = "DELLX..T.3..OGQ1" |
| 0x09 | CmdGetNetFnSupport | User |  |  | YES: 0xC7 (needs channel/LUN param) |  | Bitmap of supported NetFns |
| 0x0a | CmdGetCommandSupport | Operator | ✓ |  | YES: 0xCC (needs NetFn/channel param) |  | Command support bitmap |
| 0x0b | CmdGetCommandSubFnSupport | Administrator |  |  | ? |  | Sub-function support bitmap |
| 0x0c | CmdGetConfigurableCommands | Operator | ✓ |  | ? |  | Configurable commands bitmap |
| 0x0d | CmdGetConfigurableCommandSubFn | Administrator |  |  | ? |  | Configurable sub-functions |
| 0x22 | CmdResetWatchdogTimer | Operator |  |  | ? (WRITES) |  | Pet the watchdog timer |
| 0x24 | CmdSetWatchdogTimer | Administrator |  |  | ? (WRITES) |  | Configure watchdog |
| 0x25 | CmdGetWatchdogTimer | User |  |  | YES: c4 00 00 00 c0 12 79 12 |  | Watchdog config + countdown |
| 0x2e | CmdSetBMCGlobalEnable | Unspecified | ✓ |  | ? (WRITES) |  | Enable/disable message handling |
| 0x2f | CmdGetBMCGlobalEnable | User |  |  | YES: 0c |  | Global enables: SEL+EventMsgBuf enabled |
| 0x30 | CmdClearMsgFlags | Unspecified | ✓ |  | ? (WRITES) |  | Clear message flag bits |
| 0x31 | CmdGetMsgFlags | Unspecified | ✓ |  | NO (0xC1) |  | Not available on LAN — KCS system interface only |
| 0x32 | CmdEnableMsgChannelRecv | Unspecified | ✓ |  | ? |  | Enable channel receive |
| 0x33 | CmdGetMsg | Unspecified | ✓ |  | ? |  | Retrieve from receive queue |
| 0x35 | CmdReadEventMsgBuf | Unspecified | ✓ |  | ? |  | Read from event message buffer |
| 0x37 | CmdGetSystemGUID | Unspecified |  |  | YES: 44 45 4c 4c 58 00 10 54 80 33 b5 c0 4f 47 51  |  | Same as DeviceGUID |
| 0x3c | CmdCloseSession | Administrator |  |  | ? (WRITES) |  | Close IPMI session |
| 0x3d | CmdGetSessionInfo | Administrator | ✓ |  | YES: 20 05 01 02 04 01 c0 a8 00 02 b0 be 83 a2 52  |  | Current session: from 192.168.0.2, MAC b0:be:83:a2:52:c5 |
| 0x3f | CmdGetAuthCode | Operator |  |  | ? |  | Generate auth code |
| 0x40 | CmdSetChannelAccess | Administrator |  |  | ? (WRITES) |  | Set channel access mode |
| 0x41 | CmdGetChannelAccess | User |  |  | YES: 12 04 (ch1, volatile) |  | Ch1: always available, max priv=Admin |
| 0x42 | CmdGetChannelInfo | User |  |  | YES: 01 04 01 81 f2 1b 00 00 00 (ch1) |  | Ch1: 802.3 LAN, IPMB-1.0, multi-session |
| 0x43 | CmdSetUserAccess | Administrator | ✓ |  | ? (WRITES) |  | Set user privilege level |
| 0x44 | CmdGetUserAccess | Operator |  |  | YES: 10 88 01 0f (ch1 user1) |  | 16 user slots, user1 enabled, Admin priv |
| 0x45 | CmdSetUserName | Administrator |  |  | ? (WRITES) |  | Write user name |
| 0x46 | CmdGetUserName | Operator |  |  | YES: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |  | User 1 name = null (anonymous/root) |
| 0x47 | CmdSetUserPassword | Administrator | ✓ |  | ? (WRITES) |  | Set/test user password |
| 0x48 | CmdActivatePayload | Callback |  |  | ? (WRITES) |  | Activate SOL/OEM payload |
| 0x49 | CmdDeactivatePayload | Callback |  |  | ? (WRITES) |  | Deactivate payload |
| 0x4a | CmdGetPayloadActivationStatus | User |  |  | YES: 01 00 00 (SOL) |  | SOL: 1 instance max, 0 active |
| 0x4b | CmdGetPayloadInstanceInfo | User |  |  | ? |  | Payload instance info |
| 0x4c | CmdSetUserPayloadAccess | Administrator |  |  | ? (WRITES) |  | Set user payload access |
| 0x4d | CmdGetUserPayloadAccess | User |  |  | ? |  | User payload access bitmap |
| 0x4e | CmdGetChannelPayloadSupport | User |  |  | YES: 03 00 3f 00 00 00 00 00 (ch1) |  | Ch1: IPMI+SOL standard, 6 OEM payloads |
| 0x4f | CmdGetChannelPayloadVersion | User |  |  | ? |  | Payload version |
| 0x50 | CmdGetChannelOEMPayloadInfo | User |  |  | ? |  | OEM payload info |
| 0x52 | CmdSuspendBMCARPs | Operator | ✓ |  |  |  | Gratuitous ARP and ARP response suspend/resume for a LAN channel |
| 0x54 | CmdGetChannelCipherSuites | Operator |  |  |  |  | Enumerate supported cipher suites per channel |
| 0x55 | CmdSuspendResumePayloadEncryption | User |  |  |  |  | Temporarily suspend/resume payload encryption on active session |
| 0x56 | CmdSetChannelSecurityKeys | Administrator | ✓ |  |  |  | Set or clear integrity/confidentiality keys for a channel |
| 0x60 | CmdSetCommandEnables | Administrator | ✓ |  |  |  | Enable/disable specific commands (command firewall write) |
| 0x61 | CmdGetCommandEnables | Operator |  |  |  |  | Read command enable bitmap |
| 0x62 | CmdSetCommandSubFnEnables | Administrator |  |  |  |  | Enable/disable sub-functions of a specific command |
| 0x63 | CmdGetCommandSubFnEnables | User |  |  |  |  | Read sub-function enable bitmap |
| 0x64 | CmdSet/GetSessionLessChannelPrivilege | Operator |  |  |  |  | Get or set privilege level on session-less channels (e.g., KCS) |

## NetFn 0x08 — Firmware

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x02 | CmdFirmwareUpdate | Administrator |  |  |  |  | Initiate firmware update process |
| 0x10 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command (chunk write) |
| 0x11 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command |
| 0x12 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command |
| 0x13 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command |
| 0x14 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command |
| 0x15 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command |
| 0x16 | (FW phase cmd) | Administrator | ✓ |  |  |  | Firmware update sub-command |

## NetFn 0x0a — Storage

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x10 | CmdGetFRUInvAreaInfo | User |  |  | YES: 00 10 00 (dev 0) |  | FRU area: 4096 bytes (0x1000), byte access |
| 0x11 | CmdReadFRUData | User |  |  | ? |  | Read bytes from FRU inventory data area |
| 0x12 | CmdWriteFRUData | Administrator |  |  | ? (WRITES) |  | Write FRU data. Can overwrite serial numbers |
| 0x20 | CmdGetSDRRepoInfo | User |  |  | YES: 51 7e 00 e1 05 ff ff ff ff ff ff ff ff 42 |  | 126 SDRs, 1505 bytes free, v1.5 |
| 0x22 | CmdResvSDRRepo | User |  |  | ? |  | Reserve SDR repository |
| 0x23 | CmdGetSDR | User |  |  | ? |  | Read SDR by ID |
| 0x25 | CmdPartAddSDR | Operator | ✓ |  | DISABLED (0xC1) |  | Dell stub 0x00161140 — confirmed disabled |
| 0x27 | CmdClrSDR | Administrator |  |  | DISABLED (0xC1) |  | Dell stub 0x00161140 — confirmed disabled |
| 0x28 | CmdGetSDRRepoTime | User |  |  | YES: a8 e5 d3 69 |  | SDR repo timestamp (Unix time) |
| 0x29 | CmdSetSDRRepoTime | Administrator |  |  | ? (WRITES) |  | Set SDR timestamp |
| 0x2c | CmdRunInitAgent | Operator |  |  | ? (WRITES) |  | Run sensor init agent |
| 0x40 | CmdGetSELInfo | User |  |  | YES: 51 07 00 90 1f 81 5b c4 69 95 fc 46 4d 02 |  | 7 entries, 8080 bytes free, v1.5 |
| 0x42 | CmdReserveSEL | User |  |  | ? |  | Reserve SEL |
| 0x43 | CmdGetSELEntry | User |  |  | ? |  | Read SEL record by ID |
| 0x44 | CmdAddSELEntry | Operator |  |  | ? (WRITES) |  | Add event record to SEL |
| 0x47 | CmdClearSEL | Administrator |  |  | ? (DESTRUCTIVE) |  | Erase entire SEL |
| 0x48 | CmdGetSELTime | User |  |  | YES: a8 e5 d3 69 |  | SEL clock (Unix timestamp) |
| 0x49 | CmdSetSELTime | Administrator |  |  | ? (WRITES) |  | Set SEL clock time |

## NetFn 0x0c — Transport

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x01 | CmdSetLANConfigParam | Administrator | ✓ |  | ? (WRITES) |  | Write LAN config: IP, subnet, gateway, VLAN |
| 0x02 | CmdGetLANConfigParam | Operator |  |  | YES: 11 c0 a8 00 17 (ch1 param3=IP) |  | LAN IP = 192.168.0.23 |
| 0x10 | CmdSetSerModemConfigParam | Administrator | ✓ |  | ? (WRITES) |  | Write serial/modem config |
| 0x11 | CmdGetSerModemConfigParam | Operator |  |  | ? |  | Read serial/modem config |
| 0x12 | CmdSetSerModemMux | Operator |  |  | ? (WRITES) |  | Control serial port mux |
| 0x1c | CmdSetSOLConfiguration | Operator |  |  | ? (WRITES) |  | Set SOL parameters |
| 0x21 | CmdSetSOLConfiguration (Dell) | Administrator | ✓ |  | ? (WRITES) |  | Dell-extended SOL config set |
| 0x22 | CmdGetSOLConfiguration | User |  |  | YES: 11 01 (ch1 param1=enable) |  | SOL enabled |

## NetFn 0x2e — OEM / Group (extended)

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x01 | 0x00174724 | User |  |  |  |  | OEM/Group command (Dell IANA 0x0002A2 prefix required) |
| 0x02 | 0x0017488c | User | ✓ |  |  |  | OEM/Group command |
| 0x03 | 0x00174c68 | Administrator | ✓ |  |  |  | OEM/Group command |
| 0x04 | 0x00175218 | Administrator |  |  |  |  | CmdPOSTEvent — POST event notification (confirmed symbol) |
| 0x07 | (Group Extension) | User | ✓ |  | ? |  | OEM/Group NetFn. First 3 bytes = IANA |
| 0x08 | (Group Extension) | User | ✓ |  | ? |  | OEM/Group NetFn command |
| 0x21 | 0x00188484 | Administrator |  |  |  |  | Stub/not-implemented (shared handler) |
| 0xcc | CmdOSAOEMCmdHandler | Callback | ✓ |  | YES: 0xC7 (needs data) |  | OSA OEM command handler |

## NetFn 0x30 — Dell OEM

| Cmd | Name | Priv | Sessionless | Stubbed | Live (R710) | Handler | Notes |
|-----|------|------|-------------|---------|-------------|---------|-------|
| 0x00 | CmdOEMGetChassisCapabilities | User |  | ✗ stubbed | No (0xC1) | `0x00063e1c` | Dell OEM chassis info / blade identification — NOT accessible on LAN or KCS |
| 0x01 | (MASER init area) | User |  | ✗ stubbed | No (0xC1) | `0x00060b90` | MASER/OSA initialization — NOT accessible on LAN |
| 0x02 | (OEM cmd) | Operator |  | ✗ stubbed | No (0xC1) | `0x00113684` | Dell OEM command 0x02 — NOT accessible on LAN |
| 0x04 | (near CmdOEMLockMASER) | Operator | ✓ | ✗ stubbed | No (0xC1) | `0x00063f1c` | MASER lock NOT available on LAN — KCS-only or firewall-blocked |
| 0x05 | CmdOEM Cmd 0x05 | Administrator | ✓ | ✗ stubbed | No (0xC1) | `0x00064074` | NOT accessible on LAN |
| 0x06 | (OEM cmd) | Operator | ✓ | ✗ stubbed | No (0xC1) | `0x00063d3c` | NOT accessible on LAN |
| 0x0a | (MASER area) | User |  | ✗ stubbed | No (0xC1) | `0x00060ce8` | MASER-area — NOT accessible on LAN |
| 0x18 | CmdGetBladeID area | User |  | ✗ stubbed | No (0xC1) | `0x00063afc` | NOT accessible on LAN |
| 0x1c | CmdOEMExtendedConfigure | Administrator | ✓ |  | Yes | `0x000a8384` | LIVE: 0xC7 (needs 4+ bytes). racadm extended config reserve/access |
| 0x20 | (OEM cmd) | User |  |  | Yes | `0x00064838` | LIVE: 0xC7 |
| 0x21 | (stub handler) | Administrator |  |  | — | `0x00188484` | LIVE: 0xC7. Stub 0x00188484 — accepts data but likely returns error |
| 0x22 | (OEM cmd) | User |  |  | Yes | `0x000c5fd8` | LIVE: returns empty (success) |
| 0x24 | (OEM cmd) | Administrator |  |  | Yes | `0x00189b54` | LIVE: 0xC7 |
| 0x25 | CmdOEMGetPwrCapEn? | User |  |  | Yes | `0x00189c24` | LIVE: returns 00 (power capping disabled) |
| 0x26 | CmdOEMResetPwrConsumptionDataCounters (near) | Administrator |  |  | Yes | `0x0005de00` | LIVE: 0xC7 |
| 0x27 | CmdOEMExtendedConfigure (get) | Administrator | ✓ |  | Yes | `0x000a7738` | LIVE: returns data with 4 bytes input. 0x27 grp 0x00 0x00 0x00 → racadm config b |
| 0x30 | (OEM cmd) | Administrator |  |  | Yes | `0x00065694` | LIVE: 0xC7 |
| 0x31 | (OEM cmd) | Administrator | ✓ |  | Yes | `0x000657c8` | LIVE: 0xC7 |
| 0x32 | (OEM cmd) | User |  |  | Yes | `0x000a8698` | LIVE: returns 00 |
| 0x33 | (OEM cmd) | User |  |  | Yes | `0x00065f5c` | LIVE: returns 01 00 01 |
| 0x37 | (OEM cmd) | User |  |  | No (0xC1) | `0x000639f0` | NOT PRESENT on LAN |
| 0x38 | (OEM cmd) | User |  |  | No (0xC1) | `0x0006396c` | NOT PRESENT on LAN |
| 0x39 | (OEM cmd) | User |  |  | No (0xC1) | `0x00063a74` | NOT PRESENT on LAN |
| 0x51 | (OEM cmd) | User |  |  | Yes | `0x00063674` | LIVE: returns 03 00 00 00 00 |
| 0x87 | (OEM cmd) | User |  |  | No (0xC1) | `0x00063b9c` | NOT PRESENT on LAN |
| 0x8b | CmdOEMCheckMASER_IPMIcmdStatus? | Operator |  |  | Yes | `0x000640fc` | LIVE: 0xC7 (needs >6 bytes) |
| 0x8c | (OEM cmd) | User |  |  | No (0xC1) | `0x00064abc` | NOT PRESENT on LAN |
| 0x8d | (OEM cmd) | Operator |  |  | Yes | `0x00064bac` | LIVE: 0xC7 |
| 0x9c | (OEM cmd) | User |  |  | Yes | `0x00066090` | LIVE: 0xC7 |
| 0x9d | (OEM cmd) | Operator |  |  | Yes | `0x0006612c` | LIVE: 0xC7 |
| 0xa0 | CmdOEMGetMASERAccessState | User |  |  | Yes | `0x0017531c` | LIVE: returns 00 (MASER unlocked/accessible) |
| 0xa1 | CmdOEMUnLockMASER | User | ✓ |  | Yes | `0x0007acfc` | LIVE: rsp=0x01 (no active MASER session). Confirmed symbol match |
| 0xa2 | CmdOEMvFlash / CmdOEMMASERPartitionAccess | User | ✓ |  | Yes | `0x0006fa18` | LIVE: rsp=0x01 (no active MASER session) |
| 0xa3 | CmdOEMPOST* (near CmdOEMPOSTGetBootVolLabel) | User | ✓ |  | Yes | `0x0007376c` | LIVE: 0xCC (data content wrong). Accessible on LAN but needs correct payload |
| 0xa4 | CmdOEMPOST* (near CmdOEMPOSTSetBIOSPassword) | User | ✓ |  | Yes | `0x000739e0` | LIVE: rsp=0x01 (no active MASER session) |
| 0xa5 | (OEM cmd) | User | ✓ |  | Yes | `0x00175a4c` | LIVE: rsp=0x01 (no active MASER session) |
| 0xa6 | CmdOEMPOSTMASERAccess (near) | User | ✓ |  | Yes | `0x00073ce0` | LIVE: 0xCC (data content wrong). Accessible on LAN |
| 0xa9 | CmdOEMPOSTSetBIOSPassword (near) | User | ✓ |  | Yes | `0x00072810` | LIVE: rsp=0x03 (Dell-specific error). Accessible on LAN — NOT KCS-only as predic |
| 0xaa | (OEM cmd) | User | ✓ |  | Yes | `0x00071134` | LIVE: rsp=0x01 (no active MASER session) |
| 0xab | (OEM cmd) | User | ✓ |  | Yes | `0x000716cc` | LIVE: 0xC7 |
| 0xac | (OEM cmd) | User | ✓ |  | Yes | `0x00071a78` | LIVE: rsp=0x01 (no active MASER session) |
| 0xad | CmdOEMGetMASERType | User | ✓ |  | Yes | `0x0007158c` | LIVE: returns 00 00 00 with 2-byte input. No SD card present |
| 0xae | (OEM cmd) | User | ✓ |  | Yes | `0x00071378` | LIVE: 0xC7 |
| 0xaf | (OEM cmd) | User | ✓ |  | Yes | `0x00071480` | LIVE: 0xC7 |
| 0xb0 | CmdOEMPwrAvgInterval / CmdOEMPwrCapEn area | User |  |  | Yes | `0x0005e704` | LIVE: 0xC7 (needs >1 byte) |
| 0xb3 | CmdOEMPwrAvgRange area | User |  |  | Yes | `0x0005e388` | LIVE: 0xC7 (needs >1 byte) |
| 0xb5 | DellCmdGetLCDInfo | User |  |  | Yes | `0x000a800c` | LIVE: returns empty (success) with 0x00 0x00. LCD info param 0 |
| 0xb6 | CmdOEMPwrHeadroom area | Operator |  |  | Yes | `0x0005f6e8` | LIVE: 0xC7 (needs >1 byte) |
| 0xb7 | CmdOEMGetPWRConsumptionData | User |  |  | Yes | `0x0005f82c` | LIVE: returns 00 with 0x0A 0x00. Power consumption param 0x0A |
| 0xb8 | (OEM cmd) | User |  |  | Yes | `0x00066214` | LIVE: 0xC7 |
| 0xb9 | (OEM cmd) | Administrator |  |  | Yes | `0x0006635c` | LIVE: 0xC7 |
| 0xba | Power area | User |  |  | Yes | `0x0005f908` | LIVE: 0xC7 |
| 0xbb | Power area | User |  |  | Yes | `0x0005f9fc` | LIVE: returns 0c 05 ca 04 |
| 0xbc | (OEM cmd) | Administrator | ✓ |  | Yes | `0x00066578` | LIVE: 0xC7 |
| 0xbe | (OEM cmd) | User | ✓ |  | No (0xC1) | `0x00066670` | NOT PRESENT on LAN |
| 0xbf | (OEM cmd) | User | ✓ |  | Yes | `0x000666b0` | LIVE: 0xC7 |
| 0xc0 | (OEM cmd) | User | ✓ |  | Yes | `0x000b367c` | LIVE: 0xC7 |
| 0xc1 | (OEM cmd) | Operator | ✓ |  | Yes | `0x00067634` | LIVE: 0xC7 |
| 0xc2 | (OEM cmd) | User |  |  | Yes | `0x00094bf4` | LIVE: 0xC7 |
| 0xc3 | (OEM cmd) | User | ✓ |  | Yes | `0x000646f0` | LIVE: 0xCC (right length but wrong content) |
| 0xc4 | (OEM cmd) | User | ✓ |  | Yes | `0x000b33e0` | LIVE: 0xC7 |
| 0xca | DelleKmsCmdHlder area | Administrator | ✓ |  | Yes | `0x00177d20` | LIVE: 0xC7→0xC1 at 6+ bytes. eKMS not enabled on this firmware |
| 0xcc | CmdOEMPowerConsumption area | User |  |  | Yes | `0x0005ed90` | LIVE: 0xCC at 4 bytes (right length, wrong sub-cmd) |
| 0xcd | Power area | User |  |  | Yes | `0x0005f608` | LIVE: 0xC7 |
| 0xd0 | CmdOEMDellFactory / MaserCmd area | Administrator |  |  | Yes | `0x000601e4` | LIVE: 0xC7. Reachable on LAN but needs correct payload |
| 0xd2 | (OEM cmd) | User | ✓ |  | Yes | `0x0017b830` | LIVE: returns empty (success) |
| 0xd4 | (OEM cmd) | User |  |  | Yes | `0x00060694` | LIVE: 0xC7 |

## Legend

- **Priv**: minimum privilege per dispatch table — Callback, User, Operator, Administrator, OEM, or Unspecified.
- **Sessionless**: cmd is reachable before opening an IPMI session (bit 7 of the dispatch descriptor byte).
- **Stubbed**: dispatch table override redirects this cmd to a shared 0xC1-returning stub. Functionally disabled on Dell.
- **Live (R710)**: response observed against Dell PowerEdge R710 / iDRAC6 1.70, 192.168.0.23 (probed 2026-04-06 and beyond).
- **Handler**: ARM little-endian address inside fullfw binary; useful for Ghidra cross-reference.
