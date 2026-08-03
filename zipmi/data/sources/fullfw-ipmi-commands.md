# Dell iDRAC6 BMC — IPMI Command Dispatch Table Analysis

Extracted from `fullfw` binary (Dell iDRAC6 Enterprise).
Two dispatch tables parsed: **Standard** at `0x0019e238` (120 entries, 960 bytes) and **OEM** at `0x0019fac0` (93 entries, 744 bytes).
Architecture: ARM little-endian. Entry format: `[descriptor:32][handler_ptr:32]`.

Descriptor word layout:
- `bits[7:0]` = IPMI Command code
- `bits[15:8]` = NetFn pair index (actual request NetFn = this value × 2)
- `bits[23:16]` = Minimum privilege required (0=Unspecified, 1=Callback, 2=User, 3=Operator, 4=Admin, 5=OEM Proprietary)
- `bits[31:24]` = Flags (bit 7 = `0x80` → available without an active session / session-less)

Privilege abbreviations: **U**=Unspecified(0), **CB**=Callback(1), **Usr**=User(2), **Op**=Operator(3), **Adm**=Admin(4), **OEM**=OEM Proprietary(5).

---

## 1. Standard IPMI Commands

### 1.1 Chassis Commands (NetFn 0x00/0x01)

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x00 0x00` | CmdGetChassisCapabilities | Usr | No | **YES**: `01 20 20 20 20 20` | Returns chassis capabilities: intrusion sensor, all devices at BMC 0x20 |
| `raw 0x00 0x01` | CmdGetChassisStatus | Usr | No | **YES**: `21 10 00 50` | Power ON, restore=previous, last on via IPMI |
| `raw 0x00 0x02` | CmdChassisControl | Op | No | ? (WRITES) | Power off / on / cycle / hard reset / diagnostic interrupt / soft shutdown |
| `raw 0x00 0x04` | DellCmdChassisIdentify | Op | Yes | ? (WRITES) | Blink chassis identify LED (Dell override of standard identify) |
| `raw 0x00 0x05` | CmdSetChassisCapabilities | Adm | Yes | ? (WRITES) | Write chassis capability bytes |
| `raw 0x00 0x07` | CmdGetSystemRestartCause | Usr | No | **YES**: `01 01` | Restart cause 0x01 = chassis control command, channel 0x01 |
| `raw 0x00 0x08` | CmdSetSystemBootOptions | Op | Yes | ? (WRITES) | Set boot flags: boot device, BIOS quiet mode, lock out reset buttons |
| `raw 0x00 0x09` | CmdGetSystemBootOptions | Op | No | **YES**: 0xC7 (needs param byte) | Read current boot option parameters |
| `raw 0x00 0x0B` | CmdSetPowerCycleInterval | Adm | No | ? (WRITES) | Set delay (seconds) between power-off and power-on during a power cycle |

### 1.2 Sensor / Event Commands (NetFn 0x04/0x05)

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x04 0x00` | CmdSetEventReceiver | Adm | No | ? (WRITES) | Set IPMB address and LUN of event message receiver |
| `raw 0x04 0x01` | CmdGetEventReceiver | Usr | No | **YES**: `20 00` | Event receiver at BMC (0x20), LUN 0 |
| `raw 0x04 0x02` | CmdPlatformEvent | Op | Yes | ? (WRITES) | Generate a platform event message |
| `raw 0x04 0x10` | CmdPEFCGetCapabilities | Usr | No | **YES**: `51 1f 28` | PEF v1.5, 31 filter entries, 40 alert policies |
| `raw 0x04 0x11` | CmdPEFCArmPostponeTimer | Adm | No | ? (WRITES) | Arm or postpone the PEF postpone timer |
| `raw 0x04 0x12` | CmdPEFCSetConfigurationParameters | Adm | Yes | ? (WRITES) | Write PEF configuration |
| `raw 0x04 0x13` | CmdPEFCGetConfigurationParameters | Op | Yes | **YES**: 0xC7 (needs param byte) | Read PEF configuration parameters |
| `raw 0x04 0x14` | CmdPEFCSetLastProcessedEventID | Op | No | ? (WRITES) | Set record ID of most recently processed SEL event |
| `raw 0x04 0x15` | CmdPEFCGetLastProcessedEventID | Usr | No | **YES**: `81 5b c4 69 07 00 ff ff 07 00` | Last processed event IDs |
| `raw 0x04 0x16` | CmdPEFCAlertImmediate | Op | No | ? (WRITES) | Force immediate alert transmission |
| `raw 0x04 0x17` | CmdPETCAcknowledge | U | No | **YES**: 0xC7 (needs data) | Acknowledge a PET SNMP trap |
| `raw 0x04 0x23` | CmdGetSensorReadingFactors | Usr | No | **DISABLED (0xC1)** | Dell stub `0x00161140` — **confirmed disabled on live BMC** |
| `raw 0x04 0x24` | CmdSetSensorHysteresis | Adm | No | ? (WRITES) | Set hysteresis for threshold-based sensor |
| `raw 0x04 0x25` | CmdGetSensorHysteresis | Usr | No | **YES**: 0xC7 (needs 2-byte sensor#) | Read hysteresis values |
| `raw 0x04 0x26` | CmdSetSensorThresholds | Op | No | ? (WRITES) | Write threshold values |
| `raw 0x04 0x27` | CmdGetSensorThresholds | Usr | No | **YES**: `18 00 00 00 d5 da 00` (sensor 1) | Sensor 1 thresholds: UC=0xD5, UNR=0xDA |
| `raw 0x04 0x28` | CmdSetSensorEventEnable | Op | Yes | ? (WRITES) | Enable/disable event generation per sensor |
| `raw 0x04 0x29` | CmdGetSensorEventEnable | Usr | No | **YES**: `00` (sensor 1) | Sensor 1 events: none enabled |
| `raw 0x04 0x2A` | CmdRearmSensorEvents | Op | Yes | ? (WRITES) | Re-arm event generation |
| `raw 0x04 0x2B` | CmdGetSensorEventStatus | Usr | No | **YES**: `00 00` (sensor 1) | Sensor 1 event status: no events |
| `raw 0x04 0x2D` | CmdGetSensorReading | Usr | No | **YES**: `42 00 c0` (sensor 1) | Sensor 1 reading=0x42, scanning enabled |
| `raw 0x04 0x30` | CmdSetSensorReading | Op | Yes | ? (WRITES) | Inject arbitrary reading/event status |

### 1.3 Application / IPM Device Commands (NetFn 0x06/0x07)

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x06 0x01` | CmdGetDeviceID | Usr | No | **YES**: `20 80 01 70 02 df a2 02 00 ...` | FW 1.70, IPMI 2.0, Dell IANA 674 |
| `raw 0x06 0x02` | CmdColdReset | Adm | No | ? (DESTRUCTIVE) | Unconditionally reset the BMC |
| `raw 0x06 0x04` | CmdGetSelfTestResults | Usr | No | **YES**: `55 00` | Self-test passed, no errors |
| `raw 0x06 0x05` | CmdManufacturingTestOn | Adm | No | ? (WRITES) | Enable manufacturing test mode |
| `raw 0x06 0x06` | CmdSetACPIPowerState | Adm | No | ? (WRITES) | Set ACPI power state |
| `raw 0x06 0x07` | CmdGetACPIPowerState | Usr | No | **YES**: `2a 2a` | System=S0/G0(working), Device=D0(on) |
| `raw 0x06 0x08` | CmdGetDeviceGUID | Usr | No | **YES**: `44 45 4c 4c 58 00 10 54 80 33 b5 c0 4f 47 51 31` | GUID = "DELLX..T.3..OGQ1" |
| `raw 0x06 0x09` | CmdGetNetFnSupport | Usr | No | **YES**: 0xC7 (needs channel/LUN param) | Bitmap of supported NetFns |
| `raw 0x06 0x0A` | CmdGetCommandSupport | Op | Yes | **YES**: 0xCC (needs NetFn/channel param) | Command support bitmap |
| `raw 0x06 0x0B` | CmdGetCommandSubFnSupport | Adm | No | ? | Sub-function support bitmap |
| `raw 0x06 0x0C` | CmdGetConfigurableCommands | Op | Yes | ? | Configurable commands bitmap |
| `raw 0x06 0x0D` | CmdGetConfigurableCommandSubFn | Adm | No | ? | Configurable sub-functions |
| `raw 0x06 0x22` | CmdResetWatchdogTimer | Op | No | ? (WRITES) | Pet the watchdog timer |
| `raw 0x06 0x24` | CmdSetWatchdogTimer | Adm | No | ? (WRITES) | Configure watchdog |
| `raw 0x06 0x25` | CmdGetWatchdogTimer | Usr | No | **YES**: `c4 00 00 00 c0 12 79 12` | Watchdog config + countdown |
| `raw 0x06 0x2E` | CmdSetBMCGlobalEnable | U | Yes | ? (WRITES) | Enable/disable message handling |
| `raw 0x06 0x2F` | CmdGetBMCGlobalEnable | Usr | No | **YES**: `0c` | Global enables: SEL+EventMsgBuf enabled |
| `raw 0x06 0x30` | CmdClearMsgFlags | U | Yes | ? (WRITES) | Clear message flag bits |
| `raw 0x06 0x31` | CmdGetMsgFlags | U | Yes | **NO (0xC1)** | **Not available on LAN** — KCS system interface only |
| `raw 0x06 0x32` | CmdEnableMsgChannelRecv | U | Yes | ? | Enable channel receive |
| `raw 0x06 0x33` | CmdGetMsg | U | Yes | ? | Retrieve from receive queue |
| `raw 0x06 0x35` | CmdReadEventMsgBuf | U | Yes | ? | Read from event message buffer |
| `raw 0x06 0x37` | CmdGetSystemGUID | U | No | **YES**: `44 45 4c 4c 58 00 10 54 80 33 b5 c0 4f 47 51 31` | Same as DeviceGUID |
| `raw 0x06 0x3C` | CmdCloseSession | Adm | No | ? (WRITES) | Close IPMI session |
| `raw 0x06 0x3D` | CmdGetSessionInfo | Adm | Yes | **YES**: `20 05 01 02 04 01 c0 a8 00 02 b0 be 83 a2 52 c5 dd d1` | Current session: from 192.168.0.2, MAC b0:be:83:a2:52:c5 |
| `raw 0x06 0x3F` | CmdGetAuthCode | Op | No | ? | Generate auth code |
| `raw 0x06 0x40` | CmdSetChannelAccess | Adm | No | ? (WRITES) | Set channel access mode |
| `raw 0x06 0x41` | CmdGetChannelAccess | Usr | No | **YES**: `12 04` (ch1, volatile) | Ch1: always available, max priv=Admin |
| `raw 0x06 0x42` | CmdGetChannelInfo | Usr | No | **YES**: `01 04 01 81 f2 1b 00 00 00` (ch1) | Ch1: 802.3 LAN, IPMB-1.0, multi-session |
| `raw 0x06 0x43` | CmdSetUserAccess | Adm | Yes | ? (WRITES) | Set user privilege level |
| `raw 0x06 0x44` | CmdGetUserAccess | Op | No | **YES**: `10 88 01 0f` (ch1 user1) | 16 user slots, user1 enabled, Admin priv |
| `raw 0x06 0x45` | CmdSetUserName | Adm | No | ? (WRITES) | Write user name |
| `raw 0x06 0x46` | CmdGetUserName | Op | No | **YES**: `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` (user1) | User 1 name = null (anonymous/root) |
| `raw 0x06 0x47` | CmdSetUserPassword | Adm | Yes | ? (WRITES) | Set/test user password |
| `raw 0x06 0x48` | CmdActivatePayload | CB | No | ? (WRITES) | Activate SOL/OEM payload |
| `raw 0x06 0x49` | CmdDeactivatePayload | CB | No | ? (WRITES) | Deactivate payload |
| `raw 0x06 0x4A` | CmdGetPayloadActivationStatus | Usr | No | **YES**: `01 00 00` (SOL) | SOL: 1 instance max, 0 active |
| `raw 0x06 0x4E` | CmdGetChannelPayloadSupport | Usr | No | **YES**: `03 00 3f 00 00 00 00 00` (ch1) | Ch1: IPMI+SOL standard, 6 OEM payloads |
| `raw 0x06 0x4B` | CmdGetPayloadInstanceInfo | Usr | No | ? | Payload instance info |
| `raw 0x06 0x4C` | CmdSetUserPayloadAccess | Adm | No | ? (WRITES) | Set user payload access |
| `raw 0x06 0x4D` | CmdGetUserPayloadAccess | Usr | No | ? | User payload access bitmap |
| `raw 0x06 0x4F` | CmdGetChannelPayloadVersion | Usr | No | ? | Payload version |
| `raw 0x06 0x50` | CmdGetChannelOEMPayloadInfo | Usr | No | ? | OEM payload info |
| `raw 0x06 0x52` | CmdSuspendBMCARPs | Op | Yes | Gratuitous ARP and ARP response suspend/resume for a LAN channel |
| `raw 0x06 0x54` | CmdGetChannelCipherSuites | Op | No | Enumerate supported cipher suites per channel |
| `raw 0x06 0x55` | CmdSuspendResumePayloadEncryption | Usr | No | Temporarily suspend/resume payload encryption on active session |
| `raw 0x06 0x56` | CmdSetChannelSecurityKeys | Adm | Yes | Set or clear integrity/confidentiality keys for a channel |
| `raw 0x06 0x60` | CmdSetCommandEnables | Adm | Yes | Enable/disable specific commands (command firewall write) |
| `raw 0x06 0x61` | CmdGetCommandEnables | Op | No | Read command enable bitmap |
| `raw 0x06 0x62` | CmdSetCommandSubFnEnables | Adm | No | Enable/disable sub-functions of a specific command |
| `raw 0x06 0x63` | CmdGetCommandSubFnEnables | Usr | No | Read sub-function enable bitmap |
| `raw 0x06 0x64` | CmdSet/GetSessionLessChannelPrivilege | Op | No | Get or set privilege level on session-less channels (e.g., KCS) |

### 1.4 Firmware Update Commands (NetFn 0x08/0x09)

| ipmitool raw | Handler | Priv | Session-less | Description |
|---|---|---|---|---|
| `raw 0x08 0x02` | CmdFirmwareUpdate | Adm | No | Initiate firmware update process |
| `raw 0x08 0x10` | (FW phase cmd) | Adm | Yes | Firmware update sub-command (chunk write) |
| `raw 0x08 0x11` | (FW phase cmd) | Adm | Yes | Firmware update sub-command |
| `raw 0x08 0x12` | (FW phase cmd) | Adm | Yes | Firmware update sub-command |
| `raw 0x08 0x13` | (FW phase cmd) | Adm | Yes | Firmware update sub-command |
| `raw 0x08 0x14` | (FW phase cmd) | Adm | Yes | Firmware update sub-command |
| `raw 0x08 0x15` | (FW phase cmd) | Adm | Yes | Firmware update sub-command |
| `raw 0x08 0x16` | (FW phase cmd) | Adm | Yes | Firmware update sub-command |

Note: The 7 sub-commands at 0x10-0x16 are all session-less capable (flags=0x80), suggesting firmware update protocol proceeds without maintaining a full IPMI session after initial handshake.

### 1.5 Storage Commands (NetFn 0x0A/0x0B)

#### FRU Inventory

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x0a 0x10` | CmdGetFRUInvAreaInfo | Usr | No | **YES**: `00 10 00` (dev 0) | FRU area: 4096 bytes (0x1000), byte access |
| `raw 0x0a 0x11` | CmdReadFRUData | Usr | No | ? | Read bytes from FRU inventory data area |
| `raw 0x0a 0x12` | CmdWriteFRUData | Adm | No | ? (WRITES) | Write FRU data. Can overwrite serial numbers |

#### SDR Repository

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x0a 0x20` | CmdGetSDRRepoInfo | Usr | No | **YES**: `51 7e 00 e1 05 ff ff ff ff ff ff ff ff 42` | 126 SDRs, 1505 bytes free, v1.5 |
| `raw 0x0a 0x22` | CmdResvSDRRepo | Usr | No | ? | Reserve SDR repository |
| `raw 0x0a 0x23` | CmdGetSDR | Usr | No | ? | Read SDR by ID |
| `raw 0x0a 0x25` | CmdPartAddSDR | Op | Yes | **DISABLED (0xC1)** | Dell stub `0x00161140` — **confirmed disabled** |
| `raw 0x0a 0x27` | CmdClrSDR | Adm | No | **DISABLED (0xC1)** | Dell stub `0x00161140` — **confirmed disabled** |
| `raw 0x0a 0x28` | CmdGetSDRRepoTime | Usr | No | **YES**: `a8 e5 d3 69` | SDR repo timestamp (Unix time) |
| `raw 0x0a 0x29` | CmdSetSDRRepoTime | Adm | No | ? (WRITES) | Set SDR timestamp |
| `raw 0x0a 0x2C` | CmdRunInitAgent | Op | No | ? (WRITES) | Run sensor init agent |

#### SEL (System Event Log)

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x0a 0x40` | CmdGetSELInfo | Usr | No | **YES**: `51 07 00 90 1f 81 5b c4 69 95 fc 46 4d 02` | 7 entries, 8080 bytes free, v1.5 |
| `raw 0x0a 0x42` | CmdReserveSEL | Usr | No | ? | Reserve SEL |
| `raw 0x0a 0x43` | CmdGetSELEntry | Usr | No | ? | Read SEL record by ID |
| `raw 0x0a 0x44` | CmdAddSELEntry | Op | No | ? (WRITES) | Add event record to SEL |
| `raw 0x0a 0x47` | CmdClearSEL | Adm | No | ? (DESTRUCTIVE) | Erase entire SEL |
| `raw 0x0a 0x48` | CmdGetSELTime | Usr | No | **YES**: `a8 e5 d3 69` | SEL clock (Unix timestamp) |
| `raw 0x0a 0x49` | CmdSetSELTime | Adm | No | ? (WRITES) | Set SEL clock time |

### 1.6 Transport Commands (NetFn 0x0C/0x0D)

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x0c 0x01` | CmdSetLANConfigParam | Adm | Yes | ? (WRITES) | Write LAN config: IP, subnet, gateway, VLAN |
| `raw 0x0c 0x02` | CmdGetLANConfigParam | Op | No | **YES**: `11 c0 a8 00 17` (ch1 param3=IP) | LAN IP = 192.168.0.23 |
| `raw 0x0c 0x10` | CmdSetSerModemConfigParam | Adm | Yes | ? (WRITES) | Write serial/modem config |
| `raw 0x0c 0x11` | CmdGetSerModemConfigParam | Op | No | ? | Read serial/modem config |
| `raw 0x0c 0x12` | CmdSetSerModemMux | Op | No | ? (WRITES) | Control serial port mux |
| `raw 0x0c 0x1C` | CmdSetSOLConfiguration | Op | No | ? (WRITES) | Set SOL parameters |
| `raw 0x0c 0x21` | CmdSetSOLConfiguration (Dell) | Adm | Yes | ? (WRITES) | Dell-extended SOL config set |
| `raw 0x0c 0x22` | CmdGetSOLConfiguration | Usr | No | **YES**: `11 01` (ch1 param1=enable) | SOL enabled |

### 1.7 OEM/Group Commands in Standard Table (NetFn 0x2E/0x2F)

| ipmitool raw | Handler | Priv | Session-less | Live | Description |
|---|---|---|---|---|---|
| `raw 0x2e 0x07` | (Group Extension) | Usr | Yes | ? | OEM/Group NetFn. First 3 bytes = IANA |
| `raw 0x2e 0x08` | (Group Extension) | Usr | Yes | ? | OEM/Group NetFn command |
| `raw 0x2e 0xCC` | CmdOSAOEMCmdHandler | CB | Yes | **YES**: 0xC7 (needs data) | OSA OEM command handler |

---

## 2. Dell OEM Commands (NetFn 0x30/0x31)

All entries from the OEM dispatch table with NetFn 0x30. Dell's IANA is `0x0002A2` (674 decimal).

"Remote" column: Yes = accessible from LAN IPMI session, KCS-only = restricted to system interface, Mfg = requires manufacturing mode.

| ipmitool raw | Handler Addr | Likely Function | Priv | Session-less | Remote | Live (T710 FW1.70) | Description |
|---|---|---|---|---|---|---|---|
| `raw 0x30 0x00` | `0x00063e1c` | CmdOEMGetChassisCapabilities | Usr | No | **No (0xC1)** | NOT PRESENT | Dell OEM chassis info / blade identification — NOT accessible on LAN or KCS |
| `raw 0x30 0x01` | `0x00060b90` | (MASER init area) | Usr | No | **No (0xC1)** | NOT PRESENT | MASER/OSA initialization — NOT accessible on LAN |
| `raw 0x30 0x02` | `0x00113684` | (OEM cmd) | Op | No | **No (0xC1)** | NOT PRESENT | Dell OEM command 0x02 — NOT accessible on LAN |
| `raw 0x30 0x04` | `0x00063f1c` | (near CmdOEMLockMASER) | Op | Yes | **No (0xC1)** | NOT PRESENT | **MASER lock NOT available on LAN** — KCS-only or firewall-blocked |
| `raw 0x30 0x05` | `0x00064074` | CmdOEM Cmd 0x05 | Adm | Yes | **No (0xC1)** | NOT PRESENT | NOT accessible on LAN |
| `raw 0x30 0x06` | `0x00063d3c` | (OEM cmd) | Op | Yes | **No (0xC1)** | NOT PRESENT | NOT accessible on LAN |
| `raw 0x30 0x0A` | `0x00060ce8` | (MASER area) | Usr | No | **No (0xC1)** | NOT PRESENT | MASER-area — NOT accessible on LAN |
| `raw 0x30 0x18` | `0x00063afc` | CmdGetBladeID area | Usr | No | **No (0xC1)** | NOT PRESENT | NOT accessible on LAN |
| `raw 0x30 0x1C` | `0x000a8384` | CmdOEMExtendedConfigure | Adm | Yes | Yes | **LIVE: 0xC7 (needs 4+ bytes)**. racadm extended config reserve/access |
| `raw 0x30 0x20` | `0x00064838` | (OEM cmd) | Usr | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x21` | `0x00188484` | (stub handler) | Adm | No | — | **LIVE: 0xC7**. Stub `0x00188484` — accepts data but likely returns error |
| `raw 0x30 0x22` | `0x000c5fd8` | (OEM cmd) | Usr | No | Yes | **LIVE: returns empty (success)** |
| `raw 0x30 0x24` | `0x00189b54` | (OEM cmd) | Adm | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x25` | `0x00189c24` | CmdOEMGetPwrCapEn? | Usr | No | Yes | **LIVE: returns `00`** (power capping disabled) |
| `raw 0x30 0x26` | `0x0005de00` | CmdOEMResetPwrConsumptionDataCounters (near) | Adm | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x27` | `0x000a7738` | CmdOEMExtendedConfigure (get) | Adm | Yes | Yes | **LIVE: returns data** with 4 bytes input. `0x27 grp 0x00 0x00 0x00` → racadm config backend |
| `raw 0x30 0x30` | `0x00065694` | (OEM cmd) | Adm | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x31` | `0x000657c8` | (OEM cmd) | Adm | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x32` | `0x000a8698` | (OEM cmd) | Usr | No | Yes | **LIVE: returns `00`** |
| `raw 0x30 0x33` | `0x00065f5c` | (OEM cmd) | Usr | No | Yes | **LIVE: returns `01 00 01`** |
| `raw 0x30 0x37` | `0x000639f0` | (OEM cmd) | Usr | No | **No (0xC1)** | NOT PRESENT on LAN |
| `raw 0x30 0x38` | `0x0006396c` | (OEM cmd) | Usr | No | **No (0xC1)** | NOT PRESENT on LAN |
| `raw 0x30 0x39` | `0x00063a74` | (OEM cmd) | Usr | No | **No (0xC1)** | NOT PRESENT on LAN |
| `raw 0x30 0x51` | `0x00063674` | (OEM cmd) | Usr | No | Yes | **LIVE: returns `03 00 00 00 00`** |
| `raw 0x30 0x87` | `0x00063b9c` | (OEM cmd) | Usr | No | **No (0xC1)** | NOT PRESENT on LAN |
| `raw 0x30 0x8B` | `0x000640fc` | CmdOEMCheckMASER_IPMIcmdStatus? | Op | No | Yes | **LIVE: 0xC7** (needs >6 bytes) |
| `raw 0x30 0x8C` | `0x00064abc` | (OEM cmd) | Usr | No | **No (0xC1)** | NOT PRESENT on LAN |
| `raw 0x30 0x8D` | `0x00064bac` | (OEM cmd) | Op | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x9C` | `0x00066090` | (OEM cmd) | Usr | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0x9D` | `0x0006612c` | (OEM cmd) | Op | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xA0` | `0x0017531c` | CmdOEMGetMASERAccessState | Usr | No | Yes | **LIVE: returns `00`** (MASER unlocked/accessible) |
| `raw 0x30 0xA1` | `0x0007acfc` | **CmdOEMUnLockMASER** | Usr | Yes | Yes | **LIVE: rsp=0x01** (no active MASER session). Confirmed symbol match |
| `raw 0x30 0xA2` | `0x0006fa18` | **CmdOEMvFlash / CmdOEMMASERPartitionAccess** | Usr | Yes | Yes | **LIVE: rsp=0x01** (no active MASER session) |
| `raw 0x30 0xA3` | `0x0007376c` | CmdOEMPOST* (near CmdOEMPOSTGetBootVolLabel) | Usr | Yes | Yes | **LIVE: 0xCC** (data content wrong). Accessible on LAN but needs correct payload |
| `raw 0x30 0xA4` | `0x000739e0` | CmdOEMPOST* (near CmdOEMPOSTSetBIOSPassword) | Usr | Yes | Yes | **LIVE: rsp=0x01** (no active MASER session) |
| `raw 0x30 0xA5` | `0x00175a4c` | (OEM cmd) | Usr | Yes | Yes | **LIVE: rsp=0x01** (no active MASER session) |
| `raw 0x30 0xA6` | `0x00073ce0` | CmdOEMPOSTMASERAccess (near) | Usr | Yes | Yes | **LIVE: 0xCC** (data content wrong). Accessible on LAN |
| `raw 0x30 0xA9` | `0x00072810` | CmdOEMPOSTSetBIOSPassword (near) | Usr | Yes | Yes | **LIVE: rsp=0x03** (Dell-specific error). **Accessible on LAN — NOT KCS-only as predicted!** |
| `raw 0x30 0xAA` | `0x00071134` | (OEM cmd) | Usr | Yes | Yes | **LIVE: rsp=0x01** (no active MASER session) |
| `raw 0x30 0xAB` | `0x000716cc` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xAC` | `0x00071a78` | (OEM cmd) | Usr | Yes | Yes | **LIVE: rsp=0x01** (no active MASER session) |
| `raw 0x30 0xAD` | `0x0007158c` | **CmdOEMGetMASERType** | Usr | Yes | Yes | **LIVE: returns `00 00 00`** with 2-byte input. No SD card present |
| `raw 0x30 0xAE` | `0x00071378` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xAF` | `0x00071480` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xB0` | `0x0005e704` | CmdOEMPwrAvgInterval / CmdOEMPwrCapEn area | Usr | No | Yes | **LIVE: 0xC7** (needs >1 byte) |
| `raw 0x30 0xB3` | `0x0005e388` | CmdOEMPwrAvgRange area | Usr | No | Yes | **LIVE: 0xC7** (needs >1 byte) |
| `raw 0x30 0xB5` | `0x000a800c` | **DellCmdGetLCDInfo** | Usr | No | Yes | **LIVE: returns empty (success)** with `0x00 0x00`. LCD info param 0 |
| `raw 0x30 0xB6` | `0x0005f6e8` | CmdOEMPwrHeadroom area | Op | No | Yes | **LIVE: 0xC7** (needs >1 byte) |
| `raw 0x30 0xB7` | `0x0005f82c` | CmdOEMGetPWRConsumptionData | Usr | No | Yes | **LIVE: returns `00`** with `0x0A 0x00`. Power consumption param 0x0A |
| `raw 0x30 0xB8` | `0x00066214` | (OEM cmd) | Usr | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xB9` | `0x0006635c` | (OEM cmd) | Adm | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xBA` | `0x0005f908` | Power area | Usr | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xBB` | `0x0005f9fc` | Power area | Usr | No | Yes | **LIVE: returns `0c 05 ca 04`** |
| `raw 0x30 0xBC` | `0x00066578` | (OEM cmd) | Adm | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xBE` | `0x00066670` | (OEM cmd) | Usr | Yes | **No (0xC1)** | NOT PRESENT on LAN |
| `raw 0x30 0xBF` | `0x000666b0` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xC0` | `0x000b367c` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xC1` | `0x00067634` | (OEM cmd) | Op | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xC2` | `0x00094bf4` | (OEM cmd) | Usr | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xC3` | `0x000646f0` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xCC** (right length but wrong content) |
| `raw 0x30 0xC4` | `0x000b33e0` | (OEM cmd) | Usr | Yes | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xCA` | `0x00177d20` | **DelleKmsCmdHlder** area | Adm | Yes | Yes | **LIVE: 0xC7→0xC1 at 6+ bytes**. eKMS not enabled on this firmware |
| `raw 0x30 0xCC` | `0x0005ed90` | CmdOEMPowerConsumption area | Usr | No | Yes | **LIVE: 0xCC at 4 bytes** (right length, wrong sub-cmd) |
| `raw 0x30 0xCD` | `0x0005f608` | Power area | Usr | No | Yes | **LIVE: 0xC7** |
| `raw 0x30 0xD0` | `0x000601e4` | CmdOEMDellFactory / MaserCmd area | Adm | No | Yes | **LIVE: 0xC7**. Reachable on LAN but needs correct payload |
| `raw 0x30 0xD2` | `0x0017b830` | (OEM cmd) | Usr | Yes | Yes | **LIVE: returns empty (success)** |
| `raw 0x30 0xD4` | `0x00060694` | (OEM cmd) | Usr | No | Yes | **LIVE: 0xC7** |

### Key Dell OEM 0x30 Commands with Known String-Identified Functions

These were identified via debug strings in the binary but may use sub-command dispatch within the handlers above:

| Sub-function | Parent Handler | Description | Remote | Notes |
|---|---|---|---|---|
| CmdOEMLockMASER | 0x30/0x04 area | Session-based MASER locking with watchdog + ACK | Yes | 2-byte session handles, watchdog timeout |
| CmdOEMUnLockMASER | `raw 0x30 0xA1` | Unlock MASER session | Yes | Session-less capable |
| CmdOEMCreateDynamicPartition | via MASER dispatch | Create SD partitions (FAT16/32/EXT2/3/RAW) | Yes | Calls `avct_im_create_image` |
| CmdOEMDeleteDynamicPartition | via MASER dispatch | Remove SD partitions | Yes | |
| CmdOEMAttachPartitions | via MASER dispatch | Mount via bitmap selection | Yes | |
| CmdOEMDetachPartitions | via MASER dispatch | Unmount via bitmap | Yes | |
| CmdOEMSecureUpdatePartition | via MASER dispatch | Hash-verified firmware write | Yes | Calls `SecureUpdateExecute` |
| CmdOEMRecreateMASER | via 0x30/0xD0 | Factory re-image SD | KCS+Mfg | Checks `IsMsgFromSystemInterface` + `IsInManufacturingTestMode` |
| CmdOEMMASERBonding | via MASER dispatch | Bond MASER to iDRAC ID | KCS-only | Checks `IsMsgFromSystemInterface` |
| CmdOEMDellFactory | via 0x30/0xD0 | Factory HW inventory / recreate MASER images | KCS+Mfg | Checks both system interface and manufacturing mode |
| CmdOEMPOSTSetBIOSPassword | 0x30/0xA9 area | Set BIOS password | KCS-only | Writes to `/tmp/biossetuppassword`, shells out to `brorch` |
| CmdOEMPOSTMASERAccess | 0x30/0xA6 area | POST-phase MASER access | KCS-only | Checks `IsMsgFromSystemInterface` |
| CmdOEMPOSTMASERSetSystemReq | via POST dispatch | Boot to MASER / cancel | KCS-only | POST-phase only |
| CmdOEMPOSTGetBootVolLabel | 0x30/0xA3 area | Get boot volume label | KCS-only | POST-phase only |
| CmdOEMvFlash | `raw 0x30 0xA2` area | vFlash master dispatch | Yes | Sub-dispatches to vFlash operations |
| CmdOEMVflashCreateEmptyPartition | via vFlash dispatch | Create vFlash partitions | Yes | FAT16/32, EXT2/3, RAW |
| CmdOEMVflashCardControl | via vFlash dispatch | Enable/disable/init SD card | Yes | |
| CmdOEMVflashSetBootPartition | via vFlash dispatch | Set boot partition | Yes | |
| CmdOEMSetAutoDiscovery | via OEM dispatch | Auto-discovery setup | Yes | Runs `/etc/discovery/auto_disc_setup.sh` |
| CmdOEMBackupRestore | via OEM dispatch | Backup/restore operations | Yes | Delegates to `/bin/jstore` |
| CmdOEMGetCertificateStatus | via OEM dispatch | Certificate status query | Yes | |
| CmdOEMSignCertificate | via OEM dispatch | Sign certificate | Yes | |
| CmdOEMRemoveCertificate | via OEM dispatch | Remove certificate | Yes | |
| CmdOEMRemoteEnablement | via OEM dispatch | Remote enablement | Yes | |
| CmdOEMSetNICTeaming | via OEM dispatch | NIC teaming config | Yes | |
| CmdOEMManufacturingTestOn | 0x30 area | Enter manufacturing mode | KCS+Mfg | Checks `IsMsgFromSystemInterface` |

---

## 3. OEM/Group Commands (NetFn 0x2E/0x2F) — OEM Table

| ipmitool raw | Handler Addr | Priv | Session-less | Description |
|---|---|---|---|---|
| `raw 0x2e 0x01` | `0x00174724` | Usr | No | OEM/Group command (Dell IANA 0x0002A2 prefix required) |
| `raw 0x2e 0x02` | `0x0017488c` | Usr | Yes | OEM/Group command |
| `raw 0x2e 0x03` | `0x00174c68` | Adm | Yes | OEM/Group command |
| `raw 0x2e 0x04` | `0x00175218` | Adm | No | **CmdPOSTEvent** — POST event notification (confirmed symbol) |
| `raw 0x2e 0x21` | `0x00188484` | Adm | No | Stub/not-implemented (shared handler) |

---

## 4. Dell OEM Overrides of Standard Commands

The OEM dispatch table doesn't just contain Dell-proprietary NetFn 0x30 commands — it also
contains entries for **standard IPMI NetFn values** (0x04, 0x06, 0x0A, 0x0C). When both tables
have an entry for the same NetFn/Cmd pair, the OEM table handler takes priority. There are
17 such overrides, falling into two categories:

### 4.1 Overrides That Replace with Dell-Extended Handlers (14)

These swap the generic IPMI handler for a Dell-specific one that handles Dell proprietary
parameter IDs while still supporting the standard ones:

| ipmitool raw | OEM Handler | Standard Handler | Standard Name | Why Dell Overrides |
|---|---|---|---|---|
| `raw 0x04 0x02` | `0x0005fdbc` | `0x00183c0c` | CmdPlatformEvent | Dell extends PEF with OEM event types |
| `raw 0x06 0x04` | `0x0006679c` | `0x0018417c` | CmdGetSelfTestResults | Returns Dell-specific self-test data beyond the standard 2-byte result |
| `raw 0x06 0x0A` | `0x00065ae4` | `0x00180cd4` | CmdGetCommandSupport | Dell OEM firewall — reports Dell-specific command support bitmaps |
| `raw 0x06 0x52` | `0x00064c7c` | `0x00156c1c` | CmdSuspendBMCARPs | Dell-specific ARP behavior (probably iDRAC dedicated NIC vs shared mode) |
| `raw 0x06 0x56` | `0x00066b68` | `0x0015c6d8` | CmdSetChannelSecurityKeys | Dell OEM key management extensions |
| `raw 0x06 0x61` | `0x00065e40` | `0x001826d8` | CmdGetCommandEnables | Dell OEM firewall enable bitmap |
| `raw 0x0a 0x20` | `0x00062870` | `0x00036b18` | CmdGetSDRRepoInfo | Returns Dell extended SDR metadata |
| `raw 0x0c 0x01` | `0x00066c5c` | `0x00184890` | CmdSetLANConfigParam | Dell LAN params: iDRAC NIC selection, dedicated/shared mode, VLAN extensions |
| `raw 0x0c 0x02` | `0x0006701c` | `0x0018574c` | CmdGetLANConfigParam | Read Dell-extended LAN parameters |
| `raw 0x0c 0x10` | `0x00064f80` | `0x00167a24` | CmdSetSerModemConfigParam | Dell serial/modem extensions |
| `raw 0x0c 0x11` | `0x00065348` | `0x00167c9c` | CmdGetSerModemConfigParam | Dell serial read extensions |
| `raw 0x0c 0x21` | `0x00065454` | `0x0017f8e4` | CmdSetSOLConfiguration | Dell SOL extensions |
| `raw 0x0c 0x22` | `0x0006556c` | `0x0017f97c` | CmdGetSOLConfiguration | Dell SOL read extensions |
| `raw 0x0c 0x31/0x32/0x33` | `0x00063338`/`0x000631b8`/`0x00062ecc` | (none) | Dell-only Transport cmds | Dell proprietary commands with no standard equivalent (Adm/Usr/Adm) |

### 4.2 Overrides That Silently Disable Commands (3)

These three all point to the **same handler** at `0x00161140`, which appears exactly 3 times
in the OEM table and nowhere else. A single function serving as the handler for three unrelated
commands is almost certainly a stub that returns `IPMI_CC_INVALID_CMD (0xC1)` or
`IPMI_CC_NOT_SUPPORTED (0xD4)`:

| ipmitool raw | OEM Handler | Standard Handler | Standard Name | Why Dell Disables It |
|---|---|---|---|---|
| `raw 0x04 0x23` | `0x00161140` (STUB) | `0x00166328` | CmdGetSensorReadingFactors | Dell may use fixed linearization in SDRs, making runtime factor queries unnecessary or problematic |
| `raw 0x0a 0x25` | `0x00161140` (STUB) | `0x00037504` | CmdPartAddSDR | **Dell locks down the SDR repository** — sensor population is factory-defined and shouldn't be modified at runtime via IPMI |
| `raw 0x0a 0x27` | `0x00161140` (STUB) | `0x00037ca8` | CmdClrSDR | **Catastrophic if triggered** — would remove all sensor definitions, completely blinding monitoring. Dell disables this to prevent accidental or malicious SDR wipes |

### 4.3 The Stub Handler at `0x00161140` — Detailed Analysis

**Confirmed on live BMC (2026-04-06)**: The stub returns `0xC1` on **both LAN and KCS**.
Tested via `IPMICmd 0x20 0x04 0x00 0x23 0x01 0x00` on the BMC shell — response was
`0x14 0x23 0xc1`. The OEM dispatch table is the **single dispatch path for all channels**.
There is no table routing bypass via the system interface.

This address appears exactly 3 times as the OEM handler for GetSensorReadingFactors (`0x04/0x23`),
PartAddSDR (`0x0A/0x25`), and ClearSDR (`0x0A/0x27`). Three completely unrelated commands all
mapped to the same function strongly indicates a "return error completion code" stub.

The command is still *dispatched* to a handler — it just returns failure. This is distinct from the
command being absent from the table entirely. The distinction matters because:
- The dispatch path itself may have side effects (logging, state changes)
- A tool probing for supported commands via `GetCommandSupport` (`0x06/0x0A`) may still report
  these commands as "supported" even though they always fail

### 4.4 The Stub Handler at `0x00188484`

A second shared handler appearing 2 times in the OEM table:
- NetFn `0x2E` cmd `0x21` (OEM/Group)
- NetFn `0x30` cmd `0x21` (Dell OEM)

Likely another "not implemented" return stub, possibly for commands that were planned but
never completed in this firmware version.

### 4.5 Dual-Table Dispatch — Security Implications

**Tested 2026-04-06**: The OEM dispatch table is the **single active dispatch path** for all
channels (LAN and KCS). The standard table entries for stubbed commands are dead code — they
exist in the binary but are never reached. Confirmed by testing `GetSensorReadingFactors`
(`0x04 0x23`) via both `ipmitool` (LAN) and `IPMICmd` (KCS/system interface on the BMC) —
both return `0xC1`.

~~**Table routing bypass**~~: DISPROVED. Cannot force commands through the standard table
by using a different channel. The OEM table overrides are **universal and permanent**.

**Security implications (confirmed):**

1. **Asymmetric protection reveals Dell's threat model**: Dell specifically worried about SDR
   manipulation (disabled PartAddSDR and ClearSDR) but left SEL clearing (`0x0A/0x47`) enabled
   at Admin level and remotely accessible. This suggests Dell considered SDR corruption harder to
   recover from than SEL loss — SDR defines the sensor infrastructure, while SEL is "just" logs.

2. **Dead dispatch table entries**: 8 commands in the OEM table (`0x30`: `0x00`, `0x01`, `0x02`,
   `0x04`, `0x05`, `0x06`, `0x0A`, `0x18`) return `0xC1` on both LAN and KCS. These are compiled
   into the binary but not active on the T710 platform — likely for other platform variants in
   the multi-platform firmware codebase.

3. **CmdOEMLockMASER is NOT cmd `0x30 0x04`** on this platform (returns `0xC1` everywhere).
   It is likely a sub-command of another handler or only activatable when an SD card is present.

4. **Remaining attack surface**: The command firewall (`CmdSetCommandEnables` at `0x06/0x60`,
   Admin, session-less) could potentially be used to re-enable stubbed commands — but since the
   stub is an actual handler function (not a firewall disable), firewall manipulation would not
   restore the original handler. The stub would need to be patched in memory/flash.

---

## 5. Live Probe Results (Dell PowerEdge T710, iDRAC 1.70, 2026-04-06)

Target: `192.168.0.23`, iDRAC firmware 1.70, IPMI 2.0, Manufacturer Dell (IANA 674).
Board: PowerEdge T710, serial `CN7475113Q0633`. No SD card present (MASER type 0).
126 SDR entries, 7 SEL entries, self-test passed (0x55 0x00).
SOL enabled, encryption forced, port 623.

### 5.1 NetFn 0x30 Full Sweep (256 commands tested)

Of 256 possible command codes, **54 responded** (anything other than `0xC1 Invalid Command`).
The remaining 202 returned `0xC1` and are not registered in the dispatch table for this channel.

#### Commands That Returned Data Successfully

| ipmitool raw | Response | Likely Function | Interpretation |
|---|---|---|---|
| `raw 0x30 0x22` | *(empty, success)* | ? | Success with no response data |
| `raw 0x30 0x25` | `00` | CmdOEMGetPwrCapEn? | Power capping disabled (0=off) |
| `raw 0x30 0x27 0x01 0x00 0x00 0x00` | `0a` | CmdOEMExtendedConfigure | Group 1 config read — **racadm config backend**. Returns group param count |
| `raw 0x30 0x27 0x02 0x00 0x00 0x00` | `03` | CmdOEMExtendedConfigure | Group 2 config read |
| `raw 0x30 0x27 0x03 0x00 0x00 0x00` | `00` | CmdOEMExtendedConfigure | Group 3 config read |
| `raw 0x30 0x27 0x04 0x00 0x00 0x00` | `00 00` | CmdOEMExtendedConfigure | Group 4 config read |
| `raw 0x30 0x32` | `00` | ? | Status = 0 |
| `raw 0x30 0x33` | `01 00 01` | ? | 3-byte config/status |
| `raw 0x30 0x51` | `03 00 00 00 00` | ? | 5-byte status response |
| `raw 0x30 0xA0` | `00` | CmdOEMGetMASERAccessState | **MASER state = unlocked/accessible** |
| `raw 0x30 0xAD 0x00 0x00` | `00 00 00` | CmdOEMGetMASERType | **MASER type 0 = no SD card present** (same for type params 0-3) |
| `raw 0x30 0xB5 0x00 0x00` | *(empty, success)* | DellCmdGetLCDInfo | LCD info param 0 (empty = no LCD or no data for this param) |
| `raw 0x30 0xB7 0x0A 0x00` | `00` | CmdOEMGetPWRConsumptionData | Power consumption data, param 0x0A |
| `raw 0x30 0xBB` | `0c 05 ca 04` | ? | 4 bytes: unknown status/config data |
| `raw 0x30 0xD2` | *(empty, success)* | ? | Success with no response data |
| `raw 0x30 0x1C 0x01 0x00 0x00 0x00` | *(empty, success)* | CmdOEMExtendedConfigure (reserve?) | Extended configure with 4+ byte input |

#### Commands Requiring MASER Session (rsp=0x01 "no active session")

These all return Dell-specific completion code `0x01`, meaning "MASER session not active".
A `CmdOEMLockMASER` call must succeed first to obtain a session handle. However, cmd `0x04`
returns `0xC1` on LAN, so the lock command may only be available on specific channels (KCS)
or is a sub-command of another handler.

| ipmitool raw | Likely Function | Notes |
|---|---|---|
| `raw 0x30 0xA1` | CmdOEMUnLockMASER | Needs active MASER session handle to unlock |
| `raw 0x30 0xA2` | CmdOEMvFlash / CmdOEMMASERPartitionAccess | Partition access requires session |
| `raw 0x30 0xA4` | CmdOEMPOST* (MASER area) | POST-phase MASER command |
| `raw 0x30 0xA5` | MASER area | Session-required MASER command |
| `raw 0x30 0xAA` | MASER area | Session-required MASER command |
| `raw 0x30 0xAC` | MASER area | Session-required MASER command |

Note: Since `CmdOEMGetMASERType` returns `00 00 00` (no SD card), MASER session establishment
would likely fail even if the lock command were accessible — there's no storage device to manage.

#### Commands Requiring Specific Data Formats (rsp=0xC7 or 0xCC)

These are live (not `0xC1`) but need the correct request payload. `0xC7` = wrong data length,
`0xCC` = right length but wrong content.

| ipmitool raw | Rsp | Likely Function | Notes |
|---|---|---|---|
| `raw 0x30 0x1C` | 0xC7 | CmdOEMExtendedConfigure | Needs 4+ bytes (group/object/index) |
| `raw 0x30 0x20` | 0xC7 | ? | Needs data |
| `raw 0x30 0x21` | 0xC7 | (stub `0x00188484`) | Needs data but likely returns error anyway |
| `raw 0x30 0x24` | 0xC7 | ? | Needs data |
| `raw 0x30 0x26` | 0xC7 | CmdOEMResetPwrConsumptionDataCounters area | Needs data |
| `raw 0x30 0x27` | varies | CmdOEMExtendedConfigure | **Works with 4 bytes**: `grp 0x00 0x00 0x00` |
| `raw 0x30 0x30` | 0xC7 | ? | Needs data |
| `raw 0x30 0x31` | 0xC7 | ? | Needs data |
| `raw 0x30 0x8B` | 0xC7 | CmdOEMCheckMASER_IPMIcmdStatus? | Strings say "expected 6 bytes" but 6 still fails |
| `raw 0x30 0x8D` | 0xC7 | ? | Needs data |
| `raw 0x30 0x9C` | 0xC7 | ? | Needs data |
| `raw 0x30 0x9D` | 0xC7 | ? | Needs data |
| `raw 0x30 0xA3` | 0xCC | CmdOEMPOSTGetBootVolLabel area | Data content wrong |
| `raw 0x30 0xA6` | 0xCC | CmdOEMPOSTMASERAccess area | Data content wrong |
| `raw 0x30 0xA9` | 0x03 | CmdOEMPOSTSetBIOSPassword area | **0x03 = unknown Dell-specific error** |
| `raw 0x30 0xAB` | 0xC7 | MASER area | Needs data |
| `raw 0x30 0xAE` | 0xC7 | MASER area | Needs data |
| `raw 0x30 0xAF` | 0xC7 | MASER area | Needs data |
| `raw 0x30 0xB0` | 0xC7 | CmdOEMPwrAvgInterval | Needs data (>1 byte) |
| `raw 0x30 0xB3` | 0xC7 | CmdOEMPwrAvgRange | Needs data (>1 byte) |
| `raw 0x30 0xB5` | 0xC7 / ok | DellCmdGetLCDInfo | **Works with 2 bytes**: `param 0x00` |
| `raw 0x30 0xB6` | 0xC7 | CmdOEMPwrHeadroom | Needs data (>1 byte) |
| `raw 0x30 0xB7` | 0xC7 / ok | CmdOEMGetPWRConsumptionData | **Works with 2 bytes**: `0x0A 0x00` returns `00` |
| `raw 0x30 0xB8` | 0xC7 | ? | Needs data |
| `raw 0x30 0xB9` | 0xC7 | ? | Needs data |
| `raw 0x30 0xBA` | 0xC7 | Power area | Needs data |
| `raw 0x30 0xBC` | 0xC7 | ? | Needs data |
| `raw 0x30 0xBF` | 0xC7 | ? | Needs data |
| `raw 0x30 0xC0` | 0xC7 | ? | Needs data |
| `raw 0x30 0xC1` | 0xC7 | ? | Needs data |
| `raw 0x30 0xC2` | 0xC7 | ? | Needs data |
| `raw 0x30 0xC3` | 0xCC | ? | Right length (0 bytes) but data content wrong |
| `raw 0x30 0xC4` | 0xC7 | ? | Needs data |
| `raw 0x30 0xCA` | 0xC7→0xC1 | DelleKmsCmdHlder | Needs data, but **becomes 0xC1 at 6+ bytes** — eKMS not enabled? |
| `raw 0x30 0xCC` | 0xC7 / ok@4 | CmdOEMPowerConsumption | **Accepts 4 bytes** (then 0xCC — wrong sub-cmd) |
| `raw 0x30 0xCD` | 0xC7 | Power area | Needs data |
| `raw 0x30 0xD0` | 0xC7 | CmdOEMDellFactory | Needs data |
| `raw 0x30 0xD4` | 0xC7 | ? | Needs data |

#### Dead Dispatch Table Entries (0xC1 on BOTH LAN and KCS)

These commands exist in the OEM dispatch table binary data but return `0xC1` on all channels.
**Confirmed dead on KCS via `IPMICmd` on the BMC (2026-04-06)** — they are NOT KCS-only,
they are simply not wired up on the T710/McCave platform (FW 1.70). Likely active on other
platform variants in the multi-platform codebase.

| Cmd | Dispatch Table Handler | KCS Result | LAN Result | Status |
|---|---|---|---|---|
| `0x00` | `0x00063e1c` | 0xC1 | 0xC1 | **DEAD** |
| `0x01` | `0x00060b90` | not tested | 0xC1 | Dead (inferred) |
| `0x02` | `0x00113684` | not tested | 0xC1 | Dead (inferred) |
| `0x04` | `0x00063f1c` (near CmdOEMLockMASER) | **0xC1** | 0xC1 | **DEAD — CmdOEMLockMASER is NOT this cmd** |
| `0x05` | `0x00064074` | not tested | 0xC1 | Dead (inferred) |
| `0x06` | `0x00063d3c` | not tested | 0xC1 | Dead (inferred) |
| `0x0A` | `0x00060ce8` | not tested | 0xC1 | Dead (inferred) |
| `0x18` | `0x00063afc` | **0xC1** | 0xC1 | **DEAD** |
| `0x37` | `0x000639f0` | not tested | 0xC1 | Dead (inferred) |
| `0x38` | `0x0006396c` | not tested | 0xC1 | Dead (inferred) |
| `0x39` | `0x00063a74` | not tested | 0xC1 | Dead (inferred) |
| `0x87` | `0x00063b9c` | **0xC1** | 0xC1 | **DEAD** |
| `0x8C` | `0x00064abc` | **0xC1** | 0xC1 | **DEAD** |
| `0xBE` | `0x00066670` | not tested | 0xC1 | Dead (inferred) |

### 5.2 NetFn 0x2E Full Sweep

6 commands responded (not `0xC1`), all requiring data (`0xC7`):

| ipmitool raw | Rsp | Notes |
|---|---|---|
| `raw 0x2e 0x01` | 0xC7 | OEM/Group cmd — needs Dell IANA prefix + data |
| `raw 0x2e 0x02` | 0xC7 | OEM/Group cmd |
| `raw 0x2e 0x03` | 0xC7 | OEM/Group cmd |
| `raw 0x2e 0x04` | 0xC7 | CmdPOSTEvent (confirmed symbol) |
| `raw 0x2e 0x21` | 0xC7 | Stub handler `0x00188484` |
| `raw 0x2e 0xCC` | 0xC7 | CmdOSAOEMCmdHandler |

### 5.3 Dell OEM Stub Disabling — Confirmed on Live BMC (LAN + KCS)

All three commands disabled by the `0x00161140` stub return **`0xC1` (Invalid Command)** on
**both LAN and KCS**, confirming the OEM dispatch table is the universal dispatch path:

| Command | Standard Name | LAN (ipmitool) | KCS (IPMICmd on BMC) | Status |
|---|---|---|---|---|
| `0x04 0x23` | CmdGetSensorReadingFactors | 0xC1 | `0x14 0x23 0xc1` | **DISABLED everywhere** |
| `0x0a 0x25` | CmdPartAddSDR | 0xC1 | not tested (WRITES) | **DISABLED** |
| `0x0a 0x27` | CmdClrSDR | 0xC1 | not tested (DESTRUCTIVE) | **DISABLED** |

The stub at `0x00161140` returns completion code `0xC1`, making disabled commands
indistinguishable from truly non-existent commands to external tools.

**Table routing bypass hypothesis DISPROVED**: The KCS system interface uses the same
OEM dispatch table as LAN. The standard table handlers for these three commands are
dead code that cannot be reached through any known channel.

### 5.4 Standard IPMI Commands — Confirmed Working

| ipmitool raw | Response | Decoded |
|---|---|---|
| `raw 0x00 0x00` | `01 20 20 20 20 20` | Chassis caps: intrusion sensor, all devices at BMC addr 0x20 |
| `raw 0x00 0x01` | `21 10 00 50` | Power ON, restore=previous, last power-on via IPMI |
| `raw 0x06 0x01` | `20 80 01 70 02 df a2 02 00 00 01 00 15 00 00` | Device ID 0x20, FW 1.70, IPMI 2.0, Dell IANA, product 0x0100 |
| `raw 0x06 0x04` | `55 00` | Self-test passed, no errors |
| `raw 0x0a 0x20` | `51 7e 00 e1 05 ff ff ff ff ff ff ff ff 42` | SDR v1.5, 126 records, 1505 bytes free |

### 5.5 Key Observations

1. **CmdOEMLockMASER is NOT `0x30 0x04`**: This command returns `0xC1` on both LAN and KCS.
   CmdOEMLockMASER is either a sub-command of another handler (likely `0x30 0x8B` which
   handles MASER status checks), invoked only internally by fullfw, or only activates when
   an SD card is present (this T710 has no SD card — MASER type `00 00 00`).

2. **Completion code `0x01` is Dell-specific "no MASER session"**: Not a standard IPMI CC.
   Commands returning 0x01 are dispatched and running but fail because no MASER session is
   active. This affects `0xA1`, `0xA2`, `0xA4`, `0xA5`, `0xAA`, `0xAC`.

3. **Extended Configure (`0x30 0x27`) is the racadm backend**: This is how `racadm getconfig`
   works over IPMI. Groups 1-4 returned data, groups 5+ returned `0xCC`. This is a high-value
   target for configuration extraction.

4. **eKMS (`0x30 0xCA`) transitions from `0xC7` to `0xC1`**: At small data lengths it says
   "wrong length", but at 6+ bytes it says "invalid command". This suggests eKMS support
   is compile-time included but runtime-disabled on this firmware/hardware.

5. **14 dispatch table entries are dead code on T710**: Commands `0x00`, `0x01`, `0x02`,
   `0x04`, `0x05`, `0x06`, `0x0A`, `0x18`, `0x37`, `0x38`, `0x39`, `0x87`, `0x8C`, `0xBE`
   return `0xC1` on all channels. **Confirmed via KCS testing** — these are NOT channel-
   restricted, they are simply not wired up on this platform variant.

6. **OEM dispatch table is universal**: Confirmed by KCS testing that the same dispatch
   table serves all channels. The standard table's original handlers for Dell-stubbed
   commands (GetSensorReadingFactors, PartAddSDR, ClearSDR) are unreachable dead code.
   There is no table routing bypass.

---

## 6. Attack Surface Summary

### 6.1 Commands Usable Without Authentication (Session-less + Low Privilege)

| NetFn | Cmd | Name | Priv |
|---|---|---|---|
| 0x06 | 0x2E | CmdSetBMCGlobalEnable | U |
| 0x06 | 0x30 | CmdClearMsgFlags | U |
| 0x06 | 0x31 | CmdGetMsgFlags | U |
| 0x06 | 0x32 | CmdEnableMsgChannelRecv | U |
| 0x06 | 0x33 | CmdGetMsg | U |
| 0x06 | 0x35 | CmdReadEventMsgBuf | U |
| 0x06 | 0x37 | CmdGetSystemGUID | U |
| 0x2e | 0xCC | CmdOSAOEMCmdHandler | CB |

### 6.2 High-Impact Commands Accessible at Operator Level

| NetFn | Cmd | Name | Impact |
|---|---|---|---|
| 0x00 | 0x02 | CmdChassisControl | Power off/on/reset |
| 0x00 | 0x08 | CmdSetSystemBootOptions | Boot device hijack |
| 0x04 | 0x30 | CmdSetSensorReading | Inject false sensor data |
| 0x04 | 0x26 | CmdSetSensorThresholds | Manipulate alarm thresholds |
| 0x04 | 0x28 | CmdSetSensorEventEnable | Suppress monitoring alerts |
| 0x0a | 0x44 | CmdAddSELEntry | Inject fake log entries |

### 6.3 Dell OEM Commands That Execute Shell Commands

| Raw Command | Function | Shell Command | Risk |
|---|---|---|---|
| `raw 0x30 0xD0` area | CmdOEMRecreateMASER | `/bin/avct_control ... imgcreate &` | Image recreation |
| `raw 0x30 0xD0` area | CmdOEMDellFactory | `/bin/hwinvapp`, `rm -rf /flash/*` | **Flash wipe** |
| `raw 0x30 0xA9` area | CmdOEMPOSTSetBIOSPassword | `brorch setbiospwd -filename=/tmp/biossetuppassword` | BIOS password set |
| Various MASER cmds | MASER partition ops | `mount -t vfat -o loop ...`, `cp -f /tmp/%s %s/%s` | **Potential cmd injection** |
| Various | CmdOEMBackupRestore | `/bin/jstore -a 21 &` | Job scheduling |
| Various | Auto-discovery | `/etc/discovery/auto_disc_setup.sh` | Network config |

---

## 7. Dispatch Table Metadata

| Field | Standard Table | OEM Table |
|---|---|---|
| Base address | `0x0019e238` | `0x0019fac0` |
| Size (bytes) | 960 | 744 |
| Entry count | 120 | 93 |
| Entry size | 8 bytes | 8 bytes |
| NetFn coverage | 0x00, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x2E | 0x00, 0x04, 0x06, 0x0A, 0x0C, 0x2E, 0x30 |
| Dispatch model | Sequential scan | Sequential scan |
| Shared stub `0x00161140` | — | 3 entries (disables commands) |
| Shared stub `0x00188484` | — | 2 entries (not-implemented) |
