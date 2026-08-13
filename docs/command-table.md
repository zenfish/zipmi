# IPMI Command Status Table — zipmi vs real BMCs

Modeled on **Table G-1, Command Number Assignments and Privilege Levels**
(IPMI 2.0 spec, Appendix G). Adds columns for zipmi implementation status
and per-platform live test results.

> **Coverage: zipmi implements 63 of 188 standard IPMI commands** — 34 fully
> decoded (✓, field-level encode/decode) + 29 raw-wired (⚡, sent by a verb,
> response as bytes). 125 are not implemented (✗) — though any command is still
> reachable by name via `zipmi ipmi <name>` / `zipmi raw`. Per-NetFn breakdown
> sits at the top of each section below.

## Legend

**zipmi column:**

| Symbol | Meaning |
|--------|---------|
| ✓ | Full Packet class registered in `CMD_PAYLOADS`; field-level encode + decode |
| ⚡ | Works via `zipmi raw` (NetFn/cmd accepted, response returned as raw bytes) |
| ✗ | Not implemented |

**Per-platform columns (R710, X11SSZ, …):**

| Symbol | Meaning |
|--------|---------|
| ✓ | Tested live, returns expected response |
| ✗ | Tested live, returns error / unsupported / 0xC1 InvalidCommand |
| ? | Not yet tested |
| — | Not applicable to this device class |

**Privilege column** (matches spec G-1):

| Symbol | Meaning |
|--------|---------|
| C | Callback |
| U | User |
| O | Operator |
| A | Administrator |
| O\* | Operator + privilege-checking caveat |
| s | Sessionless |
| -- | privilege not constrained / N/A |

---

## App NetFn (0x06)

**68 commands · 39 done by zipmi** — ✓ 19 decoded, ⚡ 20 raw · ✗ 29 not implemented.
Done: Get Device ID, Cold Reset, Warm Reset, Get Self Test Results, Get Device GUID, Get System GUID, Get Channel Authentication Capabilities, Get Session Challenge, Activate Session, Set Session Privilege Level, Close Session, Get Channel Access, Get Channel Info Command, Get User Access Command, Get User Name Command, Activate Payload, Deactivate Payload, Get Payload Activation Status, Get Channel Cipher Suites, Get NetFn Support, Get Command Support, Get Command Sub-function Support, Get Configurable Commands, Get Command Enables, Get Command Sub-function Enables, Reset Watchdog Timer, Set Watchdog Timer, Get Watchdog Timer, Get Message Flags, Get Message, Send Message, Get Session Info, Set User Access Command, Set User Name, Set User Password Command, Set User Payload Access, Get User Payload Access, Master Read-Write, Get System Interface Capabilities


### IPM Device "Global" Commands

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 00h  | Reserved | — | — | — | — | — |
| 01h  | Get Device ID | 20.1 | s | ✓ | ✓ | ? |
| 01h  | Broadcast Get Device ID | 20.9 | s | ✗ | ? | ? |
| 02h  | Cold Reset | 20.2 | A | ✓ | ? | ? |
| 03h  | Warm Reset | 20.3 | A | ✓ | ? | ? |
| 04h  | Get Self Test Results | 20.4 | U | ✓ | ✓ | ? |
| 05h  | Manufacturing Test On | 20.5 | A | ✗ | ? | ? |
| 06h  | Set ACPI Power State | 20.6 | A | ✗ | ? | ? |
| 07h  | Get ACPI Power State | 20.7 | U | ✗ | ? | ? |
| 08h  | Get Device GUID | 20.8 | U | ✓ | ✓ | ? |
| 09h  | Get NetFn Support | 21.2 | A | ⚡ | ? | ? |
| 0Ah  | Get Command Support | 21.3 | A | ⚡ | ? | ? |
| 0Bh  | Get Command Sub-function Support | 21.4 | A | ⚡ | ? | ? |
| 0Ch  | Get Configurable Commands | 21.5 | A | ⚡ | ? | ? |
| 0Dh  | Get Configurable Command Sub-functions | 21.6 | A | ✗ | ? | ? |
| 60h  | Set Command Enables | 21.7 | A | ✗ | ? | ? |
| 61h  | Get Command Enables | 21.8 | A | ⚡ | ? | ? |
| 62h  | Set Command Sub-function Enables | 21.9 | A | ✗ | ? | ? |
| 63h  | Get Command Sub-function Enables | 21.10 | A | ⚡ | ? | ? |
| 64h  | Get OEM NetFn IANA Support | 21.11 | A | ✗ | ? | ? |

### BMC Watchdog Timer Commands

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 22h  | Reset Watchdog Timer | 27.5 | O | ⚡ | ? | ? |
| 24h  | Set Watchdog Timer   | 27.6 | O | ⚡ | ? | ? |
| 25h  | Get Watchdog Timer   | 27.7 | U | ⚡ | ? | ? |

### BMC Device and Messaging Commands

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 2Eh  | Set BMC Global Enables | 22.1 | A | ✗ | ? | ? |
| 2Fh  | Get BMC Global Enables | 22.2 | U | ✗ | ? | ? |
| 30h  | Clear Message Flags | 22.3 | A | ✗ | ? | ? |
| 31h  | Get Message Flags | 22.4 | A | ⚡ | ? | ? |
| 32h  | Enable Message Channel Receive | 22.5 | A | ✗ | ? | ? |
| 33h  | Get Message | 22.6 | A | ⚡ | ? | ? |
| 34h  | Send Message | 22.7 | A* | ⚡ | ? | ? |
| 35h  | Read Event Message Buffer | 22.8 | A | ✗ | ? | ? |
| 36h  | Get BT Interface Capabilities | 22.10 | U | ✗ | ? | ? |
| 37h  | Get System GUID | 22.14 | U | ✓ | ✓ | ? |
| 58h  | Set System Info Parameters | 22.14a | A | ✗ | ? | ? |
| 59h  | Get System Info Parameters | 22.14b | U | ✗ | ? | ? |
| 38h  | Get Channel Authentication Capabilities | 22.13 | s | ✓ | ✓ | ? |
| 39h  | Get Session Challenge | 22.15 | s | ✓ | ✓ | ? |
| 3Ah  | Activate Session | 22.17 | s | ✓ | ✓ | ? |
| 3Bh  | Set Session Privilege Level | 22.18 | U | ✓ | ✓ | ? |
| 3Ch  | Close Session | 22.19 | C | ✓ | ✓ | ? |
| 3Dh  | Get Session Info | 22.20 | U | ⚡ | ? | ? |
| 3Fh  | Get AuthCode | 22.21 | U | ✗ | ? | ? |
| 40h  | Set Channel Access | 22.22 | A | ✗ | ? | ? |
| 41h  | Get Channel Access | 22.23 | U | ✓ | ? | ? |
| 42h  | Get Channel Info Command | 22.24 | U | ✓ | ? | ? |
| 43h  | Set User Access Command | 22.26 | A | ⚡ | ? | ? |
| 44h  | Get User Access Command | 22.27 | O | ✓ | ✓ | ? |
| 45h  | Set User Name | 22.28 | A | ⚡ | ? | ? |
| 46h  | Get User Name Command | 22.29 | O | ✓ | ✓ | ? |
| 47h  | Set User Password Command | 22.30 | A | ⚡ | ? | ? |
| 48h  | Activate Payload | 24.1 | U/O | ✓ | ? | ? |
| 49h  | Deactivate Payload | 24.2 | U/O | ✓ | ? | ? |
| 4Ah  | Get Payload Activation Status | 24.3 | U | ✓ | ? | ? |
| 4Bh  | Get Payload Instance Info | 24.4 | U | ✗ | ? | ? |
| 4Ch  | Set User Payload Access | 24.5 | A | ⚡ | ? | ? |
| 4Dh  | Get User Payload Access | 24.6 | O | ⚡ | ? | ? |
| 4Eh  | Get Channel Payload Support | 24.7 | U | ✗ | ? | ? |
| 4Fh  | Get Channel Payload Version | 24.8 | U | ✗ | ? | ? |
| 50h  | Get Channel OEM Payload Info | 24.9 | U | ✗ | ? | ? |
| 52h  | Master Read-Write | 22.11 | A* | ⚡ | ? | ? |
| 54h  | Get Channel Cipher Suites | 22.15 | s | ✓ | ? | ? |
| 55h  | Suspend/Resume Payload Encryption | 24.10 | U | ✗ | ? | ? |
| 56h  | Set Channel Security Keys | 22.25 | A | ✗ | ? | ? |
| 57h  | Get System Interface Capabilities | 22.9 | U | ⚡ | ? | ? |
| 5Ah  | Get Authorization Privilege Level | 22.x | s | ✗ | ? | ? |
| 5Bh  | Get Authentication Capabilities (v2) | 22.x | s | ✗ | ? | ? |
| 5Ch  | Get Session-Less Channel Privilege Level | 22.x | s | ✗ | ? | ? |
| 5Dh  | Set Session-Less Channel Privilege Level | 22.x | s | ✗ | ? | ? |
| 5Eh  | Get Session-Less Channel Auth Caps | 22.x | s | ✗ | ? | ? |

---

## Chassis NetFn (0x00)

**13 commands · 7 done by zipmi** — ✓ 4 decoded, ⚡ 3 raw · ✗ 6 not implemented.
Done: Get Chassis Status, Chassis Control, Set System Boot Options, Get System Boot Options, Chassis Identify, Set Power Restore Policy, Get System Restart Cause


| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 00h  | Get Chassis Capabilities | 28.1 | U | ✗ | ? | ? |
| 01h  | Get Chassis Status | 28.2 | U | ✓ | ✓ | ? |
| 02h  | Chassis Control | 28.3 | O | ✓ | ? (untested destructive) | ? |
| 03h  | Chassis Reset | 28.4 | O | ✗ | ? | ? |
| 04h  | Chassis Identify | 28.5 | O | ⚡ | ? | ? |
| 05h  | Set Chassis Capabilities | 28.7 | A | ✗ | ? | ? |
| 06h  | Set Power Restore Policy | 28.8 | A | ⚡ | ? | ? |
| 07h  | Get System Restart Cause | 28.11 | U | ⚡ | ? | ? |
| 08h  | Set System Boot Options | 28.12 | A | ✓ | ? (untested writeable) | ? |
| 09h  | Get System Boot Options | 28.13 | U | ✓ | ✓ | ? |
| 0Ah  | Set Front Panel Button Enables | 28.6 | A | ✗ | ? | ? |
| 0Bh  | Set Power Cycle Interval | 28.9 | A | ✗ | ? | ? |
| 0Fh  | Get POH Counter | 28.14 | U | ✗ | ? | ? |

---

## Sensor / Event NetFn (0x04)

**27 commands · 1 done by zipmi** — ✓ 1 decoded, ⚡ 0 raw · ✗ 26 not implemented.
Done: Get Sensor Reading


| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 00h  | Set Event Receiver | 29.1 | A | ✗ | ? | ? |
| 01h  | Get Event Receiver | 29.2 | U | ✗ | ? | ? |
| 02h  | Platform Event Message | 29.3 | O | ✗ | ? | ? |
| 10h  | Get PEF Capabilities | 30.1 | U | ✗ | ? | ? |
| 11h  | Arm PEF Postpone Timer | 30.2 | A | ✗ | ? | ? |
| 12h  | Set PEF Configuration Parameters | 30.3 | A | ✗ | ? | ? |
| 13h  | Get PEF Configuration Parameters | 30.4 | U | ✗ | ? | ? |
| 14h  | Set Last Processed Event ID | 30.5 | A | ✗ | ? | ? |
| 15h  | Get Last Processed Event ID | 30.6 | A | ✗ | ? | ? |
| 16h  | Alert Immediate | 30.7 | O | ✗ | ? | ? |
| 17h  | PET Acknowledge | 30.8 | s | ✗ | ? | ? |
| 20h  | Get Device SDR Info | 35.2 | U | ✗ | ? | ? |
| 21h  | Get Device SDR | 35.3 | U | ✗ | ? | ? |
| 22h  | Reserve Device SDR Repository | 35.4 | U | ✗ | ? | ? |
| 23h  | Get Sensor Reading Factors | 35.5 | U | ✗ | ? | ? |
| 24h  | Set Sensor Hysteresis | 35.6 | O | ✗ | ? | ? |
| 25h  | Get Sensor Hysteresis | 35.7 | U | ✗ | ? | ? |
| 26h  | Set Sensor Threshold | 35.8 | O | ✗ | ? | ? |
| 27h  | Get Sensor Threshold | 35.9 | U | ✗ | ? | ? |
| 28h  | Set Sensor Event Enable | 35.10 | O | ✗ | ? | ? |
| 29h  | Get Sensor Event Enable | 35.11 | U | ✗ | ? | ? |
| 2Ah  | Re-arm Sensor Events | 35.12 | O | ✗ | ? | ? |
| 2Bh  | Get Sensor Event Status | 35.13 | U | ✗ | ? | ? |
| 2Dh  | Get Sensor Reading | 35.14 | U | ✓ | ✓ | ? |
| 2Eh  | Set Sensor Type | 35.16 | O | ✗ | ? | ? |
| 2Fh  | Get Sensor Type | 35.17 | U | ✗ | ? | ? |
| 30h  | Set Sensor Reading And Event Status | 35.15 | O | ✗ | ? | ? |

---

## Storage NetFn (0x0A)

**30 commands · 11 done by zipmi** — ✓ 7 decoded, ⚡ 4 raw · ✗ 19 not implemented.
Done: Get FRU Inventory Area Info, Get SDR Repository Info, Reserve SDR Repository, Get SDR, Get SEL Info, Reserve SEL, Get SEL Entry, Read FRU Data, Clear SEL, Get SEL Time, Set SEL Time


### FRU Inventory

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 10h  | Get FRU Inventory Area Info | 34.1 | U | ✓ | ? | ? |
| 11h  | Read FRU Data | 34.2 | O | ⚡ | ? | ? |
| 12h  | Write FRU Data | 34.3 | O | ✗ | ? | ? |

### SDR Repository

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 20h  | Get SDR Repository Info | 33.9 | U | ✓ | ✓ | ? |
| 21h  | Get SDR Repository Allocation Info | 33.10 | U | ✗ | ? | ? |
| 22h  | Reserve SDR Repository | 33.11 | U | ✓ | ✓ | ? |
| 23h  | Get SDR | 33.12 | U | ✓ | ✓ (chunked reads required) | ? |
| 24h  | Add SDR | 33.13 | A | ✗ | ? | ? |
| 25h  | Partial Add SDR | 33.14 | A | ✗ | ? | ? |
| 26h  | Delete SDR | 33.15 | O | ✗ | ? | ? |
| 27h  | Clear SDR Repository | 33.16 | O | ✗ | ? | ? |
| 28h  | Get SDR Repository Time | 33.17 | U | ✗ | ? | ? |
| 29h  | Set SDR Repository Time | 33.18 | A | ✗ | ? | ? |
| 2Ah  | Enter SDR Repository Update Mode | 33.19 | A | ✗ | ? | ? |
| 2Bh  | Exit SDR Repository Update Mode | 33.20 | A | ✗ | ? | ? |
| 2Ch  | Run Initialization Agent | 33.21 | A | ✗ | ? | ? |

### SEL

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 40h  | Get SEL Info | 31.2 | U | ✓ | ✓ | ? |
| 41h  | Get SEL Allocation Info | 31.3 | U | ✗ | ? | ? |
| 42h  | Reserve SEL | 31.4 | U | ✓ | ✓ | ? |
| 43h  | Get SEL Entry | 31.5 | U | ✓ | ✓ | ? |
| 44h  | Add SEL Entry | 31.6 | O | ✗ | ? | ? |
| 45h  | Partial Add SEL Entry | 31.7 | O | ✗ | ? | ? |
| 46h  | Delete SEL Entry | 31.8 | O | ✗ | ? | ? |
| 47h  | Clear SEL | 31.9 | O | ⚡ | ? | ? |
| 48h  | Get SEL Time | 31.10 | U | ⚡ | ? | ? |
| 49h  | Set SEL Time | 31.11 | O | ⚡ | ? | ? |
| 5Ch  | Get SEL Time UTC Offset | 31.11a | U | ✗ | ? | ? |
| 5Dh  | Set SEL Time UTC Offset | 31.11b | O | ✗ | ? | ? |
| 5Ah  | Get Auxiliary Log Status | 31.12 | O | ✗ | ? | ? |
| 5Bh  | Set Auxiliary Log Status | 31.13 | A | ✗ | ? | ? |

---

## Transport NetFn (0x0C)

**25 commands · 5 done by zipmi** — ✓ 3 decoded, ⚡ 2 raw · ✗ 20 not implemented.
Done: Get LAN Configuration Parameters, Set SOL Configuration Parameters, Get SOL Configuration Parameters, Set Serial/Modem Configuration, Get Serial/Modem Configuration


### LAN Device Commands

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 01h  | Set LAN Configuration Parameters | 23.1 | A | ✗ | ? | ? |
| 02h  | Get LAN Configuration Parameters | 23.2 | A | ✓ | ✓ | ? |
| 03h  | Suspend BMC ARPs | 23.3 | A | ✗ | ? | ? |
| 04h  | Get IP/UDP/RMCP Statistics | 23.4 | U | ✗ | ? | ? |

### Serial / Modem

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 10h  | Set Serial/Modem Configuration | 25.1 | A | ⚡ | ? | ? |
| 11h  | Get Serial/Modem Configuration | 25.2 | U | ⚡ | ? | ? |
| 12h  | Set Serial/Modem Mux | 25.3 | A | ✗ | ? | ? |
| 13h  | Get TAP Response Codes | 25.4 | A | ✗ | ? | ? |
| 14h  | Set PPP UDP Proxy Transmit Data | 25.5 | A | ✗ | ? | ? |
| 15h  | Get PPP UDP Proxy Transmit Data | 25.6 | A | ✗ | ? | ? |
| 16h  | Send PPP UDP Proxy Packet | 25.7 | A | ✗ | ? | ? |
| 17h  | Get PPP UDP Proxy Receive Data | 25.8 | A | ✗ | ? | ? |
| 18h  | Serial/Modem Connection Active | 25.9 | A | ✗ | ? | ? |
| 19h  | Callback | 25.10 | A | ✗ | ? | ? |
| 1Ah  | Set User Callback Options | 25.11 | A | ✗ | ? | ? |
| 1Bh  | Get User Callback Options | 25.12 | U | ✗ | ? | ? |
| 1Ch  | Set Serial Routing Mux | 25.13 | A | ✗ | ? | ? |

### SOL

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 20h  | SOL Activating | 26.1 | U | ✗ | ? | ? |
| 21h  | Set SOL Configuration Parameters | 26.2 | A | ✓ | ? | ? |
| 22h  | Get SOL Configuration Parameters | 26.3 | U | ✓ | ? | ? |

### Generic / Group

| CMD  | Name | NetFn | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|-------|--------|------|-------|------|--------|
| 02h  | Group Extension Command | 0x2C | — | varies | ✗ | ? | ? |

---

| 40h  | Forwarded Command | (fwd) | A | ✗ | ? | ? |
| 41h  | Set Forwarded Commands | (fwd) | A | ✗ | ? | ? |
| 42h  | Get Forwarded Commands | (fwd) | A | ✗ | ? | ? |
| 43h  | Enable Forwarded Commands | (fwd) | A | ✗ | ? | ? |

## Bridge NetFn (0x02) — ICMB

**26 commands · 0 done by zipmi** — ✓ 0 decoded, ⚡ 0 raw · ✗ 26 not implemented.
Done: _none_


Most bridge commands implemented as `⚡ raw` only; we don't model ICMB
specifically. Listed here for completeness.

| CMD  | Name | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|------|-------|------|--------|
| 00h  | Get Bridge State | 26.x | A | ✗ | ? | ? |
| 30h  | Send ICMB Connection ID | (ICMB) | — | ✗ | — | — |

---

| 01h  | Set Bridge State | (ICMB) | — | ✗ | — | — |
| 02h  | Get ICMB Address | (ICMB) | — | ✗ | — | — |
| 03h  | Set ICMB Address | (ICMB) | — | ✗ | — | — |
| 04h  | Set Bridge ProxyAddress | (ICMB) | — | ✗ | — | — |
| 05h  | Get Bridge Statistics | (ICMB) | — | ✗ | — | — |
| 06h  | Get ICMB Capabilities | (ICMB) | — | ✗ | — | — |
| 08h  | Clear Bridge Statistics | (ICMB) | — | ✗ | — | — |
| 09h  | Get Bridge Proxy Address | (ICMB) | — | ✗ | — | — |
| 0Ah  | Get ICMB Connector Info | (ICMB) | — | ✗ | — | — |
| 0Bh  | Get ICMB Connection ID | (ICMB) | — | ✗ | — | — |
| 0Ch  | Send ICMB Connection ID | (ICMB) | — | ✗ | — | — |
| 10h  | Prepare For Discovery | (ICMB) | — | ✗ | — | — |
| 11h  | Get Addresses | (ICMB) | — | ✗ | — | — |
| 12h  | Set Discovered | (ICMB) | — | ✗ | — | — |
| 13h  | Get Chassis Device ID | (ICMB) | — | ✗ | — | — |
| 14h  | Set Chassis Device ID | (ICMB) | — | ✗ | — | — |
| 20h  | Bridge Request | (ICMB) | — | ✗ | — | — |
| 21h  | Bridge Message | (ICMB) | — | ✗ | — | — |
| 31h  | Set Event Destination | (ICMB) | — | ✗ | — | — |
| 32h  | Set Event Reception State | (ICMB) | — | ✗ | — | — |
| 33h  | Send ICMB Event Message | (ICMB) | — | ✗ | — | — |
| 34h  | Get Event Destination | (ICMB) | — | ✗ | — | — |
| 35h  | Get Event Reception State | (ICMB) | — | ✗ | — | — |
| C0h  | Error Report | (ICMB) | — | ✗ | — | — |

## OEM NetFn (0x30) and Group OEM (0x2E)

**0 commands · 0 done by zipmi** — ✓ 0 decoded, ⚡ 0 raw · ✗ 0 not implemented.
Done: _none_


OEM commands are vendor-specific. zipmi keeps these out of `CMD_PAYLOADS`
and exposes them only via `zipmi.scapy_ipmi.oem.<vendor>` after an
explicit `zipmi.load_vendor("<vendor>")`.

**Full Dell iDRAC6 dispatch table is in [dell-command-table.md](dell-command-table.md)**
— 192 entries auto-generated from the fullfw RE markdown
(`/Volumes/yyy/phd/bmc/dell/fullfw-ipmi-commands.md`) by
`python -m zipmi.parsers.md_table --markdown`.

By NetFn:

| NetFn | Group | Entries | Sessionless | Stubbed |
|-------|-------|---------|-------------|---------|
| 0x00 | Chassis (Dell extended) | 9 | 3 | 0 |
| 0x04 | Sensor / Event | 22 | 6 | 0 |
| 0x06 | App | 52 | 14 | 0 |
| 0x08 | Firmware | 8 | 7 | 0 |
| 0x0A | Storage | 18 | 1 | 0 |
| 0x0C | Transport | 8 | 3 | 0 |
| 0x2E | Group OEM | 8 | 5 | 0 |
| 0x30 | Dell OEM | 67 | 28 | 8 |
| **Total** | | **192** | **67** | **8** |

Supermicro: stub only (4 names) until X11SSZ is back online to live-test.

---

## Notes

### R710 (Dell PowerEdge R710 / iDRAC6)

- Hardware: Dell PowerEdge R710 / T710 (same iDRAC6 firmware), Nuvoton
  WPCM450, dual Xeon E5530 (Nehalem), CentOS 6.7 host.
- BMC: iDRAC6 firmware **1.70**, manufacturer ID 674 (Dell), product
  0x0100. IPMI 2.0 advertised; cipher suites 0–11 supported; ASF Ping
  works (oem_iana=4542 ASF). Auth modes: None / MD2 / MD5 / Straight
  Pwd / RMCP+. "Per-message auth disabled" status bit set.
- Live test target: 192.168.0.23, root/calvin.
- Quirks observed: silently drops messages whose source UDP port
  changes mid-session (binds to `(src_ip, src_port)` of Activate
  Session); occasional 0xC0 NodeBusy under rapid back-to-back session
  open/close; CC 0xCC for valid requests when session is wedged.

### X11SSZ (Supermicro X11SSZ-QF)

- Hardware: Supermicro X11SSZ-QF, ASPEED AST2400 BMC, Skylake
  i7-6700K host, Ubuntu 22.04.
- BMC: vulnerable to all Pantsdown sub-vulns (CVE-2019-6260) — P2A,
  iLPC2AHB, X-DMA bridges enabled. ADMIN/ADMIN.
- Live test target: 192.168.0.24 — currently DOWN, table entries marked
  "?". Will populate on next pass.
- Expected differences from R710: full RMCP+ negotiation including
  cipher 17 (HMAC-SHA256); larger SDR; OEM NetFn 0x30 cmds 0x68/0x6E/
  0x70/0xA0 (file transfer / firmware upgrade with shell-injection).

### Methodology

Per-platform columns are populated by:

1. Running `zipmi raw <netfn> <cmd>` against the platform.
2. Recording (a) whether a non-zero CC came back and (b) whether the
   response data shape matched the spec.
3. Cross-checking against `ipmitool` for the same NetFn/cmd to
   distinguish "BMC doesn't implement" from "zipmi parsing bug".

Pasting that loop into an automation harness is on the roadmap; for
now updates are manual after each `zipmi` build cycle.
