# IPMI Command Status Table — zipmi vs real BMCs

Modeled on **Table G-1, Command Number Assignments and Privilege Levels**
(IPMI 2.0 spec, Appendix G). Adds columns for zipmi implementation status
and per-platform live test results.

> **Coverage: zipmi implements 132 of 188 standard IPMI commands** — 44 as Scapy
> packet classes (✓, field-level encode/decode, usable programmatically) + 88 as
> dedicated CLI verbs that decode in the handler (⚡, structured text/JSON output,
> just not a packet class). Both are real, decoded commands. 56 are not
> implemented (✗) — still reachable by opcode via `zipmi raw`. Per-NetFn breakdown
> sits at the top of each section below.

## Legend

**zipmi column:**

| Symbol | Meaning |
|--------|---------|
| ✓ | Scapy **packet class** in `CMD_PAYLOADS` — field-level encode/decode at the packet layer; usable programmatically (`send_cmd`) as well as from the CLI |
| ⚡ | Dedicated **CLI verb** using `send_raw` + decode in the handler — structured (text/JSON) output, just no Scapy packet class. NOT the bare `zipmi raw` fallback; these are real decoded commands |
| ✗ | Not implemented as a verb (still reachable by opcode via `zipmi raw` / `zipmi ipmi <name>`) |

**Scapy column** (whether the command has a packet class — see
[scapy-usage.md](scapy-usage.md)):

| Symbol | Meaning |
|--------|---------|
| ✓ | Has a Scapy packet class in `CMD_PAYLOADS` — build/send (`send_cmd`), dissect, and field-level fuzz programmatically. (Always paired with a `✓` in the zipmi column.) |
| — | No packet class — CLI handler-decode (`⚡`) or not implemented (`✗`). Reachable from the CLI but not as a decoded object. |

**Per-platform columns (R710, X11SSZ, …):**

> **ASMB787 column is different** — it is *not* live-tested. It is **static
> ground truth** from firmware RE: ✓ = a handler for that (NetFn, cmd) is
> present in the ASMB-787's real dispatch tables, ✗ = absent. See
> [advantech_ASMB787-command-table.md](advantech_ASMB787-command-table.md) for
> the full OEM handler catalog and [oem-handler-lineage.md](oem-handler-lineage.md)
> for the cross-vendor comparison.

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

**68 commands · 60 done by zipmi** — ✓ 20 decoded, ⚡ 40 raw · ✗ 8 not implemented.
Done: Get Device ID, Cold Reset, Warm Reset, Get Self Test Results, Get Device GUID, Get System GUID, Get Channel Authentication Capabilities, Get Session Challenge, Activate Session, Set Session Privilege Level, Close Session, Get Channel Access, Get Channel Info Command, Get User Access Command, Get User Name Command, Activate Payload, Deactivate Payload, Get Payload Activation Status, Get Channel Cipher Suites, Get NetFn Support, Get Command Support, Get Command Sub-function Support, Get Configurable Commands, Get Command Enables, Get Command Sub-function Enables, Reset Watchdog Timer, Set Watchdog Timer, Get Watchdog Timer, Get Message Flags, Get Message, Send Message, Get Session Info, Set User Access Command, Set User Name, Set User Password Command, Set User Payload Access, Get User Payload Access, Master Read-Write, Get System Interface Capabilities, Get BMC Global Enables, Get ACPI Power State, Get System Info Parameters, Get Channel Payload Support, Get Channel Payload Version, Get Payload Instance Info


### IPM Device "Global" Commands

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 00h  | Reserved | `reserved` | — | — | — | — | — | — | ✗ |
| 01h  | Get Device ID | `get_device_id` | 20.1 | s | ✓ | ✓ | ✓ | ? | ✓ |
| 01h  | Broadcast Get Device ID | `get_device_id` | 20.9 | s | ✗ | ✓ | ? | ? | ✓ |
| 02h  | Cold Reset | `cold_reset` | 20.2 | A | ✓ | ✓ | ? | ? | ✓ |
| 03h  | Warm Reset | `warm_reset` | 20.3 | A | ✓ | ✓ | ? | ? | ✓ |
| 04h  | Get Self Test Results | `get_self_test_results` | 20.4 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 05h  | Manufacturing Test On | `manufacturing_test_on` | 20.5 | A | ⚡ | — | ? | ? | ✓ |
| 06h  | Set ACPI Power State | `set_acpi_power_state` | 20.6 | A | ⚡ | — | ? | ? | ✓ |
| 07h  | Get ACPI Power State | `get_acpi_power_state` | 20.7 | U | ⚡ | — | ? | ? | ✓ |
| 08h  | Get Device GUID | `get_device_guid` | 20.8 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 09h  | Get NetFn Support | `get_net_fn_support` | 21.2 | A | ⚡ | — | ? | ? | ✓ |
| 0Ah  | Get Command Support | `get_command_support` | 21.3 | A | ⚡ | — | ? | ? | ✓ |
| 0Bh  | Get Command Sub-function Support | `get_command_sub_function_support` | 21.4 | A | ⚡ | — | ? | ? | ✓ |
| 0Ch  | Get Configurable Commands | `get_configurable_commands` | 21.5 | A | ⚡ | — | ? | ? | ✓ |
| 0Dh  | Get Configurable Command Sub-functions | `get_configurable_command_sub_functions` | 21.6 | A | ⚡ | — | ? | ? | ✓ |
| 60h  | Set Command Enables | `set_command_enables` | 21.7 | A | ⚡ | — | ? | ? | ✓ |
| 61h  | Get Command Enables | `get_command_enables` | 21.8 | A | ⚡ | — | ? | ? | ✓ |
| 62h  | Set Command Sub-function Enables | `set_command_sub_function_enables` | 21.9 | A | ⚡ | — | ? | ? | ✓ |
| 63h  | Get Command Sub-function Enables | `get_command_sub_function_enables` | 21.10 | A | ⚡ | — | ? | ? | ✓ |
| 64h  | Get OEM NetFn IANA Support | `get_oem_net_fn_iana_support` | 21.11 | A | ⚡ | — | ? | ? | ✓ |

### BMC Watchdog Timer Commands

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 22h  | Reset Watchdog Timer | `reset_watchdog_timer` | 27.5 | O | ⚡ | — | ? | ? | ✓ |
| 24h  | Set Watchdog Timer   | `set_watchdog_timer` | 27.6 | O | ⚡ | — | ? | ? | ✓ |
| 25h  | Get Watchdog Timer   | `get_watchdog_timer` | 27.7 | U | ⚡ | — | ? | ? | ✓ |

### BMC Device and Messaging Commands

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 2Eh  | Set BMC Global Enables | `set_bmc_global_enables` | 22.1 | A | ⚡ | — | ? | ? | ✓ |
| 2Fh  | Get BMC Global Enables | `get_bmc_global_enables` | 22.2 | U | ⚡ | — | ? | ? | ✓ |
| 30h  | Clear Message Flags | `clear_message_flags` | 22.3 | A | ⚡ | — | ? | ? | ✓ |
| 31h  | Get Message Flags | `get_message_flags` | 22.4 | A | ⚡ | — | ? | ? | ✓ |
| 32h  | Enable Message Channel Receive | `enable_message_channel_receive` | 22.5 | A | ⚡ | — | ? | ? | ✓ |
| 33h  | Get Message | `get_message` | 22.6 | A | ⚡ | — | ? | ? | ✓ |
| 34h  | Send Message | `send_message` | 22.7 | A* | ⚡ | — | ? | ? | ✓ |
| 35h  | Read Event Message Buffer | `read_event_message_buffer` | 22.8 | A | ⚡ | — | ? | ? | ✓ |
| 36h  | Get BT Interface Capabilities | `get_bt_interface_capabilities` | 22.10 | U | ⚡ | — | ? | ? | ✓ |
| 37h  | Get System GUID | `get_system_guid` | 22.14 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 58h  | Set System Info Parameters | `set_system_info_parameters` | 22.14a | A | ⚡ | — | ? | ? | ✓ |
| 59h  | Get System Info Parameters | `get_system_info_parameters` | 22.14b | U | ⚡ | — | ? | ? | ✓ |
| 38h  | Get Channel Authentication Capabilities | `get_channel_authentication_capabilities` | 22.13 | s | ✓ | ✓ | ✓ | ? | ✓ |
| 39h  | Get Session Challenge | `get_session_challenge` | 22.15 | s | ✓ | ✓ | ✓ | ? | ✓ |
| 3Ah  | Activate Session | `activate_session` | 22.17 | s | ✓ | ✓ | ✓ | ? | ✓ |
| 3Bh  | Set Session Privilege Level | `set_session_privilege_level` | 22.18 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 3Ch  | Close Session | `close_session` | 22.19 | C | ✓ | ✓ | ✓ | ? | ✓ |
| 3Dh  | Get Session Info | `get_session_info` | 22.20 | U | ⚡ | — | ? | ? | ✓ |
| 3Fh  | Get AuthCode | `get_auth_code` | 22.21 | U | ⚡ | — | ? | ? | ✓ |
| 40h  | Set Channel Access | `set_channel_access` | 22.22 | A | ⚡ | — | ? | ? | ✓ |
| 41h  | Get Channel Access | `get_channel_access` | 22.23 | U | ✓ | ✓ | ? | ? | ✓ |
| 42h  | Get Channel Info Command | `get_channel_info` | 22.24 | U | ✓ | ✓ | ? | ? | ✓ |
| 43h  | Set User Access Command | `set_user_access` | 22.26 | A | ⚡ | — | ? | ? | ✓ |
| 44h  | Get User Access Command | `get_user_access` | 22.27 | O | ✓ | ✓ | ✓ | ? | ✓ |
| 45h  | Set User Name | `set_user_name` | 22.28 | A | ⚡ | — | ? | ? | ✓ |
| 46h  | Get User Name Command | `get_user_name` | 22.29 | O | ✓ | ✓ | ✓ | ? | ✓ |
| 47h  | Set User Password Command | `set_user_password` | 22.30 | A | ⚡ | — | ? | ? | ✓ |
| 48h  | Activate Payload | `activate_payload` | 24.1 | U/O | ✓ | ✓ | ? | ? | ✓ |
| 49h  | Deactivate Payload | `deactivate_payload` | 24.2 | U/O | ✓ | ✓ | ? | ? | ✓ |
| 4Ah  | Get Payload Activation Status | `get_payload_activation_status` | 24.3 | U | ✓ | ✓ | ? | ? | ✓ |
| 4Bh  | Get Payload Instance Info | `get_payload_instance_info` | 24.4 | U | ⚡ | — | ? | ? | ✓ |
| 4Ch  | Set User Payload Access | `set_user_payload_access` | 24.5 | A | ⚡ | — | ? | ? | ✓ |
| 4Dh  | Get User Payload Access | `get_user_payload_access` | 24.6 | O | ⚡ | — | ? | ? | ✓ |
| 4Eh  | Get Channel Payload Support | `get_channel_payload_support` | 24.7 | U | ⚡ | — | ? | ? | ✓ |
| 4Fh  | Get Channel Payload Version | `get_channel_payload_version` | 24.8 | U | ⚡ | — | ? | ? | ✓ |
| 50h  | Get Channel OEM Payload Info | `get_channel_oem_payload_info` | 24.9 | U | ✗ | — | ? | ? | ✓ |
| 52h  | Master Read-Write | `master_write_read` | 22.11 | A* | ✓ | ✓ | ? | ? | ✓ |
| 54h  | Get Channel Cipher Suites | `get_channel_cipher_suites` | 22.15 | s | ✓ | ✓ | ? | ? | ✓ |
| 55h  | Suspend/Resume Payload Encryption | `suspend_resume_payload_encryption` | 24.10 | U | ✗ | — | ? | ? | ✓ |
| 56h  | Set Channel Security Keys | `set_channel_security_keys` | 22.25 | A | ⚡ | — | ? | ? | ✓ |
| 57h  | Get System Interface Capabilities | `get_system_interface_capabilities` | 22.9 | U | ⚡ | — | ? | ? | ✓ |
| 5Ah  | Get Authorization Privilege Level | `get_authorization_privilege_level` | 22.x | s | ✗ | — | ? | ? | ✗ |
| 5Bh  | Get Authentication Capabilities (v2) | `get_authentication_capabilities_v2` | 22.x | s | ✗ | — | ? | ? | ✗ |
| 5Ch  | Get Session-Less Channel Privilege Level | `get_session_less_channel_privilege_level` | 22.x | s | ✗ | — | ? | ? | ✗ |
| 5Dh  | Set Session-Less Channel Privilege Level | `set_session_less_channel_privilege_level` | 22.x | s | ✗ | — | ? | ? | ✗ |
| 5Eh  | Get Session-Less Channel Auth Caps | `get_session_less_channel_auth_caps` | 22.x | s | ✗ | — | ? | ? | ✗ |

---

## Chassis NetFn (0x00)

**13 commands · 13 done by zipmi** — ✓ 4 decoded, ⚡ 9 raw · ✗ 0 not implemented. (complete)
Done: Get Chassis Status, Chassis Control, Set System Boot Options, Get System Boot Options, Chassis Identify, Set Power Restore Policy, Get System Restart Cause, Get Chassis Capabilities, Get POH Counter


| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 00h  | Get Chassis Capabilities | `get_chassis_capabilities` | 28.1 | U | ⚡ | — | ? | ? | ✓ |
| 01h  | Get Chassis Status | `get_chassis_status` | 28.2 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 02h  | Chassis Control | `chassis_control` | 28.3 | O | ✓ | ✓ | ? (untested destructive) | ? | ✓ |
| 03h  | Chassis Reset | `chassis_reset` | 28.4 | O | ⚡ | — | ? | ? | ✓ |
| 04h  | Chassis Identify | `chassis_identify` | 28.5 | O | ⚡ | — | ? | ? | ✓ |
| 05h  | Set Chassis Capabilities | `set_chassis_capabilities` | 28.7 | A | ⚡ | — | ? | ? | ✓ |
| 06h  | Set Power Restore Policy | `set_power_restore_policy` | 28.8 | A | ⚡ | — | ? | ? | ✓ |
| 07h  | Get System Restart Cause | `get_system_restart_cause` | 28.11 | U | ⚡ | — | ? | ? | ✓ |
| 08h  | Set System Boot Options | `set_system_boot_options` | 28.12 | A | ✓ | ✓ | ? (untested writeable) | ? | ✓ |
| 09h  | Get System Boot Options | `get_system_boot_options` | 28.13 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 0Ah  | Set Front Panel Button Enables | `set_front_panel_button_enables` | 28.6 | A | ⚡ | — | ? | ? | ✓ |
| 0Bh  | Set Power Cycle Interval | `set_power_cycle_interval` | 28.9 | A | ⚡ | — | ? | ? | ✓ |
| 0Fh  | Get POH Counter | `get_poh_counter` | 28.14 | U | ⚡ | — | ? | ? | ✓ |

---

## Sensor / Event NetFn (0x04)

**27 commands · 25 done by zipmi** — ✓ 4 decoded, ⚡ 21 raw · ✗ 2 not implemented.
Done: Get Sensor Reading, Get PEF Capabilities, Get PEF Configuration Parameters, Get Last Processed Event ID, Get Device SDR Info, Get Device SDR, Reserve Device SDR Repository, Get Sensor Reading Factors, Get Sensor Hysteresis, Get Sensor Threshold, Get Sensor Event Enable, Get Sensor Event Status, Get Sensor Type


| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 00h  | Set Event Receiver | `set_event_receiver` | 29.1 | A | ⚡ | — | ? | ? | ✓ |
| 01h  | Get Event Receiver | `get_event_receiver` | 29.2 | U | ⚡ | — | ? | ? | ✓ |
| 02h  | Platform Event Message | `platform_event` | 29.3 | O | ⚡ | — | ? | ? | ✓ |
| 10h  | Get PEF Capabilities | `get_pef_capabilities` | 30.1 | U | ⚡ | — | ? | ? | ✓ |
| 11h  | Arm PEF Postpone Timer | `arm_pef_postpone_timer` | 30.2 | A | ⚡ | — | ? | ? | ✓ |
| 12h  | Set PEF Configuration Parameters | `set_pef_configuration_parameters` | 30.3 | A | ⚡ | — | ? | ? | ✓ |
| 13h  | Get PEF Configuration Parameters | `get_pef_configuration_parameters` | 30.4 | U | ⚡ | — | ? | ? | ✓ |
| 14h  | Set Last Processed Event ID | `set_last_processed_event_id` | 30.5 | A | ⚡ | — | ? | ? | ✓ |
| 15h  | Get Last Processed Event ID | `get_last_processed_event_id` | 30.6 | A | ⚡ | — | ? | ? | ✓ |
| 16h  | Alert Immediate | `alert_immediate` | 30.7 | O | ⚡ | — | ? | ? | ✓ |
| 17h  | PET Acknowledge | `pet_acknowledge` | 30.8 | s | ⚡ | — | ? | ? | ✓ |
| 20h  | Get Device SDR Info | `get_device_sdr_info` | 35.2 | U | ⚡ | — | ? | ? | ✓ |
| 21h  | Get Device SDR | `get_device_sdr` | 35.3 | U | ✓ | ✓ | ? | ? | ✓ |
| 22h  | Reserve Device SDR Repository | `reserve_device_sdr_repository` | 35.4 | U | ⚡ | — | ? | ? | ✓ |
| 23h  | Get Sensor Reading Factors | `get_sensor_reading_factors` | 35.5 | U | ✓ | ✓ | ? | ? | ✓ |
| 24h  | Set Sensor Hysteresis | `set_sensor_hysteresis` | 35.6 | O | ⚡ | — | ? | ? | ✓ |
| 25h  | Get Sensor Hysteresis | `get_sensor_hysteresis` | 35.7 | U | ⚡ | — | ? | ? | ✓ |
| 26h  | Set Sensor Threshold | `set_sensor_threshold` | 35.8 | O | ⚡ | — | ? | ? | ✓ |
| 27h  | Get Sensor Threshold | `get_sensor_threshold` | 35.9 | U | ✓ | ✓ | ? | ? | ✓ |
| 28h  | Set Sensor Event Enable | `set_sensor_event_enable` | 35.10 | O | ⚡ | — | ? | ? | ✓ |
| 29h  | Get Sensor Event Enable | `get_sensor_event_enable` | 35.11 | U | ⚡ | — | ? | ? | ✓ |
| 2Ah  | Re-arm Sensor Events | `re_arm_sensor_events` | 35.12 | O | ⚡ | — | ? | ? | ✓ |
| 2Bh  | Get Sensor Event Status | `get_sensor_event_status` | 35.13 | U | ⚡ | — | ? | ? | ✓ |
| 2Dh  | Get Sensor Reading | `get_sensor_reading` | 35.14 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 2Eh  | Set Sensor Type | `set_sensor_type` | 35.16 | O | ✗ | — | ? | ? | ✓ |
| 2Fh  | Get Sensor Type | `get_sensor_type` | 35.17 | U | ⚡ | — | ? | ? | ✓ |
| 30h  | Set Sensor Reading And Event Status | `set_sensor_reading_and_event_status` | 35.15 | O | ✗ | — | ? | ? | ✓ |

---

## Storage NetFn (0x0A)

**30 commands · 27 done by zipmi** — ✓ 9 decoded, ⚡ 18 raw · ✗ 3 not implemented.
Done: Get FRU Inventory Area Info, Get SDR Repository Info, Reserve SDR Repository, Get SDR, Get SEL Info, Reserve SEL, Get SEL Entry, Read FRU Data, Clear SEL, Get SEL Time, Set SEL Time


### FRU Inventory

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 10h  | Get FRU Inventory Area Info | `get_fru_inventory_area_info` | 34.1 | U | ✓ | ✓ | ? | ? | ✓ |
| 11h  | Read FRU Data | `read_fru_data` | 34.2 | O | ✓ | ✓ | ? | ? | ✓ |
| 12h  | Write FRU Data | `write_fru_data` | 34.3 | O | ✓ | ✓ | ? | ? | ✓ |

### SDR Repository

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 20h  | Get SDR Repository Info | `get_sdr_repository_info` | 33.9 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 21h  | Get SDR Repository Allocation Info | `get_sdr_repository_allocation_info` | 33.10 | U | ⚡ | — | ? | ? | ✓ |
| 22h  | Reserve SDR Repository | `reserve_sdr_repository` | 33.11 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 23h  | Get SDR | `get_sdr` | 33.12 | U | ✓ | ✓ | ✓ (chunked reads required) | ? | ✓ |
| 24h  | Add SDR | `add_sdr` | 33.13 | A | ⚡ | — | ? | ? | ✓ |
| 25h  | Partial Add SDR | `partial_add_sdr` | 33.14 | A | ✗ | — | ? | ? | ✓ |
| 26h  | Delete SDR | `delete_sdr` | 33.15 | O | ⚡ | — | ? | ? | ✓ |
| 27h  | Clear SDR Repository | `clear_sdr_repository` | 33.16 | O | ⚡ | — | ? | ? | ✓ |
| 28h  | Get SDR Repository Time | `get_sdr_repository_time` | 33.17 | U | ⚡ | — | ? | ? | ✓ |
| 29h  | Set SDR Repository Time | `set_sdr_repository_time` | 33.18 | A | ⚡ | — | ? | ? | ✓ |
| 2Ah  | Enter SDR Repository Update Mode | `enter_sdr_repository_update_mode` | 33.19 | A | ⚡ | — | ? | ? | ✓ |
| 2Bh  | Exit SDR Repository Update Mode | `exit_sdr_repository_update_mode` | 33.20 | A | ⚡ | — | ? | ? | ✓ |
| 2Ch  | Run Initialization Agent | `run_initialization_agent` | 33.21 | A | ⚡ | — | ? | ? | ✓ |

### SEL

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 40h  | Get SEL Info | `get_sel_info` | 31.2 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 41h  | Get SEL Allocation Info | `get_sel_allocation_info` | 31.3 | U | ⚡ | — | ? | ? | ✓ |
| 42h  | Reserve SEL | `reserve_sel` | 31.4 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 43h  | Get SEL Entry | `get_sel_entry` | 31.5 | U | ✓ | ✓ | ✓ | ? | ✓ |
| 44h  | Add SEL Entry | `add_sel_entry` | 31.6 | O | ⚡ | — | ? | ? | ✓ |
| 45h  | Partial Add SEL Entry | `partial_add_sel_entry` | 31.7 | O | ⚡ | — | ? | ? | ✓ |
| 46h  | Delete SEL Entry | `delete_sel_entry` | 31.8 | O | ⚡ | — | ? | ? | ✓ |
| 47h  | Clear SEL | `clear_sel` | 31.9 | O | ⚡ | — | ? | ? | ✓ |
| 48h  | Get SEL Time | `get_sel_time` | 31.10 | U | ⚡ | — | ? | ? | ✓ |
| 49h  | Set SEL Time | `set_sel_time` | 31.11 | O | ⚡ | — | ? | ? | ✓ |
| 5Ch  | Get SEL Time UTC Offset | `get_sel_time_utc_offset` | 31.11a | U | ⚡ | — | ? | ? | ✓ |
| 5Dh  | Set SEL Time UTC Offset | `set_sel_time_utc_offset` | 31.11b | O | ⚡ | — | ? | ? | ✓ |
| 5Ah  | Get Auxiliary Log Status | `get_auxiliary_log_status` | 31.12 | O | ✗ | — | ? | ? | ✓ |
| 5Bh  | Set Auxiliary Log Status | `set_auxiliary_log_status` | 31.13 | A | ✗ | — | ? | ? | ✓ |

---

## Transport NetFn (0x0C)

**25 commands · 7 done by zipmi** — ✓ 7 decoded, ⚡ 0 raw · ✗ 18 not implemented.
Done: Get LAN Configuration Parameters, Set SOL Configuration Parameters, Get SOL Configuration Parameters, Set Serial/Modem Configuration, Get Serial/Modem Configuration


### LAN Device Commands

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 01h  | Set LAN Configuration Parameters | `set_lan_configuration_parameters` | 23.1 | A | ✓ | ✓ | ? | ? | ✓ |
| 02h  | Get LAN Configuration Parameters | `get_lan_configuration_parameters` | 23.2 | A | ✓ | ✓ | ✓ | ? | ✓ |
| 03h  | Suspend BMC ARPs | `suspend_bmc_arps` | 23.3 | A | ✗ | — | ? | ? | ✓ |
| 04h  | Get IP/UDP/RMCP Statistics | `get_ip_udp_rmcp_statistics` | 23.4 | U | ✓ | ✓ | ? | ? | ✓ |

### Serial / Modem

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 10h  | Set Serial/Modem Configuration | `set_serial_modem_configuration` | 25.1 | A | ✓ | ✓ | ? | ? | ✓ |
| 11h  | Get Serial/Modem Configuration | `get_serial_modem_configuration` | 25.2 | U | ✓ | ✓ | ? | ? | ✓ |
| 12h  | Set Serial/Modem Mux | `set_serial_modem_mux` | 25.3 | A | ✗ | — | ? | ? | ✓ |
| 13h  | Get TAP Response Codes | `get_tap_response_codes` | 25.4 | A | ✗ | — | ? | ? | ✓ |
| 14h  | Set PPP UDP Proxy Transmit Data | `set_ppp_udp_proxy_transmit_data` | 25.5 | A | ✗ | — | ? | ? | ✗ |
| 15h  | Get PPP UDP Proxy Transmit Data | `get_ppp_udp_proxy_transmit_data` | 25.6 | A | ✗ | — | ? | ? | ✗ |
| 16h  | Send PPP UDP Proxy Packet | `send_ppp_udp_proxy_packet` | 25.7 | A | ✗ | — | ? | ? | ✗ |
| 17h  | Get PPP UDP Proxy Receive Data | `get_ppp_udp_proxy_receive_data` | 25.8 | A | ✗ | — | ? | ? | ✗ |
| 18h  | Serial/Modem Connection Active | `serial_modem_connection_active` | 25.9 | A | ✗ | — | ? | ? | ✓ |
| 19h  | Callback | `callback` | 25.10 | A | ✗ | — | ? | ? | ✓ |
| 1Ah  | Set User Callback Options | `set_user_callback_options` | 25.11 | A | ✗ | — | ? | ? | ✓ |
| 1Bh  | Get User Callback Options | `get_user_callback_options` | 25.12 | U | ✗ | — | ? | ? | ✓ |
| 1Ch  | Set Serial Routing Mux | `set_serial_routing_mux` | 25.13 | A | ✗ | — | ? | ? | ✗ |

### SOL

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 20h  | SOL Activating | `sol_activating` | 26.1 | U | ✗ | — | ? | ? | ✗ |
| 21h  | Set SOL Configuration Parameters | `set_sol_configuration_parameters` | 26.2 | A | ✓ | ✓ | ? | ? | ✓ |
| 22h  | Get SOL Configuration Parameters | `get_sol_configuration_parameters` | 26.3 | U | ✓ | ✓ | ? | ? | ✓ |

### Generic / Group

| CMD  | Name | Run as | NetFn | Spec § | Priv | zipmi | R710 | X11SSZ |
|------|------|--------|-------|--------|------|-------|------|--------|
| 02h  | Group Extension Command | `get_lan_configuration_parameters` | 0x2C | — | varies | ✗ | ? | ? |

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

| CMD  | Name | Run as | Spec § | Priv | zipmi | Scapy | R710 | X11SSZ | ASMB787 |
|------|------|--------|--------|------|-------|-------|------|--------|------|
| 00h  | Get Bridge State | `get_bridge_state` | 26.x | A | ✗ | — | ? | ? | ? |
| 30h  | Send ICMB Connection ID | `get_event_count` | (ICMB) | — | ✗ | — | — | — | ? |

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
