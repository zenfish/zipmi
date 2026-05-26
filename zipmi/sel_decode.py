"""SDR + SEL record decoding for `zipmi sel elist`.

Implements just enough of IPMI 2.0 §32 (SEL) and §43 (SDR) to produce
ipmitool-style extended SEL output. Pure parsers — no I/O here. The CLI
walks the BMC; this module turns the bytes into strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


# IPMI 2.0 Table 42-3: Sensor Type Codes.
SENSOR_TYPE: dict[int, str] = {
    0x01: "Temperature",
    0x02: "Voltage",
    0x03: "Current",
    0x04: "Fan",
    0x05: "Physical Security",
    0x06: "Platform Security",
    0x07: "Processor",
    0x08: "Power Supply",
    0x09: "Power Unit",
    0x0A: "Cooling Device",
    0x0B: "Other Units-based",
    0x0C: "Memory",
    0x0D: "Drive Slot",
    0x0E: "POST Memory Resize",
    0x0F: "System Firmware Progress",
    0x10: "Event Logging Disabled",
    0x11: "Watchdog 1",
    0x12: "System Event",
    0x13: "Critical Interrupt",
    0x14: "Button",
    0x15: "Module / Board",
    0x16: "Microcontroller / Coprocessor",
    0x17: "Add-in Card",
    0x18: "Chassis",
    0x19: "Chip Set",
    0x1A: "Other FRU",
    0x1B: "Cable / Interconnect",
    0x1C: "Terminator",
    0x1D: "System Boot Initiated",
    0x1E: "Boot Error",
    0x1F: "OS Boot",
    0x20: "OS Critical Stop",
    0x21: "Slot / Connector",
    0x22: "System ACPI Power State",
    0x23: "Watchdog 2",
    0x24: "Platform Alert",
    0x25: "Entity Presence",
    0x26: "Monitor ASIC / IC",
    0x27: "LAN",
    0x28: "Management Subsystem Health",
    0x29: "Battery",
    0x2A: "Session Audit",
    0x2B: "Version Change",
    0x2C: "FRU State",
}


# IPMI 2.0 Table 42-1: Generic Event/Reading Type Codes.
# Indexed by (event_reading_type_code, offset).
GENERIC_EVENT: dict[tuple[int, int], str] = {
    # 0x01 Threshold
    (0x01, 0x00): "Lower Non-critical going low",
    (0x01, 0x01): "Lower Non-critical going high",
    (0x01, 0x02): "Lower Critical going low",
    (0x01, 0x03): "Lower Critical going high",
    (0x01, 0x04): "Lower Non-recoverable going low",
    (0x01, 0x05): "Lower Non-recoverable going high",
    (0x01, 0x06): "Upper Non-critical going low",
    (0x01, 0x07): "Upper Non-critical going high",
    (0x01, 0x08): "Upper Critical going low",
    (0x01, 0x09): "Upper Critical going high",
    (0x01, 0x0A): "Upper Non-recoverable going low",
    (0x01, 0x0B): "Upper Non-recoverable going high",
    # 0x02 Discrete usage
    (0x02, 0x00): "Transition to Idle",
    (0x02, 0x01): "Transition to Active",
    (0x02, 0x02): "Transition to Busy",
    # 0x03 Digital discrete
    (0x03, 0x00): "State Deasserted",
    (0x03, 0x01): "State Asserted",
    # 0x04 Predictive failure
    (0x04, 0x00): "Predictive Failure deasserted",
    (0x04, 0x01): "Predictive Failure asserted",
    # 0x05 Limit
    (0x05, 0x00): "Limit Not Exceeded",
    (0x05, 0x01): "Limit Exceeded",
    # 0x06 Performance
    (0x06, 0x00): "Performance Met",
    (0x06, 0x01): "Performance Lags",
    # 0x07 Severity
    (0x07, 0x00): "transition to OK",
    (0x07, 0x01): "transition to Non-Critical from OK",
    (0x07, 0x02): "transition to Critical from less severe",
    (0x07, 0x03): "transition to Non-recoverable from less severe",
    (0x07, 0x04): "transition to Non-Critical from more severe",
    (0x07, 0x05): "transition to Critical from Non-recoverable",
    (0x07, 0x06): "transition to Non-recoverable",
    (0x07, 0x07): "Monitor",
    (0x07, 0x08): "Informational",
    # 0x08 Availability — device present
    (0x08, 0x00): "Device Absent",
    (0x08, 0x01): "Device Present",
    # 0x09 Availability — device enabled
    (0x09, 0x00): "Device Disabled",
    (0x09, 0x01): "Device Enabled",
    # 0x0A Redundancy
    (0x0A, 0x00): "transition to Running",
    (0x0A, 0x01): "transition to In Test",
    (0x0A, 0x02): "transition to Power Off",
    (0x0A, 0x03): "transition to On Line",
    (0x0A, 0x04): "transition to Off Line",
    (0x0A, 0x05): "transition to Off Duty",
    (0x0A, 0x06): "transition to Degraded",
    (0x0A, 0x07): "transition to Power Save",
    (0x0A, 0x08): "Install Error",
    # 0x0B Redundancy state
    (0x0B, 0x00): "Fully Redundant",
    (0x0B, 0x01): "Redundancy Lost",
    (0x0B, 0x02): "Redundancy Degraded",
    (0x0B, 0x03): "Non-redundant: Sufficient from Redundant",
    (0x0B, 0x04): "Non-redundant: Sufficient from Insufficient",
    (0x0B, 0x05): "Non-redundant: Insufficient Resources",
    (0x0B, 0x06): "Redundancy Degraded from Fully Redundant",
    (0x0B, 0x07): "Redundancy Degraded from Non-redundant",
    # 0x0C ACPI power state
    (0x0C, 0x00): "D0 Power State",
    (0x0C, 0x01): "D1 Power State",
    (0x0C, 0x02): "D2 Power State",
    (0x0C, 0x03): "D3 Power State",
}


# IPMI 2.0 Table 42-3 sensor-specific event descriptions (event_type=0x6F).
# Indexed by (sensor_type, offset). Covers the common cases; unknowns fall
# back to "sensor-specific offset 0xNN".
SENSOR_SPECIFIC_EVENT: dict[tuple[int, int], str] = {
    # 0x05 Physical Security
    (0x05, 0x00): "General Chassis intrusion",
    (0x05, 0x01): "Drive Bay intrusion",
    (0x05, 0x02): "I/O Card area intrusion",
    (0x05, 0x03): "Processor area intrusion",
    (0x05, 0x04): "LAN Leash Lost",
    (0x05, 0x05): "Unauthorized dock",
    (0x05, 0x06): "FAN area intrusion",
    # 0x07 Processor
    (0x07, 0x00): "IERR",
    (0x07, 0x01): "Thermal Trip",
    (0x07, 0x02): "FRB1/BIST failure",
    (0x07, 0x03): "FRB2/Hang in POST failure",
    (0x07, 0x04): "FRB3/Processor Startup/Init failure",
    (0x07, 0x05): "Configuration Error",
    (0x07, 0x06): "SM BIOS Uncorrectable CPU-complex Error",
    (0x07, 0x07): "Processor Presence detected",
    (0x07, 0x08): "Processor disabled",
    (0x07, 0x09): "Terminator Presence Detected",
    (0x07, 0x0A): "Processor Automatically Throttled",
    # 0x08 Power Supply
    (0x08, 0x00): "Presence detected",
    (0x08, 0x01): "Power Supply Failure detected",
    (0x08, 0x02): "Predictive Failure",
    (0x08, 0x03): "Power Supply input lost (AC/DC)",
    (0x08, 0x04): "Power Supply input lost or out-of-range",
    (0x08, 0x05): "Power Supply input out-of-range, but present",
    (0x08, 0x06): "Configuration error",
    # 0x09 Power Unit
    (0x09, 0x00): "Power Off / Power Down",
    (0x09, 0x01): "Power Cycle",
    (0x09, 0x02): "240VA Power Down",
    (0x09, 0x03): "Interlock Power Down",
    (0x09, 0x04): "AC Lost / Power input lost",
    (0x09, 0x05): "Soft Power Control Failure",
    (0x09, 0x06): "Power Unit Failure detected",
    (0x09, 0x07): "Predictive Failure",
    # 0x0C Memory
    (0x0C, 0x00): "Correctable ECC",
    (0x0C, 0x01): "Uncorrectable ECC",
    (0x0C, 0x02): "Parity",
    (0x0C, 0x03): "Memory Scrub Failed",
    (0x0C, 0x04): "Memory Device Disabled",
    (0x0C, 0x05): "Correctable ECC logging limit reached",
    (0x0C, 0x06): "Presence Detected",
    (0x0C, 0x07): "Configuration Error",
    (0x0C, 0x08): "Spare",
    # 0x0F System Firmware Progress
    (0x0F, 0x00): "System Firmware Error",
    (0x0F, 0x01): "System Firmware Hang",
    (0x0F, 0x02): "System Firmware Progress",
    # 0x10 Event Logging Disabled
    (0x10, 0x00): "Correctable Memory Error Logging Disabled",
    (0x10, 0x01): "Event Type Logging Disabled",
    (0x10, 0x02): "Log area reset/cleared",
    (0x10, 0x03): "All Event Logging Disabled",
    (0x10, 0x04): "SEL Full",
    (0x10, 0x05): "SEL Almost Full",
    # 0x12 System Event
    (0x12, 0x00): "System Reconfigured",
    (0x12, 0x01): "OEM System Boot Event",
    (0x12, 0x02): "Undetermined System Hardware Failure",
    (0x12, 0x03): "Entry added to Auxiliary Log",
    (0x12, 0x04): "PEF Action",
    (0x12, 0x05): "Timestamp Clock Sync",
    # 0x13 Critical Interrupt
    (0x13, 0x00): "Front Panel NMI / Diagnostic Interrupt",
    (0x13, 0x01): "Bus Timeout",
    (0x13, 0x02): "I/O channel check NMI",
    (0x13, 0x03): "Software NMI",
    (0x13, 0x04): "PCI PERR",
    (0x13, 0x05): "PCI SERR",
    (0x13, 0x06): "EISA Fail Safe Timeout",
    (0x13, 0x07): "Bus Correctable Error",
    (0x13, 0x08): "Bus Uncorrectable Error",
    (0x13, 0x09): "Fatal NMI (port 61h, bit 7)",
    (0x13, 0x0A): "Bus Fatal Error",
    (0x13, 0x0B): "Bus Degraded",
    # 0x1B Cable / Interconnect
    (0x1B, 0x00): "Connected",
    (0x1B, 0x01): "Config Error",
    # 0x14 Button
    (0x14, 0x00): "Power Button pressed",
    (0x14, 0x01): "Sleep Button pressed",
    (0x14, 0x02): "Reset Button pressed",
    (0x14, 0x03): "FRU Latch open",
    (0x14, 0x04): "FRU Service Request Button",
    # 0x19 Chip Set
    (0x19, 0x00): "Soft Power Control Failure",
    (0x19, 0x01): "Thermal Trip",
    # 0x1D System Boot Initiated
    (0x1D, 0x00): "Initiated by power up",
    (0x1D, 0x01): "Initiated by hard reset",
    (0x1D, 0x02): "Initiated by warm reset",
    (0x1D, 0x03): "User requested PXE boot",
    (0x1D, 0x04): "Automatic boot to diagnostic",
    (0x1D, 0x05): "OS run-time software initiated hard reset",
    (0x1D, 0x06): "OS run-time software initiated warm reset",
    (0x1D, 0x07): "System Restart",
    # 0x23 Watchdog 2
    (0x23, 0x00): "Timer expired",
    (0x23, 0x01): "Hard Reset",
    (0x23, 0x02): "Power Down",
    (0x23, 0x03): "Power Cycle",
    (0x23, 0x08): "Timer interrupt",
    # 0x28 Mgmt Subsystem Health
    (0x28, 0x00): "Sensor access degraded or unavailable",
    (0x28, 0x01): "Controller access degraded or unavailable",
    (0x28, 0x02): "Management Controller off-line",
    (0x28, 0x03): "Management Controller unavailable",
    (0x28, 0x04): "Sensor failure",
    (0x28, 0x05): "FRU failure",
    # 0x2A Session Audit
    (0x2A, 0x00): "Session Activated",
    (0x2A, 0x01): "Session Deactivated",
    (0x2A, 0x02): "Invalid Username or Password",
    (0x2A, 0x03): "Invalid password disable",
    # 0x2B Version Change
    (0x2B, 0x00): "Hardware change detected",
    (0x2B, 0x01): "Firmware/Software change detected",
    (0x2B, 0x02): "Hardware incompatibility detected",
    (0x2B, 0x07): "Firmware/Software incompatibility detected",
}


@dataclass(frozen=True)
class SensorInfo:
    """One sensor decoded from an SDR Type 1 or Type 2 record."""
    sensor_num: int
    sensor_type: int
    name: str


def _decode_id_string(type_length: int, raw: bytes) -> str:
    """Decode an SDR/FRU type-length-encoded string.

    type bits 7-6: 00=Unicode, 01=BCD-plus, 10=6-bit packed ASCII,
                   11=8-bit ASCII+Latin1.
    length bits 4-0: number of data bytes (NOT chars for 6-bit packed).
    """
    code = (type_length >> 6) & 0x03
    length = type_length & 0x1F
    data = raw[:length]
    if code == 0b11:  # 8-bit ASCII / Latin1 — by far the common case
        return data.decode("latin-1", errors="replace").rstrip("\x00").strip()
    if code == 0b10:  # 6-bit packed ASCII, base = 0x20 (' ')
        out: list[str] = []
        for i in range(0, len(data), 3):
            chunk = data[i:i + 3]
            if len(chunk) < 3:
                chunk = chunk + b"\x00" * (3 - len(chunk))
            c0 = chunk[0] & 0x3F
            c1 = ((chunk[0] >> 6) | (chunk[1] << 2)) & 0x3F
            c2 = ((chunk[1] >> 4) | (chunk[2] << 4)) & 0x3F
            c3 = (chunk[2] >> 2) & 0x3F
            out.extend(chr(0x20 + x) for x in (c0, c1, c2, c3))
        return "".join(out).rstrip().rstrip("\x00")
    if code == 0b01:  # BCD-plus: 4 bits per digit, 0..9 + " -.:,_"
        bcd = "0123456789 -.:,_"
        out = []
        for b in data:
            out.append(bcd[b & 0x0F])
            out.append(bcd[(b >> 4) & 0x0F])
        return "".join(out).strip()
    # code == 0 Unicode — uncommon; best-effort UTF-16LE
    try:
        return data.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
    except UnicodeDecodeError:
        return ""


def decode_sdr_record(rec: bytes) -> SensorInfo | None:
    """Decode SDR Type 1 (Full) or Type 2 (Compact). Returns None otherwise.

    Layout common to both (IPMI 2.0 §43.1, §43.2):
      0-1   record_id
      2     sdr_version
      3     record_type
      4     record_length
      5     sensor_owner_id
      6     sensor_owner_lun
      7     sensor_number
      ...
      12    sensor_type
      13    event/reading type code

    ID string type/length code lives at byte 47 (Type 1) or byte 31
    (Type 2), followed by the string bytes. Per IPMI 2.0 Tables 43-1, 43-2.
    """
    if len(rec) < 14:
        return None
    rec_type = rec[3]
    sensor_num = rec[7]
    sensor_type = rec[12]
    if rec_type == 0x01:
        id_off = 47
    elif rec_type == 0x02:
        id_off = 31
    else:
        return None
    if id_off >= len(rec):
        return SensorInfo(sensor_num, sensor_type, "")
    name = _decode_id_string(rec[id_off], rec[id_off + 1:])
    return SensorInfo(sensor_num, sensor_type, name)


def _format_timestamp(ts: int) -> tuple[str, str]:
    """SEL timestamp → (date_str, time_str_with_tz). IPMI epoch = 1970-01-01 UTC.

    Pre-init records have ts < 0x20000000 (~1987) per Table 32-1; ipmitool
    treats anything below that as 'Pre-Init Time-stamp'. Converted to local
    time (matches ipmitool) with zone abbreviation appended to the time.
    """
    if ts < 0x20000000:
        return "Pre-Init", "Time-stamp"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
    tz_abbrev = dt.strftime("%Z")
    return dt.strftime("%m/%d/%Y"), f"{dt.strftime('%H:%M:%S')} {tz_abbrev}".rstrip()


def _event_description(sensor_type: int, ev_byte: int, ev_data1: int) -> str:
    """Decode event description from (sensor_type, event_type, offset).

    ev_byte bit 7 is direction; bits 6-0 are the event/reading type code.
    Offset = ev_data1 bits 3-0 (low nibble).
    """
    ev_type = ev_byte & 0x7F
    offset = ev_data1 & 0x0F
    if ev_type == 0x6F:
        s = SENSOR_SPECIFIC_EVENT.get((sensor_type, offset))
        if s:
            return s
        return f"sensor-specific offset 0x{offset:02x}"
    s = GENERIC_EVENT.get((ev_type, offset))
    if s:
        return s
    return f"event 0x{ev_type:02x} offset 0x{offset:02x}"


def format_sel_record_extended(
    rec: bytes,
    sdr_map: dict[int, SensorInfo] | None = None,
) -> str:
    """ipmitool-style `sel elist` single line.

    Format:  ID | DATE | TIME | <sensor_type> <name> | <event> | Asserted

    Falls back to '#0xNN' when the sensor isn't in the SDR map.
    """
    if len(rec) < 16:
        return f"  short SEL record ({len(rec)} bytes)"
    record_id = int.from_bytes(rec[0:2], "little")
    rec_type = rec[2]
    ts = int.from_bytes(rec[3:7], "little")
    sensor_type = rec[10]
    sensor_num = rec[11]
    ev_byte = rec[12]
    ev_data1 = rec[13]
    direction = "Deasserted" if (ev_byte & 0x80) else "Asserted"
    date, tstr = _format_timestamp(ts)
    type_name = SENSOR_TYPE.get(sensor_type, f"Unknown(0x{sensor_type:02x})")
    name = ""
    if sdr_map and sensor_num in sdr_map:
        name = sdr_map[sensor_num].name
    sensor_label = f"{type_name} {name}" if name else f"{type_name} #0x{sensor_num:02x}"
    # Non-standard SEL record types (OEM range 0xC0-0xFF) — IPMI 2.0 §32.2.
    if rec_type != 0x02:
        return (f"{record_id:4x} | {date} | {tstr} | "
                f"OEM record type 0x{rec_type:02x}")
    event_desc = _event_description(sensor_type, ev_byte, ev_data1)
    return (f"{record_id:4x} | {date} | {tstr} | {sensor_label} | "
            f"{event_desc} | {direction}")
