"""
zipmi.scapy_ipmi.commands — per-command request/response payload registry.

WHAT     A `(netfn_request, cmd) → Packet class` lookup table plus the actual
         Packet classes for the commands we support so far. The base
         IPMI_Message layer doesn't know cmd-specific payload shapes; this
         module supplies them and (eventually) wires them in via
         `IPMI_Message.guess_payload_class`.

WHY      Spec commands have well-defined req/resp byte layouts. Modeling
         them as Scapy Packets gives us pretty-printing, build-from-args,
         and (Phase 6) one-line `fuzz()` per command.

         OEM commands stay OUT of this file — they live under
         `zipmi.scapy_ipmi.oem.<vendor>` and register lazily via
         `zipmi.load_vendor()`.

SUCCESS  `GetChanAuthCapsReq(channel=0xE, max_priv=0x4)` builds the 2-byte
         spec payload; the response Packet decodes a real BMC reply
         end-to-end.

TARGET   IPMI 1.5 §22.13 (Get Channel Authentication Capabilities).
         More commands will be added as Phase 1 progresses.

RELATED  ipmi15.py, /Users/zen/phd/dox/specs/IPMI-1.5.pdf
"""

from __future__ import annotations

from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    LEIntField,
    LEShortField,
    StrField,
    StrFixedLenField,
    XByteField,
)
from scapy.packet import Packet

from ..consts import COMP_CODE


# -- Get Channel Authentication Capabilities (NetFn 0x06 App, Cmd 0x38) --
# Sessionless: can be sent before any IPMI session is established.
# Spec: IPMI 1.5 §22.13, IPMI 2.0 §22.13.

class GetChanAuthCapsReq(Packet):
    name = "Get Channel Auth Caps Request"
    fields_desc = [
        # Bit 7 (high) = "Get IPMI v2.0 extended data" when set; low 4 bits
        # are the channel number (0xE = "current channel").
        BitField("v20_ext", 0, 1),
        BitField("reserved", 0, 3),
        BitField("channel", 0xE, 4),
        # Lower 4 bits = requested max privilege level (1 Callback ... 4 Admin).
        BitField("reserved2", 0, 4),
        BitField("max_priv", 0x4, 4),
    ]

    def extract_padding(self, s):
        return b"", s


class GetChanAuthCapsResp(Packet):
    name = "Get Channel Auth Caps Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        ByteField("channel", 0),
        # auth_type_support byte:
        #   bit 7  = supports IPMI v2.0 connections (when v20_ext was set in req)
        #   bit 6  = reserved
        #   bit 5  = OEM proprietary
        #   bit 4  = Straight Password
        #   bit 3  = reserved
        #   bit 2  = MD5
        #   bit 1  = MD2
        #   bit 0  = none (no auth)
        XByteField("auth_type_support", 0x00),
        # status / capabilities byte:
        #   bit 5  = anonymous login enabled
        #   bit 4  = null username support
        #   bit 3  = non-null username support
        #   bit 2  = per-message auth disabled
        #   bit 1  = user-level auth disabled
        #   bit 0  = anonymous login non-null username
        XByteField("status", 0x00),
        # ext capabilities byte (IPMI 2.0):
        #   bit 1 = supports IPMI v2.0
        #   bit 0 = supports IPMI v1.5
        XByteField("ext_caps", 0x00),
        # OEM IANA — 3 bytes LE per spec (NOT 4!).
        StrFixedLenField("oem_iana", b"\x00\x00\x00", 3),
        ByteField("oem_aux", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s

    def auth_types(self) -> list[str]:
        """Decode auth_type_support bitmask to human names."""
        bits = self.auth_type_support
        names = []
        if bits & 0x01: names.append("None")
        if bits & 0x02: names.append("MD2")
        if bits & 0x04: names.append("MD5")
        if bits & 0x10: names.append("StraightPwd")
        if bits & 0x20: names.append("OEM")
        if bits & 0x80: names.append("IPMI2.0")
        return names

    def oem_iana_int(self) -> int:
        """Decode the 3-byte LE OEM IANA field as an integer."""
        b = self.oem_iana
        return b[0] | (b[1] << 8) | (b[2] << 16)


# -- Get Device ID (NetFn 0x06 App, Cmd 0x01) --
# Spec: IPMI 1.5 §17.1 / IPMI 2.0 §20.1. Common "is the BMC alive" probe.

class GetDeviceIDResp(Packet):
    name = "Get Device ID Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        ByteField("device_id", 0),
        XByteField("device_revision", 0),     # bit 7 = SDR support; low 4 = rev
        XByteField("fw_revision_1", 0),       # bit 7 = device avail; low 7 = major
        ByteField("fw_revision_2", 0),        # BCD minor
        ByteField("ipmi_version", 0),         # 0x51 = 1.5; 0x02 = 2.0 BCD swapped
        XByteField("additional_dev_support", 0),
        StrFixedLenField("manufacturer_id", b"\x00\x00\x00", 3),  # 3-byte LE IANA
        LEShortField("product_id", 0),
        # Aux Firmware Revision Info (4 bytes, optional). We treat as fixed
        # 4-byte trailing field; if BMC omits, dissection just yields b''.
        StrFixedLenField("aux_fw_rev", b"\x00\x00\x00\x00", 4),
    ]

    def extract_padding(self, s):
        return b"", s

    def manufacturer_id_int(self) -> int:
        b = self.manufacturer_id
        return b[0] | (b[1] << 8) | (b[2] << 16)

    def fw_revision(self) -> str:
        """Decode firmware revision as a 'major.minor' string."""
        major = self.fw_revision_1 & 0x7F
        minor = self.fw_revision_2
        return f"{major}.{minor:02x}"


# -- Get Chassis Status (NetFn 0x00 Chassis, Cmd 0x01) --
# Spec: IPMI 1.5 §22.5.

class GetChassisStatusResp(Packet):
    name = "Get Chassis Status Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        XByteField("current_power_state", 0),
        XByteField("last_power_event", 0),
        XByteField("misc_chassis_state", 0),
        # Optional 4th byte (front panel button caps) — not all BMCs return it.
        ByteField("front_panel", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s

    def power_on(self) -> bool:
        return bool(self.current_power_state & 0x01)


# -- Get Session Challenge (NetFn 0x06 App, Cmd 0x39) --
# Spec: IPMI 1.5 §22.16. Sessionless. Returns a 16-byte challenge string
# and a temporary session ID used by the subsequent Activate Session.

class GetSessionChallengeReq(Packet):
    name = "Get Session Challenge Request"
    fields_desc = [
        ByteEnumField("auth_type", 0x02, AUTH_TYPE_REQ_ENUM := {
            0x00: "None", 0x01: "MD2", 0x02: "MD5",
            0x04: "StraightPwd", 0x05: "OEM",
        }),
        StrFixedLenField("user_name", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSessionChallengeResp(Packet):
    name = "Get Session Challenge Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        LEIntField("temp_session_id", 0),
        StrFixedLenField("challenge", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Activate Session (NetFn 0x06 App, Cmd 0x3A) --
# Spec: IPMI 1.5 §22.17. First AUTHENTICATED message in a session.

class ActivateSessionReq(Packet):
    name = "Activate Session Request"
    fields_desc = [
        ByteField("auth_type", 0x02),       # MD5 by default
        ByteField("max_priv", 0x04),        # Admin
        StrFixedLenField("challenge", b"\x00" * 16, 16),
        LEIntField("init_outbound_seq", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class ActivateSessionResp(Packet):
    name = "Activate Session Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        ByteField("auth_type", 0x00),       # 0 means per-msg auth disabled
        LEIntField("session_id", 0),
        LEIntField("init_inbound_seq", 0),
        ByteField("max_priv", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Set Session Privilege Level (NetFn 0x06 App, Cmd 0x3B) --
# Spec: IPMI 1.5 §22.18.

class SetSessionPrivLevelReq(Packet):
    name = "Set Session Priv Level Request"
    fields_desc = [
        BitField("reserved", 0, 4),
        BitField("priv", 0x4, 4),
    ]

    def extract_padding(self, s):
        return b"", s


class SetSessionPrivLevelResp(Packet):
    name = "Set Session Priv Level Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        BitField("reserved", 0, 4),
        BitField("priv", 0, 4),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Close Session (NetFn 0x06 App, Cmd 0x3C) --
# Spec: IPMI 1.5 §22.19.

class CloseSessionReq(Packet):
    name = "Close Session Request"
    fields_desc = [LEIntField("session_id", 0)]

    def extract_padding(self, s):
        return b"", s


class CloseSessionResp(Packet):
    name = "Close Session Response"
    fields_desc = [ByteEnumField("comp_code", 0x00, COMP_CODE)]

    def extract_padding(self, s):
        return b"", s


# -- Chassis Power Control (NetFn 0x00 Chassis, Cmd 0x02) --
# Spec: IPMI 1.5 §22.6.

CHASSIS_CTRL = {
    0x00: "down",
    0x01: "up",
    0x02: "cycle",
    0x03: "reset",
    0x04: "pulse_diag",
    0x05: "soft",
}


class ChassisControlReq(Packet):
    name = "Chassis Control Request"
    fields_desc = [
        BitField("reserved", 0, 4),
        BitEnumField("action", 0x00, 4, CHASSIS_CTRL),
    ]

    def extract_padding(self, s):
        return b"", s


class ChassisControlResp(Packet):
    name = "Chassis Control Response"
    fields_desc = [ByteEnumField("comp_code", 0x00, COMP_CODE)]

    def extract_padding(self, s):
        return b"", s


# -- Get SEL Info (NetFn 0x0A Storage, Cmd 0x40) --
# Spec: IPMI 1.5 §31.2.

class GetSELInfoResp(Packet):
    name = "Get SEL Info Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        XByteField("version", 0x51),
        LEShortField("entries", 0),
        LEShortField("free_space", 0),
        LEIntField("last_add_ts", 0),
        LEIntField("last_del_ts", 0),
        XByteField("op_support", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Cold Reset / Warm Reset (NetFn 0x06 App, Cmd 0x02 / 0x03) --
# Spec: IPMI 1.5 §17.2 / §17.3. Both: no request data, response is just cc.

class _BareCCResp(Packet):
    name = "Bare Completion Code Response"
    fields_desc = [ByteEnumField("comp_code", 0x00, COMP_CODE)]

    def extract_padding(self, s):
        return b"", s


# -- Get Channel Cipher Suites (NetFn 0x06 App, Cmd 0x54) — IPMI 2.0 §22.15 --
# Useful for the `scan` verb. Sessionless. Variable-length response payload.

class GetChannelCipherSuitesReq(Packet):
    name = "Get Channel Cipher Suites Request"
    fields_desc = [
        ByteField("channel", 0xE),
        ByteField("payload_type", 0x00),  # 0 = IPMI
        XByteField("list_index", 0x80),   # bit 7 = list algos by cipher suite
    ]

    def extract_padding(self, s):
        return b"", s


# -- Get Self Test Results (App, 0x04) — IPMI 1.5 §17.4 --

GET_SELF_TEST = {
    0x55: "Passed",
    0x56: "NoSelfTest",
    0x57: "CorruptedOrInaccessible",
    0x58: "FatalHWError",
}


class GetSelfTestResultsResp(Packet):
    name = "Get Self Test Results Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        ByteEnumField("result", 0x55, GET_SELF_TEST),
        XByteField("info", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Get Device GUID (App, 0x08) / Get System GUID (App, 0x37) --

class GetDeviceGUIDResp(Packet):
    name = "Get Device GUID Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        StrFixedLenField("guid", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSystemGUIDResp(Packet):
    name = "Get System GUID Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        StrFixedLenField("guid", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Get Channel Info (App, 0x42) — IPMI 1.5 §22.24 --

CHANNEL_MEDIUM = {
    0x01: "IPMB-1.0",
    0x02: "ICMB-1.0",
    0x04: "LAN-802.3",
    0x05: "Serial",
    0x06: "OtherLAN",
    0x07: "PCI-SMBus",
    0x08: "SMBus-1.0",
    0x09: "SMBus-2.0",
    0x0C: "SystemInterface",
}

CHANNEL_PROTOCOL = {
    0x01: "IPMB-1.0",
    0x02: "ICMB-1.0",
    0x04: "IPMI-SMBus",
    0x05: "KCS",
    0x06: "SMIC",
    0x07: "BT-10",
    0x08: "BT-15",
    0x09: "TMODE",
}


class GetChannelInfoReq(Packet):
    name = "Get Channel Info Request"
    fields_desc = [ByteField("channel", 0xE)]

    def extract_padding(self, s):
        return b"", s


class GetChannelInfoResp(Packet):
    name = "Get Channel Info Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        ByteField("channel", 0),
        ByteEnumField("medium", 0, CHANNEL_MEDIUM),
        ByteEnumField("protocol", 0, CHANNEL_PROTOCOL),
        XByteField("session_support", 0),
        StrFixedLenField("oem_iana", b"\x00\x00\x00", 3),
        ByteField("aux1", 0),
        ByteField("aux2", 0),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Get User Access (App, 0x44) / Get User Name (App, 0x46) --

class GetUserAccessReq(Packet):
    name = "Get User Access Request"
    fields_desc = [
        BitField("reserved1", 0, 4),
        BitField("channel", 0xE, 4),
        BitField("reserved2", 0, 2),
        BitField("user_id", 1, 6),
    ]

    def extract_padding(self, s):
        return b"", s


class GetUserAccessResp(Packet):
    name = "Get User Access Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        XByteField("max_user_count", 0),
        XByteField("enabled_user_count", 0),
        XByteField("fixed_name_users", 0),
        XByteField("user_access", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class GetUserNameReq(Packet):
    name = "Get User Name Request"
    fields_desc = [ByteField("user_id", 1)]

    def extract_padding(self, s):
        return b"", s


class GetUserNameResp(Packet):
    name = "Get User Name Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        StrFixedLenField("user_name", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


# -- Get Sensor Reading (Sensor/Event, 0x2D) — IPMI 1.5 §35.14 --

class GetSensorReadingReq(Packet):
    name = "Get Sensor Reading Request"
    fields_desc = [ByteField("sensor_number", 0)]

    def extract_padding(self, s):
        return b"", s


class GetSensorReadingResp(Packet):
    name = "Get Sensor Reading Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        ByteField("reading", 0),
        XByteField("status", 0),
        XByteField("thresh1", 0),
        XByteField("thresh2", 0),
    ]

    def extract_padding(self, s):
        return b"", s


# -- FRU Inventory (Storage, 0x10/0x11) --

class GetFRUInventoryInfoReq(Packet):
    name = "Get FRU Inventory Area Info Request"
    fields_desc = [ByteField("fru_id", 0)]

    def extract_padding(self, s):
        return b"", s


class GetFRUInventoryInfoResp(Packet):
    name = "Get FRU Inventory Area Info Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        LEShortField("size", 0),
        XByteField("access", 0),
    ]

    def extract_padding(self, s):
        return b"", s


# -- SDR Repository (Storage, 0x20/0x22/0x23) --

class GetSDRRepositoryInfoResp(Packet):
    name = "Get SDR Repository Info Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        XByteField("sdr_version", 0x51),
        LEShortField("record_count", 0),
        LEShortField("free_space", 0),
        LEIntField("add_ts", 0),
        LEIntField("del_ts", 0),
        XByteField("op_support", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class ReserveSDRRepoResp(Packet):
    name = "Reserve SDR Repository Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        LEShortField("reservation_id", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSDRReq(Packet):
    name = "Get SDR Request"
    fields_desc = [
        LEShortField("reservation_id", 0),
        LEShortField("record_id", 0),
        ByteField("offset", 0),
        ByteField("count", 0xFF),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSDRResp(Packet):
    name = "Get SDR Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        LEShortField("next_record_id", 0xFFFF),
        StrField("record_data", b""),    # consume to end of payload
    ]

    def extract_padding(self, s):
        return b"", s


# -- SEL (Storage, 0x42/0x43) --

class ReserveSELResp(Packet):
    name = "Reserve SEL Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        LEShortField("reservation_id", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSELEntryReq(Packet):
    name = "Get SEL Entry Request"
    fields_desc = [
        LEShortField("reservation_id", 0),
        LEShortField("record_id", 0),
        ByteField("offset", 0),
        ByteField("count", 0xFF),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSELEntryResp(Packet):
    name = "Get SEL Entry Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        LEShortField("next_record_id", 0xFFFF),
        # Standard SEL record = 16 bytes (record_id + type + ts + gen_id +
        # ev_msg_rev + sensor_type + sensor_num + ev_dir|type + ev1 + ev2 + ev3).
        StrFixedLenField("record", b"\x00" * 16, 16),
    ]

    def extract_padding(self, s):
        return b"", s


# -- System Boot Options (Chassis, 0x08 / 0x09) — IPMI 2.0 §28.12-28.13 --
#
# Boot device override is the classic BMC->host attack: force a host into
# PXE / CD / safe mode for the next boot, no host cooperation required.

BOOT_DEVICE = {
    0b0000: "no_override",
    0b0001: "pxe",
    0b0010: "hd",
    0b0011: "hd_safe_mode",
    0b0100: "diag_partition",
    0b0101: "cd_dvd",
    0b0110: "bios_setup",
    0b0111: "remote_floppy",
    0b1000: "remote_cdrom",
    0b1001: "remote_primary_media",
    0b1011: "remote_hd",
    0b1111: "float_boot",
}


class SetSystemBootOptionsReq(Packet):
    """Generic set request: selector + parameter data.

    For boot flags (selector 5) the data is 5 bytes:
      byte 0: bit 7=valid, bit 6=persistent, bit 5=BIOS verbosity, ...
      byte 1: bit 7-2 = boot_device (use BOOT_DEVICE), bit 1=lock kb, bit 0=screen blank
      byte 2: BIOS console redirection / verbosity
      byte 3: device instance / share
      byte 4: reserved
    """

    name = "Set System Boot Options Request"
    fields_desc = [
        BitField("mark_valid", 0, 1),
        BitField("parameter_selector", 0, 7),
        StrField("parameter_data", b""),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSystemBootOptionsReq(Packet):
    name = "Get System Boot Options Request"
    fields_desc = [
        BitField("get_param_revision", 0, 1),
        BitField("parameter_selector", 0, 7),
        ByteField("set_selector", 0),
        ByteField("block_selector", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class GetSystemBootOptionsResp(Packet):
    name = "Get System Boot Options Response"
    fields_desc = [
        ByteEnumField("comp_code", 0x00, COMP_CODE),
        XByteField("parameter_revision", 0),
        # parameter_selector echoed; high bit = valid
        XByteField("parameter_selector", 0),
        StrField("parameter_data", b""),
    ]

    def extract_padding(self, s):
        return b"", s


def encode_boot_flags(device: str, persistent: bool = False,
                      uefi: bool = False) -> bytes:
    """Build the 5-byte parameter_data for boot-flags selector 5."""
    code_by_name = {v: k for k, v in BOOT_DEVICE.items()}
    if device not in code_by_name:
        raise ValueError(f"unknown boot device {device!r}")
    flags = 0x80                        # bit 7 = valid
    if persistent:
        flags |= 0x40
    if uefi:
        flags |= 0x20
    dev_byte = (code_by_name[device] & 0x0F) << 2
    return bytes([flags, dev_byte, 0, 0, 0])


# -- Transport: Get LAN Configuration Parameters (0x0C, 0x02) --

class GetLANConfigParamReq(Packet):
    name = "Get LAN Config Parameters Request"
    fields_desc = [
        BitField("get_param_revision", 0, 1),
        BitField("reserved", 0, 3),
        BitField("channel", 0xE, 4),
        ByteField("parameter_selector", 0),
        ByteField("set_selector", 0),
        ByteField("block_selector", 0),
    ]

    def extract_padding(self, s):
        return b"", s


# Registry: (request_netfn, cmd) → (RequestPacket | None, ResponsePacket).
# Request payload of None means the command takes no data field.
CMD_PAYLOADS: dict[tuple[int, int], tuple[type[Packet] | None, type[Packet]]] = {
    (0x06, 0x38): (GetChanAuthCapsReq,      GetChanAuthCapsResp),
    (0x06, 0x39): (GetSessionChallengeReq,  GetSessionChallengeResp),
    (0x06, 0x3A): (ActivateSessionReq,      ActivateSessionResp),
    (0x06, 0x3B): (SetSessionPrivLevelReq,  SetSessionPrivLevelResp),
    (0x06, 0x3C): (CloseSessionReq,         CloseSessionResp),
    (0x06, 0x01): (None,                    GetDeviceIDResp),
    (0x06, 0x02): (None,                    _BareCCResp),       # Cold Reset
    (0x06, 0x03): (None,                    _BareCCResp),       # Warm Reset
    (0x06, 0x04): (None,                    GetSelfTestResultsResp),
    (0x06, 0x08): (None,                    GetDeviceGUIDResp),
    (0x06, 0x37): (None,                    GetSystemGUIDResp),
    (0x06, 0x42): (GetChannelInfoReq,       GetChannelInfoResp),
    (0x06, 0x44): (GetUserAccessReq,        GetUserAccessResp),
    (0x06, 0x46): (GetUserNameReq,          GetUserNameResp),
    (0x06, 0x54): (GetChannelCipherSuitesReq, _BareCCResp),     # see scan verb
    (0x00, 0x01): (None,                    GetChassisStatusResp),
    (0x00, 0x02): (ChassisControlReq,       ChassisControlResp),
    (0x00, 0x08): (SetSystemBootOptionsReq, _BareCCResp),
    (0x00, 0x09): (GetSystemBootOptionsReq, GetSystemBootOptionsResp),
    (0x04, 0x2D): (GetSensorReadingReq,     GetSensorReadingResp),
    (0x0A, 0x10): (GetFRUInventoryInfoReq,  GetFRUInventoryInfoResp),
    (0x0A, 0x20): (None,                    GetSDRRepositoryInfoResp),
    (0x0A, 0x22): (None,                    ReserveSDRRepoResp),
    (0x0A, 0x23): (GetSDRReq,               GetSDRResp),
    (0x0A, 0x40): (None,                    GetSELInfoResp),
    (0x0A, 0x42): (None,                    ReserveSELResp),
    (0x0A, 0x43): (GetSELEntryReq,          GetSELEntryResp),
    (0x0C, 0x02): (GetLANConfigParamReq,    _BareCCResp),       # variable resp
}


def lookup(netfn_request: int, cmd: int) -> tuple[type[Packet] | None, type[Packet]] | None:
    """Return (req_cls, resp_cls) for a known command, or None."""
    return CMD_PAYLOADS.get((netfn_request & 0xFE, cmd))


__all__ = [
    "GetChanAuthCapsReq", "GetChanAuthCapsResp",
    "GetSessionChallengeReq", "GetSessionChallengeResp",
    "ActivateSessionReq", "ActivateSessionResp",
    "SetSessionPrivLevelReq", "SetSessionPrivLevelResp",
    "CloseSessionReq", "CloseSessionResp",
    "GetDeviceIDResp", "GetSelfTestResultsResp", "GetDeviceGUIDResp",
    "GetSystemGUIDResp", "GetChannelInfoReq", "GetChannelInfoResp",
    "GetUserAccessReq", "GetUserAccessResp",
    "GetUserNameReq", "GetUserNameResp",
    "GetChassisStatusResp", "ChassisControlReq", "ChassisControlResp",
    "GetSensorReadingReq", "GetSensorReadingResp",
    "GetFRUInventoryInfoReq", "GetFRUInventoryInfoResp",
    "GetSDRRepositoryInfoResp", "ReserveSDRRepoResp", "GetSDRReq", "GetSDRResp",
    "GetSELInfoResp", "ReserveSELResp", "GetSELEntryReq", "GetSELEntryResp",
    "GetLANConfigParamReq", "GetChannelCipherSuitesReq",
    "CHASSIS_CTRL", "CMD_PAYLOADS", "lookup",
]
