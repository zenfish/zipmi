# z-artifact: 6234cf6e-79b6-4d6f-aa8b-e00e8872f872
"""
zipmi.scapy_ipmi.oem.nvidia — Nvidia OpenBMC OEM commands (raw NetFn 0x3C).

WHAT     Nvidia's OEM commands ship inside phosphor-host-ipmid's `oem/nvidia`.
         Despite the constant being named `groupNvidia`, they are registered
         with `ipmi::registerHandler(prioOemBase, groupNvidia, cmd, ...)` —
         i.e. `groupNvidia = 0x3C` is passed in the **NetFn** position, so
         these are RAW NetFn 0x3C commands, NOT a NetFn 0x2C group extension.
         (registerHandler keys on (NetFn, cmd); registerGroupHandler would be
         the 0x2C group form, and Nvidia does not use it.)

WHY      Bootstrap-credential + BIOS-password commands: Get Redfish Host Name
         (0x3C/0x32), Get Redfish Service UUID (0x3C/0x34), Set/Get BIOS
         Password (0x3C/0x36,0x37). All Admin privilege.

WIRE     Raw NetFn 0x3C — COLLIDES with Ampere and Inspur (both raw 0x3C).
         Nvidia uses cmd bytes 0x30–0x37, which don't overlap Ampere's or
         Inspur's cmd bytes, but you should still load exactly the vendor you
         target. No IANA on the wire (registered None).

LOAD     `zipmi.load_vendor("nvidia")`

SOURCE   github.com/openbmc/phosphor-host-ipmid oem/nvidia
         (bootstrap-credentials-oem-cmds.cpp:199 `registerHandler(prioOemBase,
         groupNvidia, ...)`; oemcommands.hpp:13 `constexpr Group groupNvidia
         = 0x3C`). Verified 2026-06 against fresh upstream — corrects an
         earlier mis-modeling as a 0x2C group extension.
"""

from __future__ import annotations

from scapy.fields import ByteField, StrField
from scapy.packet import Packet

from ._registry import build_fixed_packet_class, register


NVIDIA_NETFN = 0x3C  # groupNvidia, used as a raw NetFn
NVIDIA_GB200_IMAGE_SHA256 = "a0a866fa6a3fdda49d9beec0a7efe6aadd234866e39bbefde2e05f45d5439495"
NVIDIA_PROVIDER_SHA256 = "2ab52c7a110c83a3ef90687ec114f91b8d9202958d7dc688be596da6a6995ab4"
NVIDIA_PROVIDER_BUILD_ID = "73ac315f5dc971099e45efd57efa60f56b1c41e5"
NVIDIA_SOURCE_COMMIT = "44890aba03e8f56f965a46cb872f6c23285610ad"

# Keys are (NetFn, Cmd[, fixed-prefix-bytes]). A 3rd+ element is a fixed
# request-data prefix the CLI auto-supplies (see cli/oem_cmds.py dispatch), so
# the user never types a mandatory selector. BIOS Get/Set only accept password
# selector id=0x01 (admin) — the handler rejects anything else with 0xC9 — so
# 0x01 is baked in: `ob-nvidia get-bios-password` needs no data; set adds only
# the variable type+salt+hash after it.
NVIDIA_CMD_NAMES: dict[tuple[int, ...], str] = {
    (0x3C, 0x30): "Nvidia Get USB Vendor/Product ID",  # + type byte (1=VID, 2=PID)
    (0x3C, 0x31): "Nvidia Get USB Serial Number",
    (0x3C, 0x32): "Nvidia Get Redfish Host Name",
    (0x3C, 0x33): "Nvidia Get IPMI Channel for Redfish-HI",
    (0x3C, 0x34): "Nvidia Get Redfish Service UUID",
    (0x3C, 0x35): "Nvidia Get Redfish Service Port",
    (0x3C, 0x36, 0x01): "Nvidia Set BIOS Password",  # id=0x01; + type+salt[32]+hash[64]
    (0x3C, 0x37, 0x01): "Nvidia Get BIOS Password",  # id=0x01; no further data
}


class NvidiaRedfishHostnameResponse(Packet):
    """Completion code followed by the un-terminated D-Bus HostName bytes."""

    name = "NVIDIA Get Redfish Host Name Response"
    fields_desc = [ByteField("completion_code", 0), StrField("hostname", b"")]

    def extract_padding(self, data):
        return b"", data


class NvidiaRedfishUuidResponse(Packet):
    """Completion code followed by every UUID byte the permissive parser emitted."""

    name = "NVIDIA Get Redfish Service UUID Response"
    fields_desc = [ByteField("completion_code", 0), StrField("uuid", b"")]

    def extract_padding(self, data):
        return b"", data


def _fixed(name: str, fields: list[dict], *, required: bool = False) -> type[Packet]:
    return build_fixed_packet_class(name, fields, require_fields=required)


_EMPTY_REQUEST = _fixed("NVIDIA Empty Request", [], required=True)
_EMPTY_RESPONSE = _fixed(
    "NVIDIA Empty Response", [{"name": "completion_code", "kind": "u8"}]
)

NVIDIA_PAYLOADS = {
    (0x3C, 0x30): (
        _fixed("NVIDIA Get USB VID/PID Request", [
            {"name": "descriptor_type", "kind": "u8"},
        ], required=True),
        _fixed("NVIDIA Get USB VID/PID Response", [
            {"name": "completion_code", "kind": "u8"},
            {"name": "descriptor", "kind": "u16be"},
        ]),
    ),
    (0x3C, 0x31): (
        _EMPTY_REQUEST,
        _fixed("NVIDIA Get USB Serial Number Response", [
            {"name": "completion_code", "kind": "u8"},
            {"name": "serial_number", "kind": "u8"},
        ]),
    ),
    (0x3C, 0x32): (_EMPTY_REQUEST, NvidiaRedfishHostnameResponse),
    (0x3C, 0x33): (
        _EMPTY_REQUEST,
        _fixed("NVIDIA Get Redfish-HI Channel Response", [
            {"name": "completion_code", "kind": "u8"},
            {"name": "channel", "kind": "u8"},
        ]),
    ),
    (0x3C, 0x34): (_EMPTY_REQUEST, NvidiaRedfishUuidResponse),
    (0x3C, 0x35): (
        _EMPTY_REQUEST,
        _fixed("NVIDIA Get Redfish Service Port Response", [
            {"name": "completion_code", "kind": "u8"},
            {"name": "port", "kind": "u16be"},
        ]),
    ),
    (0x3C, 0x36, 0x01): (
        _fixed("NVIDIA Set BIOS Password Request", [
            {"name": "password_id", "kind": "u8", "constant": 0x01},
            {"name": "password_type", "kind": "u8"},
            {"name": "salt", "kind": "bytes", "length": 32},
            {"name": "password_hash", "kind": "bytes", "length": 64},
        ], required=True),
        _EMPTY_RESPONSE,
    ),
    (0x3C, 0x37, 0x01): (
        _fixed("NVIDIA Get BIOS Password Request", [
            {"name": "password_id", "kind": "u8", "constant": 0x01},
        ], required=True),
        _fixed("NVIDIA Get BIOS Password Response", [
            {"name": "completion_code", "kind": "u8"},
            {"name": "password_type", "kind": "u8"},
            {"name": "salt", "kind": "bytes", "length": 32},
            {"name": "password_hash", "kind": "bytes", "length": 64},
        ]),
    ),
}


def _field(offset: str, name: str, kind: str, meaning: str) -> dict[str, str]:
    return {"offset": offset, "name": name, "type": kind, "meaning": meaning}


# Firmware-bound operation contracts. Lengths exclude the completion-code byte.
NVIDIA_COMMANDS: dict[tuple[int, ...], dict] = {
    (0x3C, 0x30): {
        "name": "Get USB Vendor/Product ID", "handler": "ipmiGetUsbVendorIdProductId",
        "purpose": "Return the Redfish Host Interface USB gadget vendor or product ID.",
        "request_length": (1, 1), "response_length": (2, 2), "safety": "read-only",
        "request_fields": [_field("0", "descriptor_type", "u8", "1 = vendor ID; 2 = product ID")],
        "response_fields": [_field("0–1", "descriptor", "u16be", "0x0525 vendor or 0xa4a2 product ID")],
        "completion_codes": "0x00 success; 0xcc invalid descriptor type",
        "side_effects": "No persistent or service effect.",
    },
    (0x3C, 0x31): {
        "name": "Get USB Serial Number", "handler": "ipmiGetUsbSerialNumber",
        "purpose": "Return the one-byte USB gadget serial-number placeholder.",
        "request_length": (0, 0), "response_length": (1, 1), "safety": "read-only",
        "request_fields": [],
        "response_fields": [_field("0", "serial_number", "u8", "Always 0x00 in this provider")],
        "completion_codes": "0x00 success", "side_effects": "No persistent or service effect.",
    },
    (0x3C, 0x32): {
        "name": "Get Redfish Host Name", "handler": "ipmiGetRedfishHostName",
        "purpose": "Read the OpenBMC network SystemConfiguration HostName property.",
        "request_length": (0, 0), "response_length": (0, None), "safety": "read-only",
        "request_fields": [],
        "response_fields": [_field("0–end", "hostname", "byte string", "HostName bytes without a terminator")],
        "completion_codes": "0x00 success; 0xce response error",
        "side_effects": "D-Bus property read only.",
    },
    (0x3C, 0x33): {
        "name": "Get IPMI Channel for Redfish-HI", "handler": "ipmiGetIpmiChannelRfHi",
        "purpose": "Resolve usb0 and return its IPMI channel number after validating its channel type.",
        "request_length": (0, 0), "response_length": (1, 1), "safety": "read-only",
        "request_fields": [],
        "response_fields": [_field("0", "channel", "u8", "IPMI channel assigned to usb0")],
        "completion_codes": "0x00 success; 0xcb invalid channel configuration; 0xff channel lookup error",
        "side_effects": "Channel metadata read only.",
        "activation_note": (
            "Registered, but the pinned target names channel 3 hostusb0 while the handler looks "
            "up usb0; this integration mismatch predicts 0xff on this image."
        ),
    },
    (0x3C, 0x34): {
        "name": "Get Redfish Service UUID", "handler": "ipmiGetRedfishServiceUUID",
        "purpose": "Return the Redfish service UUID in DSP0270 mixed-endian wire order.",
        "request_length": (0, 0), "response_length": (0, None), "safety": "read-only",
        "request_fields": [],
        "response_fields": [_field(
            "0–end", "uuid", "byte string",
            "Normally 16 DSP0270 bytes; the first three UUID groups are little-endian. "
            "Invalid hex pairs are silently omitted, so malformed persistent data can return fewer bytes with success.",
        )],
        "completion_codes": "0x00 success; 0xce response error",
        "side_effects": (
            "Reads only system_uuid from /home/root/bmcweb_persistent_data.json. An odd-length "
            "UUID group reaches an unchecked group[j+1] access in the provider."
        ),
    },
    (0x3C, 0x35): {
        "name": "Get Redfish Service Port", "handler": "ipmiGetRedfishServicePort",
        "purpose": "Return the fixed HTTPS Redfish service port 443.",
        "request_length": (0, 0), "response_length": (2, 2), "safety": "read-only",
        "request_fields": [],
        "response_fields": [_field("0–1", "port", "u16be", "TCP port; fixed value 443 (0x01bb)")],
        "completion_codes": "0x00 success", "side_effects": "No persistent or service effect.",
    },
    (0x3C, 0x36, 0x01): {
        "name": "Set BIOS Password", "handler": "ipmiSetBiosPassword",
        "purpose": "Set or clear the BIOS Setup admin credential by replacing its seed and PBKDF2 hash.",
        "request_length": (98, 98), "response_length": (0, 0), "safety": "sensitive",
        "request_fields": [
            _field("0", "password_id", "u8", "Must be 0x01 (admin)"),
            _field("1", "password_type", "u8", "1 = no password; 2 = PBKDF2-SHA256; 3 = PBKDF2-SHA384"),
            _field("2–33", "salt", "32 bytes", "PBKDF2 salt; regenerated by firmware for type 1"),
            _field("34–97", "password_hash", "64 bytes", "Stored verbatim for types 2/3; SHA-256 callers conventionally zero-pad its 32-byte digest"),
        ],
        "response_fields": [],
        "completion_codes": (
            "0x00 success; 0xcc invalid selector/type; 0xff thrown exception while "
            "building or writing JSON (ordinary stream failures are not checked)"
        ),
        "side_effects": (
            "BIOS-credential write primitive: writes /var/lib/bios-settings-manager/seedData; "
            "type 1 replaces the salt and the first 32 hash bytes with a one-NUL-byte SHA-256 "
            "verifier, but preserves caller-supplied hash bytes 32–63. Those trailing bytes must "
            "be zero for Get to recognize NoPassword. Types 2/3 trust all caller-supplied material. "
            "The write resets both changed flags, zeroes UserPwdHash, has no channel gate, and does "
            "not check RAND_bytes or ordinary ofstream open/write failures before returning success."
        ),
    },
    (0x3C, 0x37, 0x01): {
        "name": "Get BIOS Password", "handler": "ipmiGetBiosPassword",
        "purpose": "Return the pending BIOS Setup admin-password action, salt, and PBKDF2 hash.",
        "request_length": (1, 1), "response_length": (97, 97), "safety": "sensitive",
        "request_fields": [_field("0", "password_id", "u8", "Must be 0x01 (admin)")],
        "response_fields": [
            _field("0", "password_type", "u8", "0 = unchanged; 1 = no password; 2 = PBKDF2-SHA256; 3 = PBKDF2-SHA384"),
            _field("1–32", "salt", "32 bytes", "Stored PBKDF2 salt, or zeros when unchanged/no password"),
            _field("33–96", "password_hash", "64 bytes", "Stored PBKDF2 hash, or zeros when unchanged/no password"),
        ],
        "completion_codes": "0x00 success; 0xc9 selector out of range; 0xce malformed stored data",
        "side_effects": (
            "Remote credential-material disclosure when IsAdminPwdChanged is true: returns a "
            "32-byte salt and 64-byte PBKDF2 verifier with no channel or POST gate. Missing files "
            "or a false flag return action 0 plus zeros; the one-NUL-byte verifier returns action 1 "
            "plus zeros. An unknown HashAlgo can return action 0 with nonzero credential material."
        ),
        "live": (
            "2026-07-22 authenticated RMCP+/cipher-17 proof returned action 2 plus the planted "
            "salt/hash; the test password Calvin was recovered offline."
        ),
    },
}

for _key, _command in NVIDIA_COMMANDS.items():
    _command["completion_codes"] += "; 0xc7 invalid request length; 0xd4 insufficient privilege"
    _command.update({
        "privilege": "Admin",
        "activation": _command.get(
            "activation_note", "Constructor-registered by libnvidia_ipmi_oem.so.0.1"
        ),
        "evidence": f"{_command['handler']} in the target provider and matching OpenBMC source",
        "confidence": "Exact source contract; handler and registration present in target provider",
    })


# Vendor detection: Get Redfish Service UUID (0x3C/0x34) is a harmless read.
NVIDIA_DETECT_PROBE = (0x3C, 0x34)


register("nvidia", None, NVIDIA_CMD_NAMES, NVIDIA_PAYLOADS)


__all__ = [
    "NVIDIA_NETFN", "NVIDIA_CMD_NAMES", "NVIDIA_COMMANDS", "NVIDIA_PAYLOADS",
    "NVIDIA_DETECT_PROBE", "NVIDIA_GB200_IMAGE_SHA256", "NVIDIA_PROVIDER_SHA256",
    "NVIDIA_PROVIDER_BUILD_ID", "NVIDIA_SOURCE_COMMIT", "NvidiaRedfishHostnameResponse",
    "NvidiaRedfishUuidResponse",
]
