"""
zipmi.scapy_ipmi.rakp — IPMI 2.0 RMCP+ Open Session and RAKP 1-4.

WHAT     Five Scapy Packet classes for the RMCP+ session-establishment
         exchange (IPMI 2.0 §13.17 / §13.20):

           OpenSessionRequest    (payload type 0x10)
           OpenSessionResponse   (payload type 0x11)
           RAKP1                 (payload type 0x12)
           RAKP2                 (payload type 0x13)
           RAKP3                 (payload type 0x14)
           RAKP4                 (payload type 0x15)

WHY      RMCP+ sets up an authenticated and (optionally) confidential
         session via these five round-trips before any IPMI message can
         be sent. Modeling them as proper Packets lets us byte-diff
         against ipmitool oracle pcaps and (Phase 6) fuzz each field
         individually.

SUCCESS  Round-trip stable on every captured pcap; bytewise diff zero
         vs `ipmitool -I lanplus -C 3` for the four RAKP message bodies.

TARGET   IPMI 2.0 §13.17 (Open Session), §13.20 (RAKP), §13.28 (cipher
         suites).

RELATED  ipmi20.py, crypto.py, IPMI v2.0 specification
"""

from __future__ import annotations

from scapy.fields import (
    ByteField,
    FieldLenField,
    LEIntField,
    StrFixedLenField,
    StrLenField,
    XByteField,
)
from scapy.packet import Packet, bind_layers

from .ipmi20 import IPMI20_Session


# IPMI 2.0 §13.17 Table 13-10: Open Session Request payload (32 bytes).
#
# The spec embeds three "payload" sub-blocks (auth, integrity, conf), each
# 8 bytes. We model each as a fixed-size sub-Packet for clarity AND so
# the algorithm fields (auth/integrity/conf alg) are addressable for fuzz.

class CipherSubPayload(Packet):
    """Auth / integrity / confidentiality payload sub-block (8 bytes)."""
    name = "Cipher Sub-Payload"
    fields_desc = [
        ByteField("payload_type", 0x00),       # 0=auth, 1=integ, 2=conf
        ByteField("reserved1", 0x00),
        ByteField("reserved2", 0x00),
        ByteField("payload_length", 0x08),     # always 0x08
        XByteField("alg", 0x00),               # low 6 bits = algorithm number
        ByteField("reserved3", 0x00),
        ByteField("reserved4", 0x00),
        ByteField("reserved5", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


class OpenSessionRequest(Packet):
    name = "Open Session Request"
    fields_desc = [
        ByteField("msg_tag", 0x00),
        ByteField("max_priv", 0x00),           # 0 = unspecified, 4 = admin
        ByteField("reserved1", 0x00),
        ByteField("reserved2", 0x00),
        LEIntField("remote_session_id", 0),    # chosen by client
        StrFixedLenField("auth_payload",     b"\x00" * 8, 8),
        StrFixedLenField("integrity_payload", b"\x00" * 8, 8),
        StrFixedLenField("conf_payload",     b"\x00" * 8, 8),
    ]

    def extract_padding(self, s):
        return b"", s


class OpenSessionResponse(Packet):
    name = "Open Session Response"
    fields_desc = [
        ByteField("msg_tag", 0x00),
        XByteField("rmcp_status", 0x00),       # 0 = OK
        ByteField("max_priv", 0x00),
        ByteField("reserved", 0x00),
        LEIntField("remote_session_id", 0),    # echoed
        LEIntField("managed_session_id", 0),   # assigned by BMC
        StrFixedLenField("auth_payload",     b"\x00" * 8, 8),
        StrFixedLenField("integrity_payload", b"\x00" * 8, 8),
        StrFixedLenField("conf_payload",     b"\x00" * 8, 8),
    ]

    def extract_padding(self, s):
        return b"", s


class RAKP1(Packet):
    """RAKP Message 1 — sent by remote console (§13.20)."""
    name = "RAKP Message 1"
    fields_desc = [
        ByteField("msg_tag", 0x00),
        ByteField("reserved1", 0x00),
        ByteField("reserved2", 0x00),
        ByteField("reserved3", 0x00),
        LEIntField("managed_session_id", 0),   # from Open Session Resp
        StrFixedLenField("remote_random", b"\x00" * 16, 16),  # R_c
        # role/priv byte: bit 4 = name-only-lookup; low nibble = max priv.
        XByteField("role", 0x14),
        ByteField("reserved4", 0x00),
        ByteField("reserved5", 0x00),
        FieldLenField("user_name_len", None, length_of="user_name", fmt="B"),
        StrLenField("user_name", b"", length_from=lambda p: p.user_name_len),
    ]

    def extract_padding(self, s):
        return b"", s


class RAKP2(Packet):
    """RAKP Message 2 — response from BMC."""
    name = "RAKP Message 2"
    fields_desc = [
        ByteField("msg_tag", 0x00),
        XByteField("rmcp_status", 0x00),
        ByteField("reserved1", 0x00),
        ByteField("reserved2", 0x00),
        LEIntField("remote_session_id", 0),
        StrFixedLenField("managed_random", b"\x00" * 16, 16),  # R_m
        StrFixedLenField("managed_guid",   b"\x00" * 16, 16),
        # Key Exchange Auth Code: variable length (HMAC-SHA1=20, HMAC-SHA256=32,
        # HMAC-MD5=16). We capture as opaque bytes; the Session validates.
        StrLenField("auth_code", b"", length_from=lambda p: p._auth_code_len()),
    ]

    def _auth_code_len(self) -> int:
        # Recover auth-code length from parent IPMI20_Session payload_length:
        # payload_length - (1+1+2 + 4 + 16 + 16) = payload_length - 40
        parent = self.underlayer
        if parent is not None and getattr(parent, "payload_length", None):
            return max(0, parent.payload_length - 40)
        return 0

    def extract_padding(self, s):
        return b"", s


class RAKP3(Packet):
    """RAKP Message 3 — sent by remote console after RAKP2."""
    name = "RAKP Message 3"
    fields_desc = [
        ByteField("msg_tag", 0x00),
        XByteField("rmcp_status", 0x00),
        ByteField("reserved1", 0x00),
        ByteField("reserved2", 0x00),
        LEIntField("managed_session_id", 0),
        StrLenField("auth_code", b"", length_from=lambda p: p._auth_code_len()),
    ]

    def _auth_code_len(self) -> int:
        parent = self.underlayer
        if parent is not None and getattr(parent, "payload_length", None):
            return max(0, parent.payload_length - 8)
        return 0

    def extract_padding(self, s):
        return b"", s


class RAKP4(Packet):
    """RAKP Message 4 — final response from BMC."""
    name = "RAKP Message 4"
    fields_desc = [
        ByteField("msg_tag", 0x00),
        XByteField("rmcp_status", 0x00),
        ByteField("reserved1", 0x00),
        ByteField("reserved2", 0x00),
        LEIntField("remote_session_id", 0),
        StrLenField("integrity_check", b"", length_from=lambda p: p._icv_len()),
    ]

    def _icv_len(self) -> int:
        parent = self.underlayer
        if parent is not None and getattr(parent, "payload_length", None):
            return max(0, parent.payload_length - 8)
        return 0

    def extract_padding(self, s):
        return b"", s


# Bind by payload_type field on IPMI20_Session.
bind_layers(IPMI20_Session, OpenSessionRequest,  payload_type=0x10)
bind_layers(IPMI20_Session, OpenSessionResponse, payload_type=0x11)
bind_layers(IPMI20_Session, RAKP1,               payload_type=0x12)
bind_layers(IPMI20_Session, RAKP2,               payload_type=0x13)
bind_layers(IPMI20_Session, RAKP3,               payload_type=0x14)
bind_layers(IPMI20_Session, RAKP4,               payload_type=0x15)


# Helpers for building the auth/integrity/conf sub-payload bytes (used by
# the high-level Session.lanplus_open()).

def auth_payload(alg: int = 0x01) -> bytes:
    """Auth Algorithm Payload bytes (8). alg: 0=none, 1=HMAC-SHA1, 2=HMAC-MD5, 3=HMAC-SHA256."""
    return bytes(CipherSubPayload(payload_type=0, alg=alg))


def integrity_payload(alg: int = 0x01) -> bytes:
    """Integrity Algorithm Payload bytes (8). alg: 0=none, 1=HMAC-SHA1-96, 2=HMAC-MD5-128, ..."""
    return bytes(CipherSubPayload(payload_type=1, alg=alg))


def conf_payload(alg: int = 0x01) -> bytes:
    """Confidentiality Algorithm Payload bytes (8). alg: 0=none, 1=AES-CBC-128, 2=xRC4-128, ..."""
    return bytes(CipherSubPayload(payload_type=2, alg=alg))


__all__ = [
    "CipherSubPayload",
    "OpenSessionRequest", "OpenSessionResponse",
    "RAKP1", "RAKP2", "RAKP3", "RAKP4",
    "auth_payload", "integrity_payload", "conf_payload",
]
