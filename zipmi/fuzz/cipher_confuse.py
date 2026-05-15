"""
zipmi.fuzz.cipher_confuse — RMCP+ cipher-suite negotiation fuzzer.

WHAT     Sends Open Session Request payloads that advertise reserved /
         unsupported / inconsistent algorithm IDs in the auth, integrity,
         and confidentiality fields, then records the BMC's Open Session
         Response. Catches firmware that fails-open on bad cipher choices
         (the canonical example being CVE-2013-4786 — cipher 0 + null
         user — but variants keep showing up on cheap silicon).

WHY      RMCP+ has 17+ defined cipher suites and three orthogonal
         algorithm fields that must all agree. Many BMCs only validate
         the suite_id and trust the per-field bytes, so claiming
         "auth=HMAC-SHA1, integrity=NONE, conf=AES-CBC-128" can produce
         an integrity-less but encrypted session — broken in different
         ways than full cipher 0.

USAGE    Programmatic:
             from zipmi.fuzz.cipher_confuse import cipher_confuse
             results = cipher_confuse(host="192.168.0.23")
         CLI:
             zipmi fuzz cipher --host 192.168.0.23

SUCCESS  Each mutation reaches the BMC; response bytes captured. Any
         "session opened despite bad cipher" is logged with WARNING.
TARGET   IPMI 2.0 RMCP+ Open Session Request (payload type 0x10).
RELATED  zipmi/scapy_ipmi/ipmi20.py, zipmi/scapy_ipmi/crypto.py,
         zipmi/cli/zipmi.py:cmd_scan_cipher_zero (the cipher-0 probe
         is the simplest member of this family).
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


# Open Session Request layout (RFC IPMI 2.0 §13.17, simplified).
# Total 32 bytes after the RMCP+ session-header preamble.
#   +0  message_tag           u8
#   +1  requested_max_priv    u8 (bits[3:0]; 4 = Admin)
#   +2  reserved              u16
#   +4  remote_console_sid    u32 LE
#   +8  auth_payload_type     u8 = 0x00
#   +9  reserved              u8 = 0x00
#  +10  auth_payload_len      u16 LE = 8
#  +12  auth_alg              u8
#  +13  reserved              3 bytes
#  +16  integrity_payload     u8 = 0x01, len=8, integrity_alg, 3 reserved
#  +24  conf_payload          u8 = 0x02, len=8, conf_alg, 3 reserved


# RMCP+ Open Session / RAKP status codes (IPMI 2.0 spec table 13-15).
RMCP_STATUS = {
    0x00: "no errors",
    0x01: "insufficient resources to create session",
    0x02: "invalid session id",
    0x03: "invalid payload type",
    0x04: "invalid authentication algorithm",
    0x05: "invalid integrity algorithm",
    0x06: "no matching authentication payload",
    0x07: "no matching integrity payload",
    0x08: "inactive session id",
    0x09: "invalid role",
    0x0A: "unauthorized role or privilege level requested",
    0x0B: "insufficient resources to create session at requested role",
    0x0C: "invalid name length",
    0x0D: "unauthorized name",
    0x0E: "unauthorized GUID",
    0x0F: "invalid integrity check value",
    0x10: "invalid confidentiality algorithm",
    0x11: "no Cipher Suite match with proposed security algorithms",
    0x12: "illegal or unrecognized parameter",
}


@dataclass
class CipherMutation:
    name: str
    auth_alg: int
    integrity_alg: int
    conf_alg: int
    expected: str  # what a strict BMC should do


MUTATIONS = [
    CipherMutation("auth_reserved_0xFF",    0xFF, 0x00, 0x00,
                   "reject — auth_alg 0xFF undefined"),
    CipherMutation("integrity_reserved_0xFF", 0x01, 0xFF, 0x00,
                   "reject — integrity_alg 0xFF undefined"),
    CipherMutation("conf_reserved_0xFF",    0x01, 0x01, 0xFF,
                   "reject — conf_alg 0xFF undefined"),
    CipherMutation("mismatch_auth_no_integrity", 0x01, 0x00, 0x01,
                   "reject — HMAC-SHA1 + no integrity + AES is invalid combo"),
    CipherMutation("all_zero_explicit",     0x00, 0x00, 0x00,
                   "accept — equivalent to cipher suite 0 (CVE-2013-4786)"),
    CipherMutation("auth_md5_legacy",       0x02, 0x00, 0x00,
                   "vendor-dependent — HMAC-MD5 is suite 1 by IANA but rare"),
    CipherMutation("integrity_only",        0x00, 0x01, 0x00,
                   "reject — no auth + integrity is nonsense"),
]


@dataclass
class CipherResult:
    mutation: str
    auth_alg: int
    integrity_alg: int
    conf_alg: int
    expected: str
    response_status: int | None  # byte +1 of Open Session Response
    response_bytes: bytes | None
    error: str = ""

    @property
    def session_opened(self) -> bool:
        return self.response_status == 0x00

    @property
    def warning(self) -> str:
        if self.session_opened and "reject" in self.expected:
            return "FAIL-OPEN — session opened despite bad cipher"
        return ""


def _open_session_request(mut: CipherMutation, console_sid: int = 0xA0A2A3A4,
                          msg_tag: int = 0x00, priv: int = 0x04) -> bytes:
    p = bytearray(32)
    p[0] = msg_tag
    p[1] = priv & 0x0F
    struct.pack_into("<I", p, 4, console_sid)
    # auth payload
    p[8] = 0x00
    struct.pack_into("<H", p, 10, 8)
    p[12] = mut.auth_alg
    # integrity payload
    p[16] = 0x01
    struct.pack_into("<H", p, 18, 8)
    p[20] = mut.integrity_alg
    # confidentiality payload
    p[24] = 0x02
    struct.pack_into("<H", p, 26, 8)
    p[28] = mut.conf_alg
    return bytes(p)


def _wrap_rmcpplus(payload: bytes) -> bytes:
    """Minimal RMCP+ envelope for Open Session Request (payload type 0x10)."""
    # RMCP header (4) + IPMI 2.0 session header (12) + payload + trailer (0).
    rmcp = bytes([0x06, 0x00, 0xFF, 0x07])
    auth_type = 0x06              # IPMI 2.0
    payload_type = 0x10           # Open Session Request
    sess_id = 0
    sess_seq = 0
    hdr = struct.pack("<BBII", auth_type, payload_type, sess_id, sess_seq)
    plen = struct.pack("<H", len(payload))
    return rmcp + hdr + plen + payload


def cipher_confuse(host: str, port: int = 623, timeout: float = 2.0,
                   ) -> list[CipherResult]:
    """For each mutation, send Open Session Request and capture reply."""
    out: list[CipherResult] = []
    for mut in MUTATIONS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            req = _wrap_rmcpplus(_open_session_request(mut))
            sock.sendto(req, (host, port))
            data, _ = sock.recvfrom(1500)
            # RMCP(4) + IPMI 2.0 session header (auth_type + payload_type
            # + session_id + session_seq = 10) + payload_len (2) = 16 bytes
            # before the payload. Open Session Response payload byte 0 is
            # msg_tag, byte 1 is rmcp_status (table 13-15 of IPMI 2.0 spec).
            status = data[17] if len(data) > 17 else None
            out.append(CipherResult(
                mutation=mut.name,
                auth_alg=mut.auth_alg,
                integrity_alg=mut.integrity_alg,
                conf_alg=mut.conf_alg,
                expected=mut.expected,
                response_status=status,
                response_bytes=data,
            ))
        except (TimeoutError, socket.timeout):
            out.append(CipherResult(
                mutation=mut.name, auth_alg=mut.auth_alg,
                integrity_alg=mut.integrity_alg, conf_alg=mut.conf_alg,
                expected=mut.expected, response_status=None,
                response_bytes=None, error="timeout",
            ))
        except OSError as e:
            out.append(CipherResult(
                mutation=mut.name, auth_alg=mut.auth_alg,
                integrity_alg=mut.integrity_alg, conf_alg=mut.conf_alg,
                expected=mut.expected, response_status=None,
                response_bytes=None, error=f"transport:{e}",
            ))
        finally:
            sock.close()
    return out
