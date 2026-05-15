"""
zipmi.fuzz.rakp_mut — RAKP field mutation fuzzer.

WHAT     Sends RAKP Message 1 with progressively-corrupted fields
         (nonce all zeros, role byte hi-bits set, user_name length
         lying about actual bytes, msg_tag wrap-around) and records
         the BMC's RAKP2 response code or timeout.

WHY      RAKP is a hand-rolled mini-protocol on top of the IPMI 2.0
         session header. BMCs vary in how strictly they validate
         field shapes; mutation here probes for parse-time bugs and
         auth-bypass surfaces (Farmer's WOOT13 paper showed cipher 0
         + null user as the canonical bypass; rakp_mut catches the
         next round of those).

USAGE    Caller supplies a host:port that has Open Session already
         working (or a vbmc to send to).

         from zipmi.fuzz.rakp_mut import fuzz_rakp1
         results = fuzz_rakp1(host="127.0.0.1", port=6230, user="root")

OUTPUTS  list[dict] — one entry per mutation describing what was sent
         and what came back.

RELATED  zipmi/scapy_ipmi/rakp.py, zipmi/scapy_ipmi/crypto.py
"""

from __future__ import annotations

import secrets
import socket
from collections.abc import Callable

from scapy.packet import Raw

from ..scapy_ipmi.ipmi20 import IPMI20_Session
from ..scapy_ipmi.rakp import (
    OpenSessionRequest, OpenSessionResponse,
    RAKP1, RAKP2,
    auth_payload, integrity_payload, conf_payload,
)
from ..scapy_ipmi.rmcp import RMCP


def _open_session(sock: socket.socket, host: str, port: int) -> int:
    """Run Open Session req → resp; return managed_session_id."""
    sid_c = secrets.randbits(32) | 1
    osr = OpenSessionRequest(
        msg_tag=0,
        max_priv=0,
        remote_session_id=sid_c,
        auth_payload=auth_payload(1),
        integrity_payload=integrity_payload(1),
        conf_payload=conf_payload(1),
    )
    sess = IPMI20_Session(auth_type=0x06, payload_type=0x10)
    wire = bytes(RMCP(msg_class=0x07) / sess / Raw(bytes(osr)))
    sock.sendto(wire, (host, port))
    data, _ = sock.recvfrom(4096)
    reply = RMCP(data)
    if not reply.haslayer(OpenSessionResponse):
        raise RuntimeError("no OSR")
    return reply[OpenSessionResponse].managed_session_id


def _send_rakp1(sock: socket.socket, host: str, port: int, payload: bytes,
                timeout: float = 2.0,
                pad_to: int | None = None) -> bytes | None:
    """Wrap RAKP1 payload in RMCP+ and send. If `pad_to` set, append 0xFF
    bytes to the full UDP datagram until it reaches that size — probes
    IP-fragment reassembly + BMC parser bounds checking."""
    sess = IPMI20_Session(auth_type=0x06, payload_type=0x12)
    wire = bytes(RMCP(msg_class=0x07) / sess / Raw(payload))
    if pad_to is not None and pad_to > len(wire):
        wire = wire + b"\xFF" * (pad_to - len(wire))
    sock.settimeout(timeout)
    sock.sendto(wire, (host, port))
    try:
        data, _ = sock.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    except OSError as e:
        # Datagram too large for socket buffer / kernel rejected it.
        return f"oserror:{e}".encode()


def _build_rakp1(managed_sid: int, rc: bytes, role: int,
                 user_name: bytes, *, name_len_override: int | None = None,
                 msg_tag: int = 0) -> bytes:
    r1 = RAKP1(
        msg_tag=msg_tag,
        managed_session_id=managed_sid,
        remote_random=rc,
        role=role,
        user_name=user_name,
    )
    raw = bytes(r1)
    if name_len_override is not None:
        # Replace the 1-byte user_name_len field (offset 27 from spec).
        raw = raw[:27] + bytes([name_len_override & 0xFF]) + raw[28:]
    return raw


def fuzz_rakp1(host: str, port: int, user: str = "root",
               timeout: float = 2.0,
               on_result: "Callable[[dict], None] | None" = None,
               ) -> list[dict]:
    """Run a small mutation suite against a target's RAKP1 handler.

    `on_result` (optional) is invoked synchronously after every mutation
    completes, enabling streaming CLI output.
    """
    user_b = user.encode("utf-8")

    results: list[dict] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # Bump send buffer so oversize-pad mutations up to ~65k bytes can
    # actually leave the host. Default macOS SO_SNDBUF is small (~9k).
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 17)
    except OSError:
        pass

    try:
        managed_sid = _open_session(sock, host, port)
    except Exception as e:
        r = {"mutation": "open_session_setup", "error": str(e)}
        if on_result:
            on_result(r)
        return [r]

    mutations = [
        # name → (rc, role, user_name, name_len_override, msg_tag, pad_to)
        # `pad_to` (when set) appends 0xFF bytes to the wire payload until
        # the UDP datagram reaches the requested size. Probes IP-fragment
        # reassembly + parser bounds checking. Common thresholds:
        #   1472  = max UDP payload that fits in one Ethernet frame (MTU 1500)
        #   1500  = forces IP fragmentation across exactly 2 fragments
        #   8000  = forces multi-fragment reassembly
        #  65000  = near max UDP datagram (65507 = 65535 - 20 IP - 8 UDP)
        ("baseline",            secrets.token_bytes(16), 0x14, user_b, None, 0,    None),
        ("nonce_zeros",         b"\x00" * 16,             0x14, user_b, None, 0,    None),
        ("nonce_ones",          b"\xFF" * 16,             0x14, user_b, None, 0,    None),
        ("role_top_bits",       secrets.token_bytes(16), 0xFF, user_b, None, 0,    None),
        ("role_zero",           secrets.token_bytes(16), 0x00, user_b, None, 0,    None),
        ("empty_username",      secrets.token_bytes(16), 0x14, b"",     None, 0,    None),
        ("namelen_lie_short",   secrets.token_bytes(16), 0x14, user_b,  1,    0,    None),
        ("namelen_lie_long",    secrets.token_bytes(16), 0x14, user_b,  0xFF, 0,    None),
        ("msg_tag_max",         secrets.token_bytes(16), 0x14, user_b, None, 0xFF, None),
        ("oversize_pad_1472",   secrets.token_bytes(16), 0x14, user_b, None, 0,    1472),
        ("oversize_pad_1500",   secrets.token_bytes(16), 0x14, user_b, None, 0,    1500),
        ("oversize_pad_8000",   secrets.token_bytes(16), 0x14, user_b, None, 0,    8000),
        ("oversize_pad_16000",  secrets.token_bytes(16), 0x14, user_b, None, 0,    16000),
        ("oversize_pad_32000",  secrets.token_bytes(16), 0x14, user_b, None, 0,    32000),
        ("oversize_pad_65000",  secrets.token_bytes(16), 0x14, user_b, None, 0,    65000),
        # Combined: lie about name_len + extend buffer with 0xFF padding.
        # Discriminates "validator parses what name_len claims" from
        # "validator bounds-checks claim against datagram length".
        ("namelen0xFF_pad_8000",   secrets.token_bytes(16), 0x14, user_b, 0xFF, 0, 8000),
        ("namelen0xFF_no_pad",     secrets.token_bytes(16), 0x14, user_b, 0xFF, 0, None),
        ("namelen1_pad_8000",      secrets.token_bytes(16), 0x14, user_b, 1,    0, 8000),
    ]

    for mut_name, rc, role, uname, name_override, msg_tag, pad_to in mutations:
        payload = _build_rakp1(managed_sid, rc, role, uname,
                               name_len_override=name_override,
                               msg_tag=msg_tag)
        entry: dict
        try:
            reply = _send_rakp1(sock, host, port, payload, timeout=timeout,
                                pad_to=pad_to)
        except Exception as e:
            entry = {"mutation": mut_name, "error": str(e), "reply": None}
        else:
            if reply is None:
                entry = {"mutation": mut_name, "result": "timeout",
                         "reply": None}
            else:
                try:
                    r2 = RMCP(reply)[RAKP2]
                    entry = {
                        "mutation": mut_name,
                        "rmcp_status": int(r2.rmcp_status),
                        "auth_code_len": len(bytes(r2.auth_code)),
                        "reply": reply,
                    }
                except Exception:
                    entry = {"mutation": mut_name, "result": "no_RAKP2",
                             "raw_len": len(reply), "reply": reply}
        results.append(entry)
        if on_result:
            on_result(entry)

    sock.close()
    return results
