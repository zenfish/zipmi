"""
zipmi.fuzz.length — IPMI 1.5 length-field corruption fuzzer.

WHAT     Sends well-formed IPMB requests wrapped in IPMI 1.5 session
         headers whose `msg_length` byte is wrong (zero, truncated,
         oversized, or byte-max 0xFF). Probes BMC parser robustness —
         a careless implementation may read past the buffer, accept a
         truncated request, or reflect an unbounded body length.

WHY      Length-prefix bugs are classic exploitable parser flaws on
         embedded BMCs. The IPMI 1.5 wire format puts a single u8
         message-length field right before the IPMB payload; if the
         BMC trusts that field it can be coerced into reading off-
         buffer data into the response.

USAGE    Programmatic:
             from zipmi.fuzz.length import length_corrupt
             results = length_corrupt(session, 0x06, 0x01, b"")
         CLI:
             zipmi fuzz length --netfn 0x06 --cmd 0x01

SUCCESS  Each mutation sent; BMC reply (or timeout) recorded as bytes.
TARGET   IPMI 1.5 only. RMCP+ has its own framing layer with explicit
         payload length — `cipher_confuse` covers that surface.
RELATED  zipmi/scapy_ipmi/ipmi15.py, zipmi/fuzz/cipher_confuse.py.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core import Session
from ..scapy_ipmi.ipmi15 import IPMI_Message, IPMI15_Session
from ..scapy_ipmi.rmcp import RMCP


@dataclass
class LengthMutation:
    name: str
    description: str


MUTATIONS = [
    LengthMutation("zero",      "msg_length = 0"),
    LengthMutation("truncated", "msg_length = actual - 1"),
    LengthMutation("oversized", "msg_length = actual + 16"),
    LengthMutation("byte-max",  "msg_length = 0xFF"),
]


def _bad_length(name: str, actual: int) -> int:
    return {
        "zero":      0,
        "truncated": max(actual - 1, 0),
        "oversized": actual + 16,
        "byte-max":  0xFF,
    }[name]


@dataclass
class LengthResult:
    mutation: str
    sent_msg_length: int
    actual_ipmb_len: int
    reply: bytes | None
    error: str = ""


def length_corrupt(
    session: Session, netfn: int, cmd: int, data: bytes = b"",
) -> list[LengthResult]:
    """Send each mutation, capture raw reply (or None on timeout)."""
    if session.lanplus:
        raise NotImplementedError(
            "length corruption only implemented for IPMI 1.5; "
            "use cipher_confuse for RMCP+ framing"
        )

    out: list[LengthResult] = []
    for mut in MUTATIONS:
        ipmb = IPMI_Message(
            rs_addr=session.transport.rs_addr,
            net_fn=netfn,
            rs_lun=0,
            rq_addr=session.transport.rq_addr,
            rq_seq=session._next_rq_seq(),
            rq_lun=0,
            cmd=cmd,
            data=data,
        )
        ipmb_bytes = bytes(ipmb)
        bad_len = _bad_length(mut.name, len(ipmb_bytes))
        sess = IPMI15_Session(
            auth_type=0, session_seq=0, session_id=0, msg_length=bad_len,
        )
        wire = bytes(RMCP(msg_class=0x07) / sess) + ipmb_bytes
        result = LengthResult(
            mutation=mut.name,
            sent_msg_length=bad_len,
            actual_ipmb_len=len(ipmb_bytes),
            reply=None,
        )
        try:
            result.reply = session.transport.send_recv(wire)
        except (TimeoutError, OSError) as e:
            result.error = f"transport:{e}"
        except Exception as e:
            result.error = f"crash:{type(e).__name__}:{e}"
        out.append(result)
    return out
