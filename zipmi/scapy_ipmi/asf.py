"""
zipmi.scapy_ipmi.asf — ASF Presence Ping/Pong (DSP0136).

WHAT     Scapy layers for ASF 2.0 RMCP messages: the common ASF header plus
         the Presence Ping (type 0x80) and Presence Pong (type 0x40) bodies.
         These are unauthenticated and pre-IPMI; they're how you discover a
         BMC and learn which IPMI/ASF capabilities it advertises.

WHY      Presence Ping is the cheapest possible BMC discovery probe and a
         great Phase 0 smoke test — no session, no auth, just send and wait
         200ms. Also useful as a `scan` CLI subcommand.

SUCCESS  `examples/00_asf_ping.py 192.168.0.23` returns a Pong with Dell's
         IANA Enterprise Number (674) in the OEM IANA field and bit 7 set
         in `supported_entities` (= IPMI supported).

TARGET   Any RMCP/UDP-623 endpoint that implements DSP0136. Verified empty
         BMCs sometimes respond to Ping even when IPMI auth is wedged.

BUILD    Imported automatically by `import zipmi`.

RELATED  DSP0136.pdf §3.2.4.1 (Presence Ping) and §3.2.4.2 (Presence Pong),
         rmcp.py.
"""

from __future__ import annotations

from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    IntField,
    LEIntField,
    StrLenField,
)
from scapy.packet import Packet, bind_layers

from .rmcp import RMCP

# DSP0136 message types we model. The full set is larger; we cover the
# discovery pair plus the catch-all so unknown types still dissect.
ASF_MSG_TYPE = {
    0x80: "PresencePing",
    0x40: "PresencePong",
    0x10: "RMCPACK",
    0x11: "Capabilities",
    0x12: "SystemState",
    0x13: "OpenSession",
    0x14: "CloseSession",
}

ASF_IANA = 4542  # IANA Enterprise Number for ASF itself (DSP0136 §3.2.3.1).


class ASF(Packet):
    """ASF common header (DSP0136 §3.2.3)."""

    name = "ASF"
    fields_desc = [
        IntField("iana", ASF_IANA),                 # 4 bytes, big-endian
        ByteEnumField("msg_type", 0x80, ASF_MSG_TYPE),
        ByteField("msg_tag", 0x00),
        ByteField("reserved", 0x00),
        FieldLenField("data_length", None, length_of="data", fmt="B"),
        StrLenField("data", b"", length_from=lambda p: p.data_length),
    ]

    def extract_padding(self, s):
        # ASF carries its own length; anything trailing is padding/junk.
        return b"", s


class ASFPresencePong(Packet):
    """ASF Presence Pong body (DSP0136 §3.2.4.2). 16 bytes."""

    name = "ASF Presence Pong"
    fields_desc = [
        # OEM IANA Enterprise Number. Emitted LSB-first on the wire by real
        # BMCs (e.g. OpenBMC sends ASF's own 4542 as be 11 00 00); decoding
        # this big-endian yields garbage like 3188785152 instead of 4542.
        LEIntField("oem_iana", 0),     # vendor-specific (0 = no OEM extension)
        IntField("oem_defined", 0),
        ByteField("supported_entities", 0),    # bit 7 = IPMI
        ByteField("supported_interactions", 0),
        # Six reserved bytes — keep as individual fields so fuzz() can hit them.
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        ByteField("reserved4", 0),
        ByteField("reserved5", 0),
        ByteField("reserved6", 0),
    ]

    def extract_padding(self, s):
        return b"", s


# Dispatch: RMCP class 6 → ASF header (per RFC 4413 / DSP0136 §3.2.2).
bind_layers(RMCP, ASF, msg_class=0x06)

# An ASF header with msg_type == 0x40 (Pong) carries a Pong body inside its
# `data` field. We can't easily express "parse `data` as another Packet" with
# StrLenField, so we expose a helper:


def parse_pong(asf: ASF) -> ASFPresencePong | None:
    """Decode the `data` field of an ASF header as a Presence Pong, if applicable."""
    if asf.msg_type != 0x40:
        return None
    if not asf.data:
        return None
    return ASFPresencePong(asf.data)


def build_ping(msg_tag: int = 0) -> ASF:
    """Construct an ASF Presence Ping (no body, just the header)."""
    return ASF(msg_type=0x80, msg_tag=msg_tag, data=b"")
