"""
zipmi.scapy_ipmi.rmcp — RMCP framing layer.

WHAT     Scapy `Packet` for the Remote Management Control Protocol header
         (RFC 4413 / IPMI 1.5 §13.1.3 / DSP0136 §3.2.2). 4 bytes:
            [0]  Version       (always 0x06 = ASF 2.0)
            [1]  Reserved      (0x00)
            [2]  Sequence#     (0xFF = no ACK requested; common for IPMI)
            [3]  Class byte:
                 bit 7   ACK/normal (0 = normal, 1 = RMCP ACK)
                 bits 6-5 reserved
                 bits 4-0 Message class (0 ASF, 6 OEM, 7 IPMI)

WHY      RMCP wraps every IPMI-over-LAN packet. Modeling it as a real Scapy
         layer with bound sub-protocols means a captured UDP/623 packet
         dissects correctly with no further glue.

SUCCESS  Round-trip stable:
            >>> from scapy.all import UDP
            >>> p = UDP(dport=623)/RMCP()/Raw(b"\\x00")
            >>> bytes(RMCP(bytes(p[RMCP]))) == bytes(p[RMCP])
            True
         And dispatch:
            >>> RMCP(b"\\x06\\x00\\xff\\x07").payload  # → IPMI15_Session

TARGET   Any UDP/623 endpoint. ACK frames have an empty payload.

BUILD    Imported automatically by `import zipmi`.

RELATED  IPMI-1.5.pdf §13.1.3 (RMCP frame), DSP0136.pdf §3.2.2 (ASF view of
         the same frame), asf.py, ipmi15.py.
"""

from __future__ import annotations

from scapy.fields import BitEnumField, BitField, ByteField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers

from ..consts import RMCP_CLASS, RMCP_VERSION


class RMCP(Packet):
    name = "RMCP"
    fields_desc = [
        ByteField("version", RMCP_VERSION),
        ByteField("reserved", 0x00),
        ByteField("seq", 0xFF),
        # Class byte: 1-bit ack | 2-bit reserved | 5-bit msg class.
        BitField("ack", 0, 1),
        BitField("class_reserved", 0, 2),
        BitEnumField("msg_class", 0x07, 5, RMCP_CLASS),
    ]


# Bind RMCP under both directions of UDP/623 so client and server captures
# both dissect.
bind_layers(UDP, RMCP, dport=623)
bind_layers(UDP, RMCP, sport=623)

# Sub-layer dispatch is set up by the sublayer modules (asf.py, ipmi15.py)
# via their own bind_layers calls — keeps coupling one-way.
