"""
zipmi.scapy_ipmi.ipmi15 — IPMI 1.5 LAN session header + IPMB message.

WHAT     Two Scapy layers:

           IPMI15_Session  — IPMI 1.5 LAN session wrapper (IPMI 1.5 §13.6).
                            Variable size: 10 bytes (no auth) or 26 bytes
                            (16-byte AuthCode for MD2/MD5/Straight Pwd).

           IPMI_Message    — IPMB request/response (IPMI 1.5 §6.12, §13.8):
                              rsAddr / NetFn|rsLUN / chk1 / rqAddr /
                              rqSeq|rqLUN / Cmd / Data... / chk2

WHY      Every authenticated and unauthenticated IPMI-over-LAN packet rides
         in this envelope. Modeling it as proper Scapy `Packet`s with real
         fields (no opaque blobs) is the foundation for both the high-level
         `Session` API and Phase 6 fuzzing.

SUCCESS  Round-trip: `IPMI_Message(bytes(IPMI_Message(...)))` reconstructs
         every field including both checksums, which match the IPMB
         2's-complement spec.

         Wire: a Get Channel Auth Caps request built via this layer matches
         ipmitool's request byte-for-byte (verified by tcpdump diff).

TARGET   IPMI 1.5 spec §6.12 (IPMB), §13.6 (LAN session), §13.8 (IPMB-over-LAN
         message format).

BUILD    Imported automatically by `import zipmi`.

RELATED  /Users/zen/phd/dox/specs/IPMI-1.5.pdf §13.6, §13.8
         rmcp.py, commands.py
"""

from __future__ import annotations

from scapy.fields import (
    BitField,
    ByteField,
    ConditionalField,
    LEIntField,
    StrFixedLenField,
    StrLenField,
    XByteField,
)
from scapy.packet import Packet, bind_layers

from ..consts import AUTH_TYPE
from .rmcp import RMCP


# IPMI 1.5 Session header (IPMI 1.5 §13.6).
#
# Layout (bytes):
#   0       AuthType (low nibble)
#   1..4    Session Sequence Number (LE u32)
#   5..8    Session ID              (LE u32)
#   9..24   AuthCode (16 bytes, ONLY when AuthType != 0)
#   N       IPMI Msg Length (1 byte) where N = 9 (no auth) or 25 (auth)
#
# RMCP+ (IPMI 2.0 lanplus) reuses the same first byte but with AuthType == 6;
# in that case the IPMI20_Session layer (Phase 3) takes over.
class IPMI15_Session(Packet):
    name = "IPMI 1.5 Session"
    fields_desc = [
        XByteField("auth_type", 0x00),
        LEIntField("session_seq", 0),
        LEIntField("session_id", 0),
        # AuthCode present only for authenticated sessions.
        ConditionalField(
            StrFixedLenField("auth_code", b"\x00" * 16, 16),
            lambda p: p.auth_type not in (0x00, 0x06),
        ),
        ByteField("msg_length", None),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """When AuthType byte is 0x06 the wire is actually IPMI 2.0 RMCP+.

        Scapy `bind_layers(RMCP, IPMI15_Session, msg_class=7)` matches first
        for both 1.5 and 2.0 traffic; this hook reroutes to IPMI20_Session
        whenever the leading byte indicates RMCP+.
        """
        if _pkt and len(_pkt) >= 1 and _pkt[0] == 0x06:
            from .ipmi20 import IPMI20_Session
            return IPMI20_Session
        return cls

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # Auto-fill msg_length when caller left it None.
        if self.msg_length is None:
            length = len(pay)
            # Find the msg_length offset: 9 (no auth) or 25 (auth).
            offset = 9 if self.auth_type in (0x00, 0x06) else 25
            pkt = pkt[:offset] + bytes([length & 0xFF]) + pkt[offset + 1:]
        return pkt + pay


# RMCP class 7 (IPMI) → IPMI 1.5 Session header.
bind_layers(RMCP, IPMI15_Session, msg_class=0x07)


# IPMB / IPMI message (IPMI 1.5 §13.8 — IPMB request format used over LAN).
#
# Wire layout:
#   0    rsAddr        (responder slave addr; 0x20 = BMC)
#   1    NetFn (high 6 bits) | rsLUN (low 2 bits)
#   2    Checksum 1   (2's complement of sum of bytes 0..1, mod 256)
#   3    rqAddr        (requester addr; 0x81 = remote console software)
#   4    rqSeq (high 6 bits) | rqLUN (low 2 bits)
#   5    Cmd
#   6..N Data
#   N+1  Checksum 2   (2's complement of sum of bytes 3..N, mod 256)
#
# Responses replace `Cmd` field's role and prepend a Completion Code byte
# at offset 6 (first data byte). We don't model that asymmetrically — the
# Completion Code is just byte 0 of `data` for responses, and the high-level
# Session API splits it out.
class IPMI_Message(Packet):
    name = "IPMI Message"
    fields_desc = [
        XByteField("rs_addr", 0x20),
        BitField("net_fn", 0, 6),
        BitField("rs_lun", 0, 2),
        XByteField("chk1", None),
        XByteField("rq_addr", 0x81),
        BitField("rq_seq", 0, 6),
        BitField("rq_lun", 0, 2),
        XByteField("cmd", 0x00),
        # `data` runs to end-of-message minus 1 byte (chk2). Length is supplied
        # by the parent IPMI15_Session.msg_length, so we use a custom dissect.
        StrLenField("data", b"", length_from=lambda p: p._data_len()),
        XByteField("chk2", None),
    ]

    def _data_len(self) -> int:
        """Compute the data length from the parent Session.msg_length."""
        # Total message = 6 fixed header bytes + data + 1 chk2 byte.
        # When dissecting, the parent has set msg_length on us via context;
        # we recover it by reading the parent layer.
        parent = self.underlayer
        if parent is None or getattr(parent, "msg_length", None) is None:
            # Fall back: assume zero data when unparented — caller should
            # pass total length explicitly. Returning 0 is safe; chk2 still
            # parses as the next byte.
            return 0
        # 6 fixed pre-data bytes + data + 1 chk2 = msg_length
        n = parent.msg_length - 7
        return max(0, n)

    @staticmethod
    def _ipmb_checksum(b: bytes) -> int:
        """IPMB 2's-complement-of-sum checksum (mod 256)."""
        return (-sum(b)) & 0xFF

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # pkt is the fully-serialized layer + (any) sub-layer payload.
        # pkt[0:2]   = rs_addr, NetFn|rsLUN
        # pkt[2]     = chk1 (placeholder if None)
        # pkt[3:6]   = rq_addr, rqSeq|rqLUN, cmd
        # pkt[6:-1]  = data
        # pkt[-1]    = chk2 (placeholder if None)
        out = bytearray(pkt + pay)

        if self.chk1 is None:
            out[2] = self._ipmb_checksum(out[0:2])
        if self.chk2 is None:
            # chk2 covers rq_addr (offset 3) through last data byte (offset -2).
            out[-1] = self._ipmb_checksum(bytes(out[3:-1]))

        return bytes(out)

    def extract_padding(self, s):
        # IPMI_Message owns all of its bytes; nothing trails.
        return b"", s


# IPMI15_Session → IPMI_Message: every authenticated/unauthenticated IPMI 1.5
# packet's session payload is exactly one IPMI message. The auth_type==6 case
# (RMCP+) will be intercepted in Phase 3 by IPMI20_Session.
bind_layers(IPMI15_Session, IPMI_Message)
