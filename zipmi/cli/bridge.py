"""
zipmi.cli.bridge — Send Message (0x06/0x34) encapsulation + bridge detection.

WHAT   Build a Send Message request that carries an IPMB-format inner command
       to another channel (e.g. the IPMB, to reach a satellite controller), and
       probe whether a BMC will actually bridge to a given channel.

WHY    Non-LAN channels (IPMB, other buses) are not remotely reachable directly.
       Bridging is the remote path onto them — and whether the BMC permits it,
       and to which channels, is enumerable. Bridgeable channels are reach edges
       for the hardware connectivity graph.

WIRE   Send Message req (IPMI 2.0 §22.7):
         byte 1: [7:6] tracking (01b=track request), [5] encrypt, [4] auth,
                 [3:0] channel to send on
         bytes 2..N: the encapsulated message. For an IPMB target that is a full
                 IPMB request: rsSA, netFn/rsLUN, csum1, rqSA, rqSeq/rqLUN, cmd,
                 data..., csum2.
"""
from __future__ import annotations

from ..consts import COMP_CODE


def _csum(data: bytes) -> int:
    """2's-complement checksum: (sum + csum) & 0xff == 0."""
    return (-sum(data)) & 0xFF


def encapsulate_ipmb(netfn: int, cmd: int, data: bytes = b"",
                     rs_addr: int = 0x20, rq_addr: int = 0x81,
                     rq_seq: int = 0, rs_lun: int = 0, rq_lun: int = 0) -> bytes:
    """One IPMB-format request (the payload carried inside Send Message)."""
    netfn_lun = ((netfn & 0x3F) << 2) | (rs_lun & 0x03)
    hdr = bytes([rs_addr & 0xFF, netfn_lun])
    csum1 = _csum(hdr)
    body = bytes([rq_addr & 0xFF, ((rq_seq & 0x3F) << 2) | (rq_lun & 0x03),
                  cmd & 0xFF]) + bytes(data)
    csum2 = _csum(body)
    return hdr + bytes([csum1]) + body + bytes([csum2])


def build_send_message(channel: int, netfn: int, cmd: int, data: bytes = b"",
                       tracking: int = 0b01, encrypt: bool = False,
                       auth: bool = False, **enc_kw) -> bytes:
    """Send Message (0x34) request data bridging (netfn,cmd,data) onto `channel`."""
    ch_byte = ((tracking & 0x03) << 6) | (int(encrypt) << 5) | (int(auth) << 4) \
        | (channel & 0x0F)
    return bytes([ch_byte]) + encapsulate_ipmb(netfn, cmd, data, **enc_kw)


def probe_bridge(session, channel: int) -> dict:
    """Test whether the BMC will bridge to `channel`, by Send-Message-ing a
    benign Get Device ID (App 0x06/0x01) onto it. Interprets the Send Message
    completion code — accept means the bridge was permitted (the bridged reply
    itself may need Get Message to retrieve).

    Returns {supported, bridgeable, cc, detail}."""
    req = build_send_message(channel, 0x06, 0x01)     # bridge Get Device ID
    try:
        cc, _ = session.send_raw(0x06, 0x34, req)
    except Exception as e:
        return {"supported": None, "bridgeable": None, "cc": None,
                "detail": f"err:{e}"}
    if cc == 0xC1:
        return {"supported": False, "bridgeable": False, "cc": cc,
                "detail": "Send Message (0x34) unsupported"}
    if cc == 0x00:
        return {"supported": True, "bridgeable": True, "cc": cc,
                "detail": "bridge accepted"}
    return {"supported": True, "bridgeable": False, "cc": cc,
            "detail": COMP_CODE.get(cc, f"cc=0x{cc:02x}")}
