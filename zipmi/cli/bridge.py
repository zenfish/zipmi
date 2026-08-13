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

# Send Message (0x34) defines its OWN completion codes in the 0x80..0x83 range —
# these override the generic/OEM meaning of those bytes in a bridging context
# (IPMI 2.0 §22.7). e.g. 0x80 here is "Invalid Session Handle", not a device code.
SEND_MSG_CC: dict[int, str] = {
    0x80: "Invalid Session Handle (needs a session on the target channel)",
    0x81: "Lost Arbitration (IPMB)",
    0x82: "Bus Error (IPMB)",
    0x83: "NAK on Write / target did not ACK on the bus",
}

# Completion codes that mean "the bridge worked, but the far end wasn't reachable"
# — as opposed to the BMC refusing the request outright.
_UNREACHABLE_CC = frozenset({0x83, 0xD3})


def cc_reason(cc: int) -> str:
    """Human reason for a completion code in a bridging context: Send-Message
    specific names first, then the generic table, then raw hex."""
    if cc in SEND_MSG_CC:
        return SEND_MSG_CC[cc]
    return COMP_CODE.get(cc, f"unknown cc=0x{cc:02x}")


def cc_category(cc: int, accepted: bool, confirmed: bool) -> str:
    """Bucket a probe outcome: reachable | bridged | unreachable | refused."""
    if accepted:
        return "reachable" if confirmed else "bridged"
    return "unreachable" if cc in _UNREACHABLE_CC else "refused"


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


def build_bridged_request(path: list[int], netfn: int, cmd: int,
                          data: bytes = b"", rs_addr: int = 0x20) -> bytes:
    """Fold Send Message nesting over a multi-hop `path` and return the request
    data for the OUTER Send Message (0x06/0x34) you send on your current session.

    path[0] is the first bridged channel (sent on from your session); path[-1] is
    the final target that runs (netfn,cmd,data). `rs_addr` is the IPMB slave
    address of that final target — default 0x20 is the BMC itself; sweep it to
    reach satellite controllers on an IPMB. Each extra hop wraps the prior blob
    as the payload of another Send Message (those wrappers always address 0x20,
    the BMC that processes them).

        [a]     -> SM(a, real@rs_addr)
        [a,b]   -> SM(a, 0x34, SM(b, real@rs_addr))
        [a,b,c] -> SM(a, 0x34, SM(b, 0x34, SM(c, real@rs_addr)))
    """
    if not path:
        raise ValueError("path needs >=1 hop")
    cur = build_send_message(path[-1], netfn, cmd, data, rs_addr=rs_addr)
    for hop in reversed(path[:-1]):                    # wrap remaining hops out
        cur = build_send_message(hop, 0x06, 0x34, cur)
    return cur


def parse_encapsulated_reply(rsp: bytes) -> tuple[int, int, bytes] | None:
    """Parse one IPMB-format bridged response returned inline by Send Message
    (or dequeued by Get Message). Returns (cmd, far_completion_code, inner_data)
    or None if too short to be a reply.

    IPMB response layout (§22.7):
      [0] rqAddr  [1] netFn/rqLUN  [2] csum1  [3] rsAddr  [4] rqSeq/rsLUN
      [5] cmd     [6] completion   [7..-1] data           [-1] csum2
    """
    if len(rsp) < 8:
        return None
    return rsp[5], rsp[6], rsp[7:-1]


def _unwrap_far_cc(rsp: bytes) -> int | None:
    """Peel nested Send Message responses down to the innermost far-end
    completion code. Returns None if nothing parseable came back."""
    parsed = parse_encapsulated_reply(rsp)
    while parsed:
        cmd, cc, inner = parsed
        if cmd == 0x34 and cc == 0x00 and len(inner) >= 8:   # nested SM reply
            parsed = parse_encapsulated_reply(inner)
            continue
        return cc
    return None


def confirm_bridge_path(session, path: list[int], get_message: bool = True,
                        rs_addr: int = 0x20) -> dict:
    """Bridge a Get Device ID (App 0x06/0x01) along `path` to IPMB slave
    `rs_addr` and confirm the far end actually answered — inline in the Send
    Message reply, else dequeued via Get Message (0x06/0x33) after Get Message
    Flags (0x06/0x31).

    Returns {path, rs_addr, accept_cc, accepted, confirmed, far_cc, via,
    category, detail}. accepted = BMC permitted the bridge; confirmed = far
    controller replied; category = reachable|bridged|unreachable|refused."""
    out = {"path": list(path), "rs_addr": rs_addr, "accept_cc": None,
           "accepted": False, "confirmed": False, "far_cc": None, "via": None,
           "category": "refused", "detail": ""}
    req = build_bridged_request(path, 0x06, 0x01, rs_addr=rs_addr)
    try:
        cc, rsp = session.send_raw(0x06, 0x34, req)
    except Exception as e:                                    # noqa: BLE001
        out["detail"] = f"err:{e}"
        return out
    out["accept_cc"] = cc
    if cc == 0xC1:
        out.update(category="refused", detail="Send Message (0x34) unsupported")
        return out
    if cc != 0x00:
        out.update(category=cc_category(cc, False, False), detail=cc_reason(cc))
        return out
    out["accepted"] = True
    far = _unwrap_far_cc(rsp)                                 # inline reply?
    if far is None and get_message:                          # queued reply?
        fcc, fdata = session.send_raw(0x06, 0x31, b"")       # Get Message Flags
        if fcc == 0x00 and fdata and (fdata[0] & 0x01):      # rx msg available
            mcc, mdata = session.send_raw(0x06, 0x33, b"")   # Get Message
            if mcc == 0x00 and len(mdata) >= 9:
                far = _unwrap_far_cc(mdata[1:])              # skip channel byte
                out["via"] = "get-message"
    if far is not None:
        out.update(confirmed=True, far_cc=far,
                   via=out["via"] or "inline",
                   category="reachable",
                   detail=("far end OK" if far == 0x00
                           else f"far end cc=0x{far:02x} {cc_reason(far)}"))
        return out
    out.update(category="bridged",
               detail="bridge accepted; far end sent no retrievable reply")
    return out


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
