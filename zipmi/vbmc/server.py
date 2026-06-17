"""
zipmi.vbmc.server — asyncio virtual BMC.

WHAT     Listens on UDP/6230 (configurable), parses incoming RMCP frames
         using the same Scapy layers as the client, and replies. Supports
         ASF Presence Ping/Pong, IPMI 1.5 sessionless commands, IPMI 1.5
         MD5-authenticated sessions (Activate Session through Close), and
         IPMI 2.0 RMCP+ Open Session + RAKP1-4 (cipher suites 0 and 3).

WHY      Gives us an in-process target for unit tests, CI, fuzzing, and
         client conformance work. Imitating real BMC quirks (Dell
         iDRAC6 fingerprint via the dell_idrac6 persona) lets us
         smoke-test client code without booting hardware.

SUCCESS  `zipmi vbmc serve --persona dell_idrac6 --port 6230` answers
         `ipmitool -H 127.0.0.1 -p 6230 -U root -P calvin mc info`
         with Dell-shaped fingerprint output.

TARGET   Local (loopback) testing. Does NOT implement the full IPMI spec
         — only the read-side commands we model in handlers.DISPATCH plus
         the session establishment dance.

RELATED  state.py, handlers.py, personas/, ../scapy_ipmi/*.py
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import secrets

from scapy.packet import Raw

from ..scapy_ipmi.asf import ASF, ASFPresencePong
from ..scapy_ipmi.commands import GetSessionChallengeReq
from ..scapy_ipmi.crypto import (
    CIPHER_SUITES,
    derive_k1, derive_k2, derive_sik,
    integrity_hmac,
    rakp2_authcode, rakp4_icv,
    aes_encrypt, aes_decrypt,
)
from ..scapy_ipmi.ipmi15 import IPMI_Message, IPMI15_Session
from ..scapy_ipmi.ipmi20 import IPMI20_Session
from ..scapy_ipmi.rakp import (
    OpenSessionRequest, OpenSessionResponse,
    RAKP1, RAKP2, RAKP3, RAKP4,
    auth_payload, integrity_payload, conf_payload,
)
from ..scapy_ipmi.rmcp import RMCP

from .handlers import DISPATCH, IPMIErr, State
from .state import Session1_5, Session2_0


def _ipmb_resp(rq_addr: int, rq_seq: int, rq_lun: int,
               rs_addr: int, net_fn: int, cmd: int,
               cc: int, data: bytes) -> bytes:
    """Build an IPMB response message. NetFn = request NetFn + 1."""
    msg = IPMI_Message(
        rs_addr=rq_addr,
        net_fn=(net_fn + 1) & 0x3F,
        rs_lun=rq_lun,
        rq_addr=rs_addr,
        rq_seq=rq_seq,
        rq_lun=0,
        cmd=cmd,
        data=bytes([cc]) + data,
    )
    return bytes(msg)


class VBMC(asyncio.DatagramProtocol):
    def __init__(self, state: State, trace: int = 0, color: bool = True):
        self.state = state
        self.trace = trace      # 0=off, 1=events, 2=events+hex
        self.color = color      # colorize -d hex output
        self.transport: asyncio.DatagramTransport | None = None

    # ---- asyncio plumbing ---------------------------------------------

    def connection_made(self, transport):
        self.transport = transport

    @staticmethod
    def _ts() -> str:
        import time
        t = time.time()
        return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"

    def _event(self, msg: str) -> None:
        if self.trace >= 1:
            print(f"  [{self._ts()}] {msg}", flush=True)

    def _hexdump(self, label: str, buf: bytes, *, is_response: bool) -> None:
        if self.trace >= 2:
            from ..scapy_ipmi.colorize import color_enabled, colorize_hex
            hexstr = colorize_hex(buf, is_response=is_response,
                                  enabled=self.color and color_enabled())
            print(f"        {label} {hexstr}", flush=True)

    def datagram_received(self, data, addr):
        if self.trace >= 1:
            from ..scapy_ipmi.cmd_names import label_from_wire
            lbl = label_from_wire(data) or "?"
            self._event(f"← recv {len(data):3d}B  {lbl:<40s}  from {addr[0]}:{addr[1]}")
        self._hexdump("← RECV", data, is_response=False)
        try:
            replies = self._handle(data, addr)
        except Exception as e:                       # pragma: no cover
            import traceback
            print(f"vbmc {addr}: handler crash: {e!r}")
            traceback.print_exc()
            return
        for r in replies or []:
            if self.trace >= 1:
                from ..scapy_ipmi.cmd_names import label_from_wire
                lbl = label_from_wire(r) or "?"
                self._event(f"→ send {len(r):3d}B  {lbl:<40s}  to   {addr[0]}:{addr[1]}")
            self._hexdump("→ SEND", r, is_response=True)
            self.transport.sendto(r, addr)

    # ---- top-level dispatch -------------------------------------------

    def _handle(self, data: bytes, addr) -> list[bytes]:
        try:
            pkt = RMCP(data)
        except Exception:
            return []
        # ASF (RMCP class 6) — Presence Ping / Pong only.
        if pkt.haslayer(ASF):
            return self._handle_asf(pkt[ASF])
        # IPMI 1.5 / 2.0 (class 7) dispatched by AuthType byte.
        sess15 = pkt.getlayer(IPMI15_Session)
        sess20 = pkt.getlayer(IPMI20_Session)
        if sess20 is not None:
            return self._handle_2_0(pkt, sess20, addr)
        if sess15 is not None:
            return self._handle_1_5(pkt, sess15, addr)
        return []

    # ---- ASF -----------------------------------------------------------

    def _handle_asf(self, asf: ASF) -> list[bytes]:
        if asf.msg_type != 0x80:
            return []
        pong_body = ASFPresencePong(
            oem_iana=4542,
            supported_entities=0x81,            # IPMI + ASF v1.0
        )
        pong = ASF(msg_type=0x40, msg_tag=asf.msg_tag, data=bytes(pong_body))
        return [bytes(RMCP(msg_class=0x06) / pong)]

    # ---- IPMI 1.5 ------------------------------------------------------

    def _handle_1_5(self, pkt, sess: IPMI15_Session, addr) -> list[bytes]:
        msg = pkt.getlayer(IPMI_Message)
        if msg is None:
            return []
        netfn = msg.net_fn
        cmd = msg.cmd
        data = bytes(msg.data) if msg.data else b""

        # Session-management commands route to dedicated handlers.
        if netfn == 0x06 and cmd in (0x39, 0x3A, 0x3B, 0x3C):
            return self._handle_session_mgmt_15(pkt, sess, msg, data)

        # Otherwise look up in the global DISPATCH table.
        try:
            cc, body = self._dispatch(netfn, cmd, data)
        except IPMIErr as e:
            cc, body = e.cc, b""

        ipmb = _ipmb_resp(
            rq_addr=msg.rs_addr,
            rq_seq=msg.rq_seq,
            rq_lun=msg.rq_lun,
            rs_addr=msg.rq_addr,
            net_fn=netfn,
            cmd=cmd,
            cc=cc,
            data=body,
        )
        # Return as IPMI 1.5 session header (auth=0 for session-less; else
        # echo the auth_type and session id).
        resp_sess = IPMI15_Session(
            auth_type=0,
            session_seq=sess.session_seq,
            session_id=sess.session_id,
        )
        wire = bytes(RMCP(msg_class=0x07) / resp_sess) + ipmb
        # Patch msg_length manually since IPMI15_Session.post_build uses
        # `pay` length and our ipmb is appended after serialization.
        # Easier: rebuild as a single concatenation.
        resp_sess.msg_length = len(ipmb)
        wire = bytes(RMCP(msg_class=0x07)) + bytes(resp_sess) + ipmb
        return [wire]

    def _dispatch(self, netfn: int, cmd: int, data: bytes) -> tuple[int, bytes]:
        h = DISPATCH.get((netfn, cmd))
        if h is None:
            # No built-in handler — fall back to synthetic OEM responses
            # loaded from a fixture (vbmc/fixtures.py). Lets the vbmc replay
            # captured/hand-crafted vendor OEM answers (incl. proprietary
            # Dell/SM cmds we can't elicit live).
            canned = self.state.persona.oem_responses.get((netfn, cmd))
            if canned is not None:
                return canned                 # (completion_code, response_data)
            return 0xC1, b""        # Invalid Command
        body = h(self.state, data)
        return 0x00, body

    def _handle_session_mgmt_15(self, pkt, sess: IPMI15_Session,
                                 msg: IPMI_Message, data: bytes) -> list[bytes]:
        # Get Session Challenge (0x39): respond with temp session id + 16-byte
        # challenge string.
        if msg.cmd == 0x39:
            req = GetSessionChallengeReq(data)
            temp_sid = secrets.randbits(32) | 1
            challenge = secrets.token_bytes(16)
            self.state.sessions_15[("temp", temp_sid)] = Session1_5(
                session_id=temp_sid,
                auth_type=req.auth_type,
                challenge=challenge,
            )
            body = b"\x00" + temp_sid.to_bytes(4, "little") + challenge
            ipmb = _ipmb_resp(msg.rs_addr, msg.rq_seq, msg.rq_lun,
                              msg.rq_addr, msg.net_fn, msg.cmd, 0, body[1:])
            resp_sess = IPMI15_Session(auth_type=0, session_seq=0, session_id=0)
            resp_sess.msg_length = len(ipmb)
            return [bytes(RMCP(msg_class=0x07)) + bytes(resp_sess) + ipmb]

        # Activate Session (0x3A): grant a real session ID. Response body
        # per IPMI 1.5 §22.17: cc + auth_type + sid (4LE) + init_inbound_seq
        # (4LE) + max_priv. We set auth_type=0 = "per-msg auth disabled"
        # (matches Dell iDRAC6) so subsequent messages skip the AuthCode.
        if msg.cmd == 0x3A:
            real_sid = secrets.randbits(32) | 1
            init_inbound_seq = 1
            body = b"\x00" \
                + real_sid.to_bytes(4, "little") \
                + init_inbound_seq.to_bytes(4, "little") \
                + b"\x04"           # admin priv
            ipmb = _ipmb_resp(msg.rs_addr, msg.rq_seq, msg.rq_lun,
                              msg.rq_addr, msg.net_fn, msg.cmd, 0, body)
            resp_sess = IPMI15_Session(auth_type=0,
                                       session_seq=0,
                                       session_id=sess.session_id)
            resp_sess.msg_length = len(ipmb)
            self.state.sessions_15[("active", real_sid)] = Session1_5(
                session_id=real_sid, auth_type=sess.auth_type, granted_priv=4,
            )
            return [bytes(RMCP(msg_class=0x07)) + bytes(resp_sess) + ipmb]

        # Set Session Privilege Level (0x3B): just echo back the requested level.
        if msg.cmd == 0x3B:
            priv = data[0] & 0x0F if data else 0x04
            ipmb = _ipmb_resp(msg.rs_addr, msg.rq_seq, msg.rq_lun,
                              msg.rq_addr, msg.net_fn, msg.cmd, 0,
                              bytes([priv]))
            resp_sess = IPMI15_Session(auth_type=0,
                                       session_seq=sess.session_seq + 1,
                                       session_id=sess.session_id)
            resp_sess.msg_length = len(ipmb)
            return [bytes(RMCP(msg_class=0x07)) + bytes(resp_sess) + ipmb]

        # Close Session (0x3C): no-op, return cc=0.
        if msg.cmd == 0x3C:
            ipmb = _ipmb_resp(msg.rs_addr, msg.rq_seq, msg.rq_lun,
                              msg.rq_addr, msg.net_fn, msg.cmd, 0, b"")
            resp_sess = IPMI15_Session(auth_type=0,
                                       session_seq=sess.session_seq + 1,
                                       session_id=sess.session_id)
            resp_sess.msg_length = len(ipmb)
            return [bytes(RMCP(msg_class=0x07)) + bytes(resp_sess) + ipmb]

        return []

    # ---- IPMI 2.0 RMCP+ ------------------------------------------------

    def _handle_2_0(self, pkt, sess: IPMI20_Session, addr) -> list[bytes]:
        ptype = sess.payload_type
        if ptype == 0x10:
            return self._handle_open_session(pkt, sess)
        if ptype == 0x12:
            return self._handle_rakp1(pkt, sess)
        if ptype == 0x14:
            return self._handle_rakp3(pkt, sess)
        if ptype == 0x00:
            return self._handle_in_session(pkt, sess)
        return []

    def _handle_open_session(self, pkt, sess: IPMI20_Session) -> list[bytes]:
        req = pkt.getlayer(OpenSessionRequest)
        if req is None:
            return []
        # Negotiate cipher: pick the requested algorithms unchanged.
        # (Real BMCs may downgrade; we just echo.)
        managed_sid = self.state.next_session_id()
        s20 = Session2_0(
            remote_session_id=req.remote_session_id,
            managed_session_id=managed_sid,
        )
        # Cipher id = lookup by (auth, integrity, conf) algs in CIPHER_SUITES.
        auth_alg = req.auth_payload[4] & 0x3F
        integ_alg = req.integrity_payload[4] & 0x3F
        conf_alg  = req.conf_payload[4] & 0x3F
        for cid, cs in CIPHER_SUITES.items():
            if (cs.auth_alg, cs.integrity_alg, cs.conf_alg) \
                    == (auth_alg, integ_alg, conf_alg):
                s20.cipher_id = cid
                break
        else:
            s20.cipher_id = 0
        self.state.sessions_20[managed_sid] = s20

        resp = OpenSessionResponse(
            msg_tag=req.msg_tag,
            rmcp_status=0,
            max_priv=4,
            remote_session_id=req.remote_session_id,
            managed_session_id=managed_sid,
            auth_payload=auth_payload(auth_alg),
            integrity_payload=integrity_payload(integ_alg),
            conf_payload=conf_payload(conf_alg),
        )
        return [self._wrap_outside_session(0x11, bytes(resp))]

    def _handle_rakp1(self, pkt, sess: IPMI20_Session) -> list[bytes]:
        r1 = pkt.getlayer(RAKP1)
        if r1 is None:
            return []
        s20 = self.state.sessions_20.get(r1.managed_session_id)
        if s20 is None:
            return []
        s20.rc = bytes(r1.remote_random)
        s20.rm = secrets.token_bytes(16)
        s20.role = r1.role
        s20.user_name = bytes(r1.user_name)

        cs = CIPHER_SUITES.get(s20.cipher_id, CIPHER_SUITES[0])
        guid = self.state.persona.system_guid
        ac = rakp2_authcode(
            cs, self.state.persona.password,
            s20.remote_session_id, s20.managed_session_id,
            s20.rc, s20.rm, guid, s20.role, s20.user_name,
        )
        r2 = RAKP2(
            msg_tag=r1.msg_tag,
            rmcp_status=0,
            remote_session_id=s20.remote_session_id,
            managed_random=s20.rm,
            managed_guid=guid,
            auth_code=ac,
        )
        return [self._wrap_outside_session(0x13, bytes(r2))]

    def _handle_rakp3(self, pkt, sess: IPMI20_Session) -> list[bytes]:
        r3 = pkt.getlayer(RAKP3)
        if r3 is None:
            return []
        s20 = self.state.sessions_20.get(r3.managed_session_id)
        if s20 is None:
            return []
        cs = CIPHER_SUITES.get(s20.cipher_id, CIPHER_SUITES[0])
        # Could verify r3.auth_code; we trust it here for simplicity.
        sik = derive_sik(cs, self.state.persona.password,
                         s20.rc, s20.rm, s20.role, s20.user_name)
        s20.sik = sik
        s20.k1  = derive_k1(cs, sik)
        s20.k2  = derive_k2(cs, sik)
        icv = rakp4_icv(cs, sik, s20.rc, s20.managed_session_id,
                        self.state.persona.system_guid)
        r4 = RAKP4(
            msg_tag=r3.msg_tag,
            rmcp_status=0,
            remote_session_id=s20.remote_session_id,
            integrity_check=icv,
        )
        return [self._wrap_outside_session(0x15, bytes(r4))]

    def _handle_in_session(self, pkt, sess: IPMI20_Session) -> list[bytes]:
        s20 = self.state.sessions_20.get(sess.session_id)
        if s20 is None:
            return []
        cs = CIPHER_SUITES.get(s20.cipher_id, CIPHER_SUITES[0])
        # Decrypt body.
        raw_layer = sess.getlayer(Raw)
        if raw_layer is None:
            return []
        body = bytes(raw_layer.load)[: sess.payload_length]
        if sess.encrypted and cs.conf_alg == 1:
            ipmb_bytes = aes_decrypt(s20.k2, body)
        else:
            ipmb_bytes = body
        # Manually carve IPMB.
        if len(ipmb_bytes) < 7:
            return []
        rs_addr = ipmb_bytes[0]
        nl = ipmb_bytes[1]
        netfn = (nl >> 2) & 0x3F
        rs_lun = nl & 3
        rq_addr = ipmb_bytes[3]
        sl = ipmb_bytes[4]
        rq_seq = (sl >> 2) & 0x3F
        rq_lun = sl & 3
        cmd = ipmb_bytes[5]
        data = ipmb_bytes[6:-1]
        # Session-management cmds: handle Set Priv / Close locally.
        if netfn == 0x06 and cmd == 0x3B:
            cc, body = 0, bytes([(data[0] & 0x0F) if data else 0x04])
        elif netfn == 0x06 and cmd == 0x3C:
            cc, body = 0, b""
            self.state.sessions_20.pop(sess.session_id, None)
        else:
            try:
                cc, body = self._dispatch(netfn, cmd, data)
            except IPMIErr as e:
                cc, body = e.cc, b""
        resp_ipmb = _ipmb_resp(rs_addr, rq_seq, rq_lun, rq_addr, netfn, cmd,
                               cc, body)
        # Encrypt + integrity-wrap.
        s20.inbound_seq = (s20.inbound_seq + 1) & 0xFFFFFFFF
        seq = s20.inbound_seq
        if cs.conf_alg == 1:
            conf_body = aes_encrypt(s20.k2, resp_ipmb)
        else:
            conf_body = resp_ipmb
        out_sess = IPMI20_Session(
            auth_type=0x06,
            encrypted=1 if cs.conf_alg else 0,
            authenticated=1 if cs.integrity_alg else 0,
            payload_type=0x00,
            session_id=s20.remote_session_id,
            session_seq=seq,
        )
        sess_bytes = bytes(out_sess / Raw(conf_body))
        n = len(sess_bytes) + 2
        pad_len = (-n) % 4
        ipad = b"\xFF" * pad_len + bytes([pad_len]) + b"\x07"
        covered = sess_bytes + ipad
        mac = integrity_hmac(cs, s20.k1, covered) if cs.integrity_alg else b""
        wire = bytes(RMCP(msg_class=0x07)) + covered + mac
        return [wire]

    def _wrap_outside_session(self, ptype: int, payload: bytes) -> bytes:
        sess = IPMI20_Session(auth_type=0x06, payload_type=ptype,
                              session_id=0, session_seq=0)
        return bytes(RMCP(msg_class=0x07) / sess / Raw(payload))


# ---- public entry point --------------------------------------------------


async def run(persona_name: str, host: str = "127.0.0.1",
              port: int = 6230, trace: int = 0, color: bool = True,
              fixtures: str | None = None) -> None:
    """Run the vbmc until cancelled. Resolves persona by module name.

    `trace`: 0=quiet, 1=event log per packet, 2=event log + hex dump.
    `color`: enable ANSI colour in -d hex output (subject to TTY check).
    `fixtures`: optional path to a sweep JSON (scripts/oem_sweep.py) whose
        captured OEM responses are loaded into the persona so the vbmc
        replays vendor OEM answers with no live BMC.
    """
    persona_mod = importlib.import_module(f"zipmi.vbmc.personas.{persona_name}")
    persona = persona_mod.build()
    if fixtures:
        from .fixtures import apply_fixture
        n = apply_fixture(persona, fixtures)
        print(f"vbmc loaded {n} synthetic OEM responses from {fixtures}")
    state = State(persona=persona)
    loop = asyncio.get_running_loop()
    transport, _proto = await loop.create_datagram_endpoint(
        lambda: VBMC(state, trace=trace, color=color),
        local_addr=(host, port),
    )
    print(f"vbmc {persona_name} listening on {host}:{port}")
    try:
        await asyncio.Event().wait()    # run forever
    finally:
        transport.close()
