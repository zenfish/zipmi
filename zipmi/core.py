"""
zipmi.core — Transport, Session, and high-level command helpers.

WHAT     `Transport` owns the UDP socket; sessionless commands ride on it
         directly. `Session` is a context-managed IPMI 1.5 LAN session:
         it does Get Channel Auth Caps -> Get Session Challenge ->
         Activate Session -> Set Privilege, hands you `send_cmd()`, and
         closes cleanly.

WHY      Phase 0/1 examples need a clean Pythonic surface. Keeping I/O
         out of the Scapy layers means the layers are easy to fuzz and
         the Session is easy to test with a vbmc fixture.

SUCCESS  Live: `Session(host, user, pw).get_device_id().fw_revision()`
         returns "1.70" against Dell iDRAC6.
         Wire: bytes match an `ipmitool -A MD5` capture for the same
         command sequence.

TARGET   Phase 1: IPMI 1.5 LAN, MD5 auth, Dell-style "per-message auth
         disabled" (status bit 2). RMCP+ in Phase 3.

RELATED  scapy_ipmi/ipmi15.py, scapy_ipmi/commands.py, scapy_ipmi/crypto.py
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Iterator
from contextlib import contextmanager

from scapy.packet import Packet

from .scapy_ipmi import commands as cmds
from .scapy_ipmi.crypto import (
    CIPHER_SUITES,
    CipherSuite,
    aes_decrypt,
    aes_encrypt,
    derive_k1,
    derive_k2,
    derive_sik,
    integrity_hmac,
    md5_auth_code,
    pad_password,
    rakp2_authcode,
    rakp3_authcode,
    rakp4_icv,
    straight_pwd_auth_code,
)
from .scapy_ipmi.ipmi15 import IPMI_Message, IPMI15_Session
from .scapy_ipmi.ipmi20 import IPMI20_Session
from .scapy_ipmi.rakp import (
    OpenSessionRequest,
    OpenSessionResponse,
    RAKP1,
    RAKP2,
    RAKP3,
    RAKP4,
    auth_payload,
    conf_payload,
    integrity_payload,
)
from .scapy_ipmi.rmcp import RMCP
from . import _msg


# Auth type byte values used in the Session header (IPMI 1.5 §13.6).
AUTH_NONE = 0x00
AUTH_MD2 = 0x01
AUTH_MD5 = 0x02
AUTH_STRAIGHT = 0x04
AUTH_RMCP_PLUS = 0x06   # IPMI 2.0 lanplus marker


class IPMIError(RuntimeError):
    """Raised for non-zero IPMI completion codes or session faults."""

    def __init__(self, msg: str, comp_code: int | None = None):
        super().__init__(msg)
        self.comp_code = comp_code


@dataclass
class Transport:
    """Synchronous UDP/623 transport. One BMC per instance.

    Holds a single persistent UDP socket for the lifetime of the
    Transport. iDRAC6 binds an authenticated session to the source
    (ip, port) of the Activate Session packet, so subsequent commands
    must reuse the same local port. Sessionless probes also benefit
    (less FD churn, faster throughput).
    """

    host: str
    port: int = 623
    timeout: float = 3.0
    rq_addr: int = 0x81
    rs_addr: int = 0x20
    # Per-request retransmit count on timeout. IPMI rides UDP (unreliable),
    # so a single dropped datagram must not fail the whole command — every
    # real IPMI client retransmits (ipmitool defaults to 4). This also covers
    # an OpenBMC netipmid race where the *first* encrypted message after the
    # RAKP4 reply can arrive before netipmid has finished installing the
    # session integrity key, so that one packet is dropped ("Packet Integrity
    # check failed") while an immediate resend succeeds. `retries` is the
    # number of *extra* attempts after the first (so total tries = retries+1).
    retries: int = 3
    # Wire trace level:
    #   0 — off (default)
    #   1 — human-readable timestamped events: "→ send …", "← recv …",
    #       "timeout", "connect". No hex.
    #   2 — everything level 1 emits, PLUS a hex dump of every packet
    #       (work + session setup handshake).
    wire_trace: int = 0
    # Colour the wire-trace hex output with ColorBrewer Pastel1
    # (RMCP/session/NetFn/cmd/data/CC). Default off; the CLI flips it on
    # via _open_session when stdout is a TTY and -n / NO_COLOR are unset.
    wire_color: bool = False
    # Set by Session.activate() while the pre-auth handshake is running.
    # Event lines tag with `[setup]` prefix while True so the user can tell
    # handshake chatter apart from work commands.
    in_setup: bool = field(default=False, init=False)

    _sock: socket.socket | None = field(default=None, init=False, repr=False)

    def _socket(self) -> socket.socket:
        if self._sock is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            # Connect-mode UDP: pins both ends of the 4-tuple, so any reply
            # from a different source is filtered out by the kernel.
            s.connect((self.host, self.port))
            self._sock = s
        return self._sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _ts(self) -> str:
        # HH:MM:SS.mmm — millisecond precision is enough for IPMI latency
        # ordering and keeps the prefix narrow.
        t = time.time()
        return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"

    def _event(self, msg: str) -> None:
        if self.wire_trace >= 1:
            tag = "[setup] " if self.in_setup else ""
            print(f"  [{self._ts()}] {tag}{msg}", flush=True)

    def send_recv(self, wire: bytes) -> bytes:
        s = self._socket()
        do_hex = self.wire_trace >= 2
        if self.wire_trace >= 1:
            from .scapy_ipmi.cmd_names import label_from_wire
            label = label_from_wire(wire) or "?"
            self._event(f"→ send {len(wire):3d}B  {label:<40s}  {self.host}:{self.port}")
        if do_hex:
            self._dump("→ SEND", wire, name=True, is_response=False)
        attempts = self.retries + 1
        for attempt in range(attempts):
            s.send(wire)
            try:
                data, _ = s.recvfrom(4096)
                break
            except socket.timeout:
                if attempt + 1 < attempts:
                    self._event(
                        f"!! timeout after {self.timeout}s "
                        f"(retransmit {attempt + 1}/{self.retries})")
                    continue
                self._event(f"!! timeout after {self.timeout}s waiting for {self.host}:{self.port}")
                raise
        if self.wire_trace >= 1:
            self._event(f"← recv {len(data):3d}B  (reply)                                  "
                        f"{self.host}:{self.port}")
        if do_hex:
            # RECV is the immediate reply to the SEND above — no need to
            # repeat the command name. (send_recv pairs them synchronously.)
            self._dump("← RECV", data, name=False, is_response=True)
        return data

    def _dump(self, label: str, buf: bytes, *, name: bool, is_response: bool) -> None:
        prefix = "[setup] " if self.in_setup else "        "
        if name:
            from .scapy_ipmi.cmd_names import label_from_wire
            cmd = label_from_wire(buf) or "?"
        else:
            cmd = ""
        from .scapy_ipmi.colorize import colorize_hex
        hexstr = colorize_hex(buf, is_response=is_response, enabled=self.wire_color)
        # Pad cmd column to a fixed width for alignment. Padding the bare
        # name (not ANSI-decorated) keeps the column count correct.
        print(f"  {prefix}{label} {cmd:<40s}  {hexstr}",
              flush=True)

    def sessionless_request(
        self,
        netfn: int,
        cmd: int,
        req_payload: Packet | bytes | None = None,
        rq_seq: int = 0,
        rmcp_plus: bool = False,
    ) -> tuple[IPMI_Message | None, Packet | None]:
        """Send an unauthenticated IPMI request (SID=0, Seq=0).

        Defaults to IPMI 1.5 session framing (AuthType=NONE). Set
        rmcp_plus=True to frame the request in an IPMI 2.0 RMCP+ session
        header (AuthType=0x06, payload type 0) instead — required for
        IPMI-2.0-only commands such as Get Channel Cipher Suites (0x54) on
        BMCs that no longer run a 1.5 listener (e.g. iDRAC10 silently drops
        the 1.5-framed probe → timeout).
        """
        data = _payload_bytes(req_payload)
        ipmb = IPMI_Message(
            rs_addr=self.rs_addr,
            net_fn=netfn,
            rs_lun=0,
            rq_addr=self.rq_addr,
            rq_seq=rq_seq,
            rq_lun=0,
            cmd=cmd,
            data=data,
        )
        if not rmcp_plus:
            pkt = (
                RMCP(msg_class=0x07)
                / IPMI15_Session(auth_type=0, session_seq=0, session_id=0)
                / ipmb
            )
            reply = RMCP(self.send_recv(bytes(pkt)))
            msg = reply[IPMI_Message] if reply.haslayer(IPMI_Message) else None
            decoded = _decode_response(msg) if msg else None
            return msg, decoded

        # RMCP+ framing. IPMI20_Session has no bind_layers to IPMI_Message for
        # payload type 0, and the reply's auth byte (0x06) reroutes dissection
        # away from IPMI_Message — so slice the inner IPMB out by offset (as
        # _query_cipher_suites does) and re-frame it in a synthetic 1.5 header
        # so IPMI_Message.data (length_from parent msg_length) parses.
        from scapy.packet import Raw
        pkt = (
            RMCP(msg_class=0x07)
            / IPMI20_Session(auth_type=AUTH_RMCP_PLUS, payload_type=0,
                             session_id=0, session_seq=0)
            / Raw(bytes(ipmb))
        )
        raw = bytes(self.send_recv(bytes(pkt)))
        # RMCP(4) + IPMI20_Session header(12): payload_length at [14:16], IPMB at [16:].
        if len(raw) < 16:
            return None, None
        plen = raw[14] | (raw[15] << 8)
        inner = raw[16:16 + plen]
        if not inner:
            return None, None
        framed = bytes([0x00]) + b"\x00" * 8 + bytes([len(inner) & 0xFF]) + inner
        sess = IPMI15_Session(framed)
        msg = sess[IPMI_Message] if sess.haslayer(IPMI_Message) else None
        decoded = _decode_response(msg) if msg else None
        return msg, decoded


def parse_cipher_suite_records(blob: bytes) -> set[int]:
    """Parse the record blob returned by Get Channel Cipher Suites (0x54) into a
    set of cipher-suite IDs. Handles both the standard Cipher Suite Record form
    (0xC0 <id> ... / 0xC1 <iana:3> <id> ...) and the bare tagged-algorithm form
    some BMCs (e.g. OpenBMC) return, where algorithm bytes carry a tag in bits[7:6]
    (00=auth, 01=integrity, 10=confidentiality) and a completed (auth,integ,conf)
    triple is reverse-mapped to a known suite ID via CIPHER_SUITES.
    """
    rev = {(cs.auth_alg, cs.integrity_alg, cs.conf_alg): sid
           for sid, cs in CIPHER_SUITES.items()}
    ids: set[int] = set()
    i = 0
    cur: dict = {}
    while i < len(blob):
        b = blob[i]
        if b == 0xC0 and i + 1 < len(blob):      # standard record: suite id follows
            ids.add(blob[i + 1]); i += 2; continue
        if b == 0xC1 and i + 4 < len(blob):      # OEM record: 3-byte IANA then id
            ids.add(blob[i + 4]); i += 5; continue
        tag = (b >> 6) & 0x3
        v = b & 0x3F
        if tag == 0:
            cur["a"] = v
        elif tag == 1:
            cur["i"] = v
        elif tag == 2:                           # confidentiality closes a record
            cur["c"] = v
            t = (cur.get("a"), cur.get("i"), cur.get("c"))
            if t in rev:
                ids.add(rev[t])
            cur = {}
        i += 1
    return ids


@dataclass
class Session:
    """Authenticated IPMI 1.5 LAN session.

    Opens with `activate()`, holds session state, sends authenticated
    commands via `send_cmd()`, and closes via `close()` or context exit.

    Currently supports MD5 ("-A MD5") and Straight Password ("-A PASSWORD").
    """

    host: str
    username: str | None            # None on both → sessionless mode (no
    password: str | None            # handshake; every send is auth_type=0,
                                    # session_id=0, seq=0). BMC decides
                                    # what it'll answer at that priv.
    priv: int = 0x04                # Administrator
    auth_type: int = AUTH_MD5
    timeout: float = 3.0

    # IPMI 2.0 RMCP+ ("lanplus") mode. When True, ignore auth_type and use
    # cipher_suite (default 3 = HMAC-SHA1 + HMAC-SHA1-96 + AES-CBC-128).
    lanplus: bool = False
    cipher_suite: int | None = 3   # None = auto-discover via Get Channel Cipher Suites

    transport: Transport = field(init=False)

    # Populated by activate():
    session_id: int = field(default=0, init=False)
    outbound_seq: int = field(default=0, init=False)   # our msg seq -> BMC
    inbound_seq:  int = field(default=0, init=False)   # BMC's seq <- BMC
    granted_priv: int = field(default=0, init=False)
    granted_auth: int = field(default=0, init=False)   # 0 = per-msg disabled
    rq_seq: int = field(default=0, init=False)

    # RMCP+ state (lanplus mode only):
    remote_session_id: int = field(default=0, init=False)
    cipher: CipherSuite | None = field(default=None, init=False)
    sik: bytes = field(default=b"", init=False)
    k1: bytes = field(default=b"", init=False)
    k2: bytes = field(default=b"", init=False)

    def __post_init__(self):
        self.transport = Transport(host=self.host, timeout=self.timeout)

    # -- public API --------------------------------------------------------

    @property
    def sessionless(self) -> bool:
        """True when no creds were supplied → every send is unauthenticated."""
        return self.username is None and self.password is None

    def activate(self) -> None:
        """Activate the IPMI session using the configured mode."""
        if self.sessionless:
            # Nothing to set up — sends go out auth_type=0, session_id=0.
            return
        self.transport.in_setup = True
        try:
            if self.lanplus:
                self._activate_lanplus()
            else:
                challenge_resp = self._get_session_challenge()
                self._activate_session(
                    challenge_resp.temp_session_id, bytes(challenge_resp.challenge)
                )
                self._set_privilege(self.priv)
        finally:
            self.transport.in_setup = False

    def probe_cipher_zero(self) -> tuple[bool, str]:
        """Actively test RMCP+ cipher-suite-0 (no-auth) access.

        Cipher 0 = no auth + no integrity + no confidentiality. A BMC that
        accepts it hands an attacker a full session with no password
        (CVE-2013-4786 / Farmer WOOT'13). This sends REAL packets and only
        returns vulnerable when the BMC both opens a cipher-0 session AND
        executes a privileged command with no credentials — it never
        concludes from silence, so dead/unroutable hosts read as not
        vulnerable, not as a false positive.

        Returns (vulnerable, detail).
        """
        if self.cipher_suite != 0:
            raise IPMIError("probe_cipher_zero requires cipher_suite=0")
        # Force the RMCP+ handshake even though no creds are set: cipher 0
        # uses null auth, so the username/password are empty by design and
        # the sessionless short-circuit (which exists for IPMI 1.5 pre-session
        # commands) must NOT apply here.
        self.lanplus = True
        if self.username is None:
            self.username = ""
        if self.password is None:
            self.password = ""
        self.transport.in_setup = True
        try:
            self._activate_lanplus()
        except IPMIError as e:
            return (False, f"cipher-0 session not opened ({e})")
        except Exception as e:  # transport timeout, decode error, etc.
            return (False, f"no usable cipher-0 session ({e})")
        finally:
            self.transport.in_setup = False
        # Session opened with cipher 0 — prove a command actually runs unauth.
        try:
            cc, data = self.send_raw(0x06, 0x01)  # Get Device ID
        except Exception as e:
            return (False, f"cipher-0 session opened but command failed ({e})")
        if cc == 0:
            return (True, f"Get Device ID ran with no auth (cc=0, {len(data)} bytes)")
        return (False, f"cipher-0 session opened but Get Device ID cc=0x{cc:02x}")

    def close(self) -> None:
        """Close Session. Best-effort — we don't raise on errors."""
        if not self.sessionless and self.session_id != 0:
            try:
                # In lanplus the Close Session targets the BMC's session ID,
                # which is what we hold in self.session_id post-activation.
                self.send_cmd(
                    0x06, 0x3C, cmds.CloseSessionReq(session_id=self.session_id)
                )
            except Exception:
                pass
            self.session_id = 0
        self.transport.close()

    def send_cmd(
        self,
        netfn: int,
        cmd: int,
        req_payload: Packet | bytes | None = None,
    ) -> Packet:
        """Send a request; return the decoded response Packet.

        Authenticated when creds were supplied, sessionless otherwise.
        Raises IPMIError on non-zero completion code.
        """
        if self.sessionless:
            msg, decoded = self.transport.sessionless_request(
                netfn, cmd, req_payload, rq_seq=self._next_rq_seq()
            )
        else:
            msg, decoded = self._send_authenticated(netfn, cmd, req_payload)
        if decoded is None:
            raise IPMIError(f"no response decoder for netfn=0x{netfn:02x} cmd=0x{cmd:02x}")
        cc = getattr(decoded, "comp_code", None)
        if cc is not None and cc != 0:
            from .consts import COMP_CODE
            raise IPMIError(
                f"BMC error: {COMP_CODE.get(cc, f'0x{cc:02x}')} on cmd 0x{cmd:02x}",
                comp_code=cc,
            )
        return decoded

    def send_raw(
        self,
        netfn: int,
        cmd: int,
        data: bytes = b"",
    ) -> tuple[int, bytes]:
        """Send arbitrary IPMI request; return (completion_code, response_data).

        Bypasses the response Packet registry — the caller gets raw bytes.
        Used by `zipmi raw` and as the building block for OEM commands
        whose response shape we haven't modeled yet. Authenticated when
        creds were supplied, sessionless otherwise. Does NOT raise on
        non-zero completion code (caller decides what's an error).
        """
        if self.sessionless:
            msg, _ = self.transport.sessionless_request(
                netfn, cmd, data, rq_seq=self._next_rq_seq()
            )
        else:
            msg, _ = self._send_authenticated(netfn, cmd, data)
        if msg is None or not msg.data:
            return 0xFF, b""
        body = bytes(msg.data)
        return body[0], body[1:]

    # Convenience wrappers; one-liners for the common spec commands.

    def get_device_id(self) -> Packet:
        return self.send_cmd(0x06, 0x01)

    def get_chassis_status(self) -> Packet:
        return self.send_cmd(0x00, 0x01)

    # -- internals ---------------------------------------------------------

    def _next_rq_seq(self) -> int:
        s = self.rq_seq & 0x3F
        self.rq_seq = (self.rq_seq + 1) & 0x3F
        return s

    def _get_session_challenge(self):
        req = cmds.GetSessionChallengeReq(
            auth_type=self.auth_type,
            user_name=pad_password(self.username),
        )
        msg, decoded = self.transport.sessionless_request(
            0x06, 0x39, req, rq_seq=self._next_rq_seq()
        )
        if decoded is None or decoded.comp_code != 0:
            cc = decoded.comp_code if decoded else None
            raise IPMIError(f"Get Session Challenge failed (cc={cc})", comp_code=cc)
        return decoded

    def _activate_session(self, temp_session_id: int, challenge: bytes) -> None:
        # Pick a non-zero initial outbound sequence; ipmitool uses random.
        # Deterministic for now (1) — easier to diff against pcaps.
        init_outbound_seq = 1

        req = cmds.ActivateSessionReq(
            auth_type=self.auth_type,
            max_priv=self.priv,
            challenge=challenge.ljust(16, b"\x00")[:16],
            init_outbound_seq=init_outbound_seq,
        )
        ipmb = IPMI_Message(
            rs_addr=self.transport.rs_addr,
            net_fn=0x06,
            rq_addr=self.transport.rq_addr,
            rq_seq=self._next_rq_seq(),
            cmd=0x3A,
            data=bytes(req),
        )
        ipmb_bytes = bytes(ipmb)

        if self.auth_type == AUTH_MD5:
            auth_code = md5_auth_code(self.password, temp_session_id, ipmb_bytes, 0)
        elif self.auth_type == AUTH_STRAIGHT:
            auth_code = straight_pwd_auth_code(self.password)
        elif self.auth_type == AUTH_NONE:
            auth_code = b""
        else:
            raise IPMIError(f"unsupported auth_type 0x{self.auth_type:02x}")

        sess_hdr = IPMI15_Session(
            auth_type=self.auth_type,
            session_seq=0,
            session_id=temp_session_id,
        )
        if auth_code:
            sess_hdr.auth_code = auth_code

        pkt = RMCP(msg_class=0x07) / sess_hdr / ipmb
        reply = RMCP(self.transport.send_recv(bytes(pkt)))
        if not reply.haslayer(IPMI_Message):
            raise IPMIError("Activate Session: no IPMI Message in reply")
        decoded = _decode_response(reply[IPMI_Message])
        if decoded is None:
            raise IPMIError("Activate Session: response did not decode")
        if decoded.comp_code != 0:
            raise IPMIError(
                f"Activate Session failed (cc=0x{decoded.comp_code:02x})",
                comp_code=decoded.comp_code,
            )
        self.session_id = decoded.session_id
        # init_inbound_seq is the seed for OUR outbound seq (confusingly named
        # in spec). Subsequent messages must use init_inbound_seq, +1, +2, ...
        self.outbound_seq = decoded.init_inbound_seq
        self.granted_priv = decoded.max_priv
        self.granted_auth = decoded.auth_type

    def _set_privilege(self, priv: int) -> None:
        req = cmds.SetSessionPrivLevelReq(priv=priv)
        decoded = self.send_cmd(0x06, 0x3B, req)
        # decoded.priv is the actual granted level — already validated by send_cmd
        # via comp_code check.

    # -- IPMI 2.0 RMCP+ (lanplus) ------------------------------------------

    # Per-algorithm strength ranks (higher = stronger). The algorithm *numbers*
    # from the spec are NOT ordered by strength, so map them explicitly.
    _AUTH_RANK = {3: 3, 1: 2, 2: 1, 0: 0}          # SHA256 > SHA1 > MD5 > none
    _CONF_RANK = {1: 3, 2: 2, 3: 1, 0: 0}          # AES-CBC-128 > xRC4-128 > xRC4-40 > none
    _INTEG_RANK = {4: 4, 1: 3, 2: 2, 3: 1, 0: 0}   # SHA256-128 > SHA1-96 > MD5-128 > none

    @classmethod
    def _cipher_strength(cls, sid: int) -> tuple[int, int, int]:
        """Lexicographic strength of a cipher suite: (auth, confidentiality,
        integrity). Auth is primary — it gates authentication, the offline-
        crackable RAKP hash, and the KDF that derives the integrity/conf keys."""
        cs = CIPHER_SUITES[sid]
        return (cls._AUTH_RANK.get(cs.auth_alg, 0),
                cls._CONF_RANK.get(cs.conf_alg, 0),
                cls._INTEG_RANK.get(cs.integrity_alg, 0))

    @classmethod
    def _select_cipher(cls, offered: set[int]) -> int:
        """Pick the strongest suite the BMC offers that we implement.

        Never *silently* downgrade to an unauthenticated suite: prefer any
        authenticated suite (auth != 0) over suite 0. But if the BMC genuinely
        offers ONLY cipher 0, use it (working beats failing) and warn loudly —
        the session is unauthenticated (cipher-zero). Falls back to 3
        (spec-mandatory) only when discovery returned nothing usable at all."""
        usable = [s for s in offered
                  if s in CIPHER_SUITES and CIPHER_SUITES[s].auth_alg != 0]
        if usable:
            return max(usable, key=cls._cipher_strength)
        if 0 in offered and 0 in CIPHER_SUITES:
            return 0            # only cipher 0 offered: use it (caller warns)
        return 3                # discovery empty/failed — spec-mandatory default


    def _query_cipher_suites(self, channel: int = 0x0E) -> set[int]:
        """Pre-session Get Channel Cipher Suites (App 0x06 / cmd 0x54), sent
        unauthenticated over RMCP+ (IPMI 2.0 §22.15). Returns the set of cipher
        suite IDs the BMC advertises, or an empty set on any error so the caller
        can fall back. Iterates the record list until a short (<16 B) chunk.

        Handles both the standard C0/C1-wrapped Cipher Suite Records and the bare
        tagged-algorithm form some BMCs (e.g. OpenBMC) return: algorithm bytes are
        tag-coded in bits[7:6] (00=auth, 01=integrity, 10=confidentiality), and a
        completed (auth,integ,conf) triple is reverse-mapped to a suite ID via
        CIPHER_SUITES (see parse_cipher_suite_records).
        """
        blob = b""
        try:
            for idx in range(0x40):
                ipmb = IPMI_Message(
                    rs_addr=self.transport.rs_addr, net_fn=0x06, rs_lun=0,
                    rq_addr=self.transport.rq_addr, rq_seq=self._next_rq_seq(),
                    rq_lun=0, cmd=0x54,
                    data=bytes([channel & 0xFF, 0x00, idx & 0x3F]),
                )
                raw = bytes(self._send_lanplus_outside_session(0x00, bytes(ipmb)))
                if len(raw) < 17:
                    break
                plen = raw[14] | (raw[15] << 8)
                msg = raw[16:16 + plen]
                if len(msg) < 8 or msg[6] != 0:      # msg[6] = completion code
                    break
                rec = msg[7:-1][1:]                  # drop trailing checksum, then channel byte
                blob += rec
                if len(rec) < 16:
                    break
        except Exception:
            return set()
        return parse_cipher_suite_records(blob)

    def _activate_lanplus(self) -> None:
        """RMCP+ Open Session + RAKP 1-4 + Set Privilege.

        Per IPMI 2.0 §13.17 (Open Session), §13.20 (RAKP), §13.32 (key
        derivation). HMAC formulas verified against ipmitool -C 3
        oracle pcap vs Dell iDRAC6.

        When cipher_suite is None (no explicit -C), auto-select: query the BMC's
        supported suites and pick the strongest, like ipmitool. Falls back to 3
        (spec-mandatory) if the BMC ignores the query — so it still works against
        a BMC that only offers 3, and against SHA1-dropping BMCs that offer only 17.
        """
        import sys
        auto = self.cipher_suite is None
        if auto:
            self.cipher_suite = self._select_cipher(self._query_cipher_suites())
            # Squeak when auto-discovery landed on something other than the
            # historical default 3 — the user didn't ask for a cipher, so tell
            # them what got picked. Non-fatal; we proceed either way.
            if self.cipher_suite != 3:
                _msg.info(f"auto-selected cipher suite {self.cipher_suite} "
                          f"(BMC's strongest offered; default is 3)")
        if self.cipher_suite not in CIPHER_SUITES:
            raise IPMIError(f"unsupported cipher suite {self.cipher_suite}")
        cs = CIPHER_SUITES[self.cipher_suite]
        self.cipher = cs

        # Warn (auto or explicit) if the resolved suite skips auth or integrity —
        # informative, non-blocking. Confidentiality is not warned (many valid
        # deployments run authenticated-but-unencrypted).
        weak = []
        if cs.auth_alg == 0:
            weak.append("NO authentication (cipher-zero; session is UNAUTHENTICATED)")
        if cs.integrity_alg == 0:
            weak.append("no integrity protection")
        if weak:
            _msg.warn(f"cipher suite {self.cipher_suite} — {'; '.join(weak)}. "
                      f"Use a non-zero suite (e.g. -C 3 or -C 17) for an "
                      f"authenticated session.")

        # Pick a random remote console session ID (avoid 0).
        import os, secrets
        self.remote_session_id = int.from_bytes(secrets.token_bytes(4), "little") or 1
        rc = secrets.token_bytes(16)

        # 1. Open Session Request → Response.
        osr = OpenSessionRequest(
            msg_tag=0x00,
            max_priv=0x00,
            remote_session_id=self.remote_session_id,
            auth_payload=auth_payload(cs.auth_alg),
            integrity_payload=integrity_payload(cs.integrity_alg),
            conf_payload=conf_payload(cs.conf_alg),
        )
        reply = self._send_lanplus_outside_session(0x10, bytes(osr))
        if not reply.haslayer(OpenSessionResponse):
            raise IPMIError("Open Session: bad reply")
        ores = reply[OpenSessionResponse]
        if ores.rmcp_status != 0:
            raise IPMIError(f"Open Session: status 0x{ores.rmcp_status:02x}")
        managed_sid = ores.managed_session_id

        # 2. RAKP1 → RAKP2 (verify BMC's auth code).
        # Spec-correct: send the REAL-length username (as ipmitool does). RAKP1's
        # user_name_len is the actual name length, and spec BMCs (OpenBMC etc.) do a
        # length-based user lookup + HMAC over the real bytes — so a NUL-padded
        # 16-byte name is looked up as "root\0\0.." and rejected with RAKP2 status
        # 0x0d ("unauthorized name"). The old unconditional ljust(16) was a workaround
        # for a QUIRKY target (an emulated iDRAC whose RAKP2 HMAC memcmp'd 16 bytes
        # against a stale/uninit packet buffer for short names); keep it as opt-in via
        # self.rakp_pad_username for that case only. uname is used consistently below
        # (packet + rakp2/3 authcode + SIK), so both sides agree either way.
        uname = self.username.encode("utf-8")
        if getattr(self, "rakp_pad_username", False):
            uname = uname.ljust(16, b"\x00")
        role = 0x14  # name-only-lookup + admin priv
        rakp1 = RAKP1(
            managed_session_id=managed_sid,
            remote_random=rc,
            role=role,
            user_name=uname,
        )
        reply = self._send_lanplus_outside_session(0x12, bytes(rakp1))
        if not reply.haslayer(RAKP2):
            raise IPMIError("RAKP2: missing")
        r2 = reply[RAKP2]
        if r2.rmcp_status != 0:
            raise IPMIError(f"RAKP2: status 0x{r2.rmcp_status:02x}")
        rm = bytes(r2.managed_random)
        guid_m = bytes(r2.managed_guid)
        expected_r2 = rakp2_authcode(
            cs, self.password, self.remote_session_id, managed_sid,
            rc, rm, guid_m, role, uname,
        )
        if bytes(r2.auth_code) != expected_r2:
            raise IPMIError("RAKP2: auth code mismatch — wrong password or BMC?")

        # 3. RAKP3 → RAKP4 (verify BMC's ICV).
        r3_code = rakp3_authcode(cs, self.password, self.remote_session_id,
                                 rm, role, uname)
        rakp3 = RAKP3(
            rmcp_status=0x00,
            managed_session_id=managed_sid,
            auth_code=r3_code,
        )
        reply = self._send_lanplus_outside_session(0x14, bytes(rakp3))
        if not reply.haslayer(RAKP4):
            raise IPMIError("RAKP4: missing")
        r4 = reply[RAKP4]
        if r4.rmcp_status != 0:
            raise IPMIError(f"RAKP4: status 0x{r4.rmcp_status:02x}")
        sik = derive_sik(cs, self.password, rc, rm, role, uname)
        expected_icv = rakp4_icv(cs, sik, rc, managed_sid, guid_m)
        if bytes(r4.integrity_check) != expected_icv:
            raise IPMIError("RAKP4: integrity check mismatch")

        # 4. Stash session keys.
        self.sik = sik
        self.k1 = derive_k1(cs, sik)
        self.k2 = derive_k2(cs, sik)
        self.session_id = managed_sid
        self.granted_priv = ores.max_priv

        # 5. Set Session Privilege Level over the now-authenticated session.
        self._set_privilege(self.priv)

    def _send_lanplus_outside_session(self, payload_type: int, payload: bytes):
        """Build & send an unauthenticated RMCP+ control packet (Open/RAKP)."""
        from scapy.packet import Raw
        sess = IPMI20_Session(
            auth_type=AUTH_RMCP_PLUS,
            payload_type=payload_type,
            session_id=0,
            session_seq=0,
        )
        wire = bytes(RMCP(msg_class=0x07) / sess / Raw(payload))
        return RMCP(self.transport.send_recv(wire))

    def _wrap_lanplus(self, payload_type: int, payload: bytes) -> bytes:
        """Encrypt + integrity-wrap `payload` into a complete RMCP+ wire
        packet for the active session. Increments the outbound session
        sequence number. Used for both IPMI messages (payload type 0) and
        SOL payloads (payload type 1).
        """
        cs = self.cipher
        if cs is None or self.session_id == 0:
            raise IPMIError("lanplus session not active")

        # Confidentiality (AES-CBC-128 if conf_alg == 1).
        if cs.conf_alg == 1:
            conf_body = aes_encrypt(self.k2, payload)
            encrypted_bit = 1
        elif cs.conf_alg == 0:
            conf_body = payload
            encrypted_bit = 0
        else:
            raise IPMIError(f"conf_alg {cs.conf_alg} not implemented")

        self.outbound_seq = (self.outbound_seq + 1) & 0xFFFFFFFF
        seq = self.outbound_seq

        from scapy.packet import Raw
        sess = IPMI20_Session(
            auth_type=AUTH_RMCP_PLUS,
            encrypted=encrypted_bit,
            authenticated=1 if cs.integrity_alg else 0,
            payload_type=payload_type,
            session_id=self.session_id,
            session_seq=seq,
        )
        # Build header + encrypted body so we can compute the HMAC over the
        # integrity-covered region. The trailer (pad + padlen + next_header)
        # follows the body; HMAC covers from auth_type through next_header.
        sess_with_body = bytes(sess / Raw(conf_body))
        n = len(sess_with_body) + 2          # +1 padlen +1 next_header
        pad_len = (-n) % 4
        ipad = b"\xFF" * pad_len + bytes([pad_len]) + b"\x07"  # 0x07 = trailer
        covered = sess_with_body + ipad

        mac = integrity_hmac(cs, self.k1, covered) if cs.integrity_alg != 0 else b""
        return bytes(RMCP(msg_class=0x07)) + covered + mac

    def _send_lanplus(
        self,
        netfn: int,
        cmd: int,
        req_payload: Packet | bytes | None,
    ) -> tuple[IPMI_Message, Packet | None]:
        """Send authenticated+encrypted IPMI message (cipher 3 style)."""
        data = _payload_bytes(req_payload)
        ipmb = IPMI_Message(
            rs_addr=self.transport.rs_addr,
            net_fn=netfn,
            rs_lun=0,
            rq_addr=self.transport.rq_addr,
            rq_seq=self._next_rq_seq(),
            rq_lun=0,
            cmd=cmd,
            data=data,
        )
        wire = self._wrap_lanplus(0x00, bytes(ipmb))
        reply = RMCP(self.transport.send_recv(wire))
        return self._unwrap_lanplus(reply)

    # -- SOL payload transport (payload type 0x01) -------------------------

    def send_sol_payload(self, sol_payload: bytes) -> None:
        """Send one SOL payload packet (RMCP+ payload type 0x01) on the
        active lanplus session. Fire-and-forget: SOL replies arrive
        asynchronously and are read via the raw socket / decode_rmcp_payload.
        """
        self.transport._socket().send(self._wrap_lanplus(0x01, sol_payload))

    def decode_rmcp_payload(self, datagram: bytes) -> tuple[int, bytes] | None:
        """Decrypt+unwrap a raw RMCP+ datagram into (payload_type, plaintext),
        or None if it has no IPMI 2.0 session layer. Used by the SOL console
        select() loop, which reads the socket itself."""
        return self._unwrap_payload(RMCP(datagram))

    def _unwrap_payload(self, reply: Packet) -> tuple[int, bytes] | None:
        """Return (payload_type, decrypted payload bytes) for an RMCP+ reply,
        or None if there's no session layer / no body."""
        from scapy.packet import Raw
        cs = self.cipher
        sess = reply.getlayer(IPMI20_Session)
        if sess is None:
            return None
        raw_layer = sess.getlayer(Raw)
        if raw_layer is None:
            return None
        body = bytes(raw_layer.load)[: sess.payload_length]
        if sess.encrypted and cs is not None and cs.conf_alg == 1:
            body = aes_decrypt(self.k2, body)
        return int(sess.payload_type), body

    def _unwrap_lanplus(self, reply: Packet) -> tuple[IPMI_Message, Packet | None]:
        res = self._unwrap_payload(reply)
        if res is None:
            if reply.getlayer(IPMI20_Session) is None:
                raise IPMIError("lanplus reply: no IPMI20_Session layer")
            return None, None
        _ptype, ipmb_bytes = res

        # Manually carve the IPMB plaintext: 6 fixed pre-data header bytes,
        # variable data, 1 trailing chk2. Avoids needing a parent
        # IPMI15_Session.msg_length (the IPMI_Message dissector relies on
        # underlayer for length, which we don't have here).
        if len(ipmb_bytes) < 7:
            return None, None
        msg = IPMI_Message()
        msg.rs_addr = ipmb_bytes[0]
        nl = ipmb_bytes[1]
        msg.net_fn = (nl >> 2) & 0x3F
        msg.rs_lun = nl & 0x03
        msg.chk1 = ipmb_bytes[2]
        msg.rq_addr = ipmb_bytes[3]
        sl = ipmb_bytes[4]
        msg.rq_seq = (sl >> 2) & 0x3F
        msg.rq_lun = sl & 0x03
        msg.cmd = ipmb_bytes[5]
        msg.data = ipmb_bytes[6:-1]
        msg.chk2 = ipmb_bytes[-1]
        decoded = _decode_response(msg)
        return msg, decoded

    # ----------------------------------------------------------------------

    def _send_authenticated(
        self,
        netfn: int,
        cmd: int,
        req_payload: Packet | bytes | None,
    ) -> tuple[IPMI_Message, Packet | None]:
        if self.lanplus:
            return self._send_lanplus(netfn, cmd, req_payload)
        if self.session_id == 0:
            raise IPMIError("session not active; call activate() first")

        data = _payload_bytes(req_payload)
        ipmb = IPMI_Message(
            rs_addr=self.transport.rs_addr,
            net_fn=netfn,
            rs_lun=0,
            rq_addr=self.transport.rq_addr,
            rq_seq=self._next_rq_seq(),
            rq_lun=0,
            cmd=cmd,
            data=data,
        )
        ipmb_bytes = bytes(ipmb)

        # Per-message auth: if granted_auth == 0, BMC disabled per-msg auth
        # (status bit 2 in Get Channel Auth Caps). Send AuthType=None for
        # ongoing messages — matches ipmitool/Dell behaviour.
        per_msg_auth = self.granted_auth != 0
        seq = self.outbound_seq
        self.outbound_seq = (self.outbound_seq + 1) & 0xFFFFFFFF

        if per_msg_auth and self.auth_type == AUTH_MD5:
            sess_auth_type = AUTH_MD5
            auth_code = md5_auth_code(self.password, self.session_id, ipmb_bytes, seq)
        elif per_msg_auth and self.auth_type == AUTH_STRAIGHT:
            sess_auth_type = AUTH_STRAIGHT
            auth_code = straight_pwd_auth_code(self.password)
        else:
            sess_auth_type = AUTH_NONE
            auth_code = b""

        sess_hdr = IPMI15_Session(
            auth_type=sess_auth_type,
            session_seq=seq,
            session_id=self.session_id,
        )
        if auth_code:
            sess_hdr.auth_code = auth_code

        pkt = RMCP(msg_class=0x07) / sess_hdr / ipmb
        reply = RMCP(self.transport.send_recv(bytes(pkt)))
        msg = reply[IPMI_Message] if reply.haslayer(IPMI_Message) else None
        decoded = _decode_response(msg) if msg else None
        return msg, decoded

    # -- context manager sugar --------------------------------------------

    def __enter__(self):
        self.activate()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


# -- helpers --------------------------------------------------------------


def _payload_bytes(p: Packet | bytes | None) -> bytes:
    if p is None:
        return b""
    if isinstance(p, Packet):
        return bytes(p)
    return bytes(p)


def _decode_response(msg: IPMI_Message | None) -> Packet | None:
    """Decode an IPMI response Message body to its Packet class.

    Tolerates short payloads: when comp_code != 0, BMCs commonly truncate
    the response to just the comp_code byte, which would crash a Scapy
    parse expecting the full success-case layout. We catch the parse
    error and synthesise a stub holding just comp_code.
    """
    if msg is None:
        return None
    req_netfn = (msg.net_fn - 1) & 0x3F
    entry = cmds.lookup(req_netfn, msg.cmd)
    if entry is None:
        return None
    _, resp_cls = entry
    raw = bytes(msg.data) if msg.data else b""
    if not raw:
        return resp_cls()
    try:
        return resp_cls(raw)
    except Exception:
        stub = resp_cls()
        if raw:
            stub.comp_code = raw[0]
        return stub


__all__ = ["Transport", "Session", "IPMIError",
           "AUTH_NONE", "AUTH_MD2", "AUTH_MD5", "AUTH_STRAIGHT"]
