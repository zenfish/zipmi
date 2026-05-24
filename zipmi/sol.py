"""
zipmi.sol — Serial-Over-LAN payload transport + interactive console.

WHAT     `SOLConsole` activates the SOL payload over an authenticated
         RMCP+ (lanplus) `Session`, then runs an interactive console: it
         pumps the local terminal's stdin to the BMC and the BMC's serial
         output to stdout, handling the SOL ACK/sequence protocol
         (IPMI 2.0 §15) and tilde escape sequences (`~.` quit, `~B` break).

WHY      SOL is the in-band-free way to watch a host's serial console
         (BIOS, bootloader, kernel) over the network — the BMC bridges
         the baseboard UART to RMCP+ packets. Pairs with `sol info`/`sol
         baud` so a tool can match `console=ttyS1,<baud>` automatically.

PROTOCOL SOL rides RMCP+ payload type 0x01, encrypted/authenticated like
         the cipher-3 IPMI messages of the session. Each SOL packet is a
         4-byte header — [seq][ack-seq][accepted-count][operation/status]
         — followed by character data. The spec allows only ONE
         outstanding console→BMC packet at a time (§15.5), so the sender
         is a simple stop-and-wait with retransmit.

TARGET   IPMI 2.0 §15 (SOL), §24.1-24.2 (Activate/Deactivate Payload).
RELATED  zipmi/core.py (Session._wrap_lanplus / send_sol_payload),
         zipmi/scapy_ipmi/commands.py, docs/sol-baud-detect.md.
"""

from __future__ import annotations

import os
import select
import sys
import time

from .core import IPMIError, Session
from .scapy_ipmi.commands import (
    ActivatePayloadReq,
    DeactivatePayloadReq,
    GetPayloadActivationStatusReq,
    encode_sol_bitrate,
)

PAYLOAD_TYPE_SOL = 0x01

# BMC → remote console status bits (data byte 4). Values per ipmitool
# lanplus_sol.h, matching IPMI 2.0 §15.9 Table 15-2.
SOL_STATUS_NACK           = 0x40   # BMC could not accept all our char data
SOL_STATUS_CHAR_UNAVAIL   = 0x20   # system powered down / asleep
SOL_STATUS_DEACTIVATED    = 0x10   # SOL deactivated (by us or another party)
SOL_STATUS_TX_OVERRUN     = 0x08   # BMC dropped chars (flow-control overrun)
SOL_STATUS_BREAK_DETECTED = 0x04   # break from the system serial port

# Remote console → BMC operation bits (operation byte 4).
SOL_OP_NACK          = 0x40
SOL_OP_RING          = 0x20
SOL_OP_BREAK         = 0x10
SOL_OP_CTS_PAUSE     = 0x08
SOL_OP_DROP_DCD_DSR  = 0x04
SOL_OP_FLUSH_INBOUND = 0x02
SOL_OP_FLUSH_OUTBOUND = 0x01


def build_sol_packet(seq: int, ack_seq: int, accepted: int,
                     operation: int, data: bytes = b"") -> bytes:
    """Build a 4-byte SOL header + character data."""
    return bytes([seq & 0x0F, ack_seq & 0x0F, accepted & 0xFF,
                  operation & 0xFF]) + data


def parse_sol_packet(buf: bytes) -> dict | None:
    """Parse a SOL payload into its fields, or None if too short."""
    if len(buf) < 4:
        return None
    return {
        "seq": buf[0] & 0x0F,
        "ack_seq": buf[1] & 0x0F,
        "accepted": buf[2],
        "status": buf[3],
        "data": buf[4:],
    }


class SOLProto:
    """Pure (I/O-free) SOL stop-and-wait state machine.

    Spec §15.5: only one outstanding console→BMC packet at a time, so the
    sender holds a single in-flight packet until the BMC acknowledges it.
    Isolated from sockets/terminals so it can be unit-tested directly.
    """

    def __init__(self, max_outbound: int = 255):
        self.tx_seq = 0                # last-used console→BMC sequence number
        self.outstanding: tuple[int, bytes] | None = None
        self.last_rx_seq = 0           # last BMC data packet seq we displayed
        self.max_outbound = max(1, max_outbound)

    def _advance_seq(self) -> int:
        # Sequence numbers are 1..15 and must be non-zero (0 = ACK-only).
        self.tx_seq = self.tx_seq % 15 + 1
        return self.tx_seq

    def make_data_packet(self, pending: bytes) -> bytes | None:
        """Take a snapshot of up to max_outbound bytes from `pending` and
        build a data packet, marking it outstanding. Returns the wire bytes,
        or None if a packet is already in flight or there's nothing to send.
        The caller must NOT drop bytes from its buffer until on_recv reports
        them accepted.
        """
        if self.outstanding is not None or not pending:
            return None
        chunk = pending[: self.max_outbound]
        seq = self._advance_seq()
        self.outstanding = (seq, chunk)
        return build_sol_packet(seq, 0, 0, 0, chunk)

    def make_retransmit(self) -> bytes | None:
        """Rebuild the outstanding packet for a timeout retry (same seq)."""
        if self.outstanding is None:
            return None
        seq, chunk = self.outstanding
        return build_sol_packet(seq, 0, 0, 0, chunk)

    def make_break(self) -> bytes:
        """An operation-only packet requesting the BMC generate a serial BREAK."""
        self._advance_seq()
        return build_sol_packet(self.tx_seq, 0, 0, SOL_OP_BREAK)

    def on_recv(self, pkt: dict) -> dict:
        """Process a BMC→console SOL packet.

        Returns: display (bytes for the terminal), ack (an ACK-only packet
        to send back, or None), consumed_tx (count of our outstanding bytes
        the BMC accepted — advance the send buffer by this), deactivated.
        """
        out = {"display": b"", "ack": None, "consumed_tx": 0, "deactivated": False}

        # (1) Acknowledgement of our outstanding data packet.
        if self.outstanding is not None and pkt["ack_seq"] == self.outstanding[0]:
            _seq, chunk = self.outstanding
            accepted = pkt["accepted"]
            nack = bool(pkt["status"] & SOL_STATUS_NACK)
            if accepted == 0 and not nack:
                accepted = len(chunk)        # some BMCs ACK a full packet w/ 0
            out["consumed_tx"] = min(accepted, len(chunk))
            self.outstanding = None          # remainder (if any) resent as new pkt

        # (2) Character data from the BMC → display + acknowledge.
        if pkt["seq"] != 0:
            out["display"] = pkt["data"]
            self.last_rx_seq = pkt["seq"]
            out["ack"] = build_sol_packet(0, pkt["seq"], len(pkt["data"]), 0)

        if pkt["status"] & SOL_STATUS_DEACTIVATED:
            out["deactivated"] = True
        return out


_HELP = (
    "\r\n"
    "~?  this help\r\n"
    "~.  terminate connection\r\n"
    "~B  send break\r\n"
    "~~  send the escape character\r\n"
)


class SOLConsole:
    """Interactive SOL console over an active lanplus `Session`."""

    def __init__(self, session: Session, *, encrypt: bool = True,
                 authenticate: bool = True, retry_interval: float = 0.25,
                 escape_char: str = "~"):
        self.s = session
        self.encrypt = encrypt
        self.authenticate = authenticate
        self.retry_interval = retry_interval
        self.escape = escape_char.encode()[:1]
        self.proto: SOLProto | None = None
        self.outbound_max = 255
        self._at_line_start = True
        self._esc_pending = False

    # -- payload lifecycle -------------------------------------------------

    def activate(self) -> None:
        cs = self.s.cipher
        enc = 1 if (self.encrypt and cs is not None and cs.conf_alg) else 0
        auth = 1 if (self.authenticate and cs is not None and cs.integrity_alg) else 0
        aux1 = (enc << 7) | (auth << 6)
        resp = self.s.send_cmd(0x06, 0x48, ActivatePayloadReq(
            payload_type=PAYLOAD_TYPE_SOL, payload_instance=1, aux1=aux1))
        port = resp.payload_udp_port
        if port and port != self.s.transport.port:
            raise IPMIError(
                f"BMC moved SOL to UDP port {port} (session is on "
                f"{self.s.transport.port}); separate-port SOL is not supported yet")
        # Inbound size is the max console→BMC payload field (header + data),
        # so the char chunk is that minus the 4-byte SOL header.
        self.outbound_max = max(1, (resp.inbound_size or 259) - 4)
        self.proto = SOLProto(max_outbound=self.outbound_max)

    def deactivate(self) -> None:
        try:
            self.s.send_cmd(0x06, 0x49, DeactivatePayloadReq(
                payload_type=PAYLOAD_TYPE_SOL, payload_instance=1))
        except Exception:
            pass

    # -- interactive loop --------------------------------------------------

    def run(self) -> int:
        """Activate SOL and run the console until `~.` or deactivation.
        Returns a process exit code."""
        self.activate()
        stdin_fd = sys.stdin.fileno()
        is_tty = os.isatty(stdin_fd)
        old_term = None
        if is_tty:
            import termios
            import tty
            old_term = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)
        sys.stderr.write(
            f"[SOL session opened — {self.escape.decode()}. to exit, "
            f"{self.escape.decode()}? for help]\r\n")
        sys.stderr.flush()
        try:
            return self._loop(stdin_fd)
        finally:
            # Restore blocking I/O before deactivate()/Close Session, which
            # use the synchronous send_recv path (a non-blocking socket would
            # make recvfrom raise instead of waiting for the reply).
            sock = self.s.transport._socket()
            sock.setblocking(True)
            sock.settimeout(self.s.transport.timeout)
            if old_term is not None:
                import termios
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_term)
            self.deactivate()
            sys.stderr.write("\r\n[SOL session closed]\r\n")
            sys.stderr.flush()

    def _loop(self, stdin_fd: int) -> int:
        sock = self.s.transport._socket()
        sock.setblocking(False)
        txbuf = bytearray()
        last_send = 0.0
        while True:
            # Send pending input (stop-and-wait: one packet in flight).
            if self.proto.outstanding is None and txbuf:
                pkt = self.proto.make_data_packet(bytes(txbuf))
                if pkt is not None:
                    self.s.send_sol_payload(pkt)
                    last_send = time.time()
            elif (self.proto.outstanding is not None
                  and time.time() - last_send > self.retry_interval):
                rt = self.proto.make_retransmit()
                if rt is not None:
                    self.s.send_sol_payload(rt)
                    last_send = time.time()

            rlist, _, _ = select.select([stdin_fd, sock], [], [], self.retry_interval)

            if stdin_fd in rlist:
                data = os.read(stdin_fd, 4096)
                if not data:                       # EOF on stdin
                    return 0
                keep = self._process_input(data)
                if keep is None:                   # ~. requested exit
                    return 0
                txbuf += keep

            if sock in rlist:
                try:
                    raw = sock.recv(4096)
                except (BlockingIOError, InterruptedError):
                    raw = b""
                if raw:
                    res = self.s.decode_rmcp_payload(raw)
                    if res is not None and res[0] == PAYLOAD_TYPE_SOL:
                        pkt = parse_sol_packet(res[1])
                        if pkt is not None:
                            out = self.proto.on_recv(pkt)
                            if out["consumed_tx"]:
                                del txbuf[: out["consumed_tx"]]
                            if out["display"]:
                                os.write(1, out["display"])
                            if out["ack"] is not None:
                                self.s.send_sol_payload(out["ack"])
                            if out["deactivated"]:
                                sys.stderr.write("\r\n[BMC deactivated SOL]\r\n")
                                return 0

    # -- tilde escape handling --------------------------------------------

    def _process_input(self, data: bytes) -> bytes | None:
        """Filter tilde escapes from raw stdin. Returns the bytes to forward
        to the BMC, or None when `~.` requests termination. Escapes are only
        recognized at the start of a line, mirroring ssh / ipmitool."""
        out = bytearray()
        for byte in data:
            ch = bytes([byte])
            if self._esc_pending:
                self._esc_pending = False
                if ch == b".":
                    return None
                if ch == b"B":
                    self.s.send_sol_payload(self.proto.make_break())
                    self._at_line_start = False
                    continue
                if ch == b"?":
                    sys.stderr.write(_HELP)
                    sys.stderr.flush()
                    continue
                if ch == self.escape:
                    out += self.escape          # ~~ → literal escape char
                    self._at_line_start = False
                    continue
                # Unrecognized: emit the escape char then this char verbatim.
                out += self.escape + ch
                self._at_line_start = ch in (b"\r", b"\n")
                continue
            if self._at_line_start and ch == self.escape:
                self._esc_pending = True
                continue
            out += ch
            self._at_line_start = ch in (b"\r", b"\n")
        return bytes(out)


def looptest(session: Session, iterations: int = 10, interval: float = 0.1,
             timeout: float = 2.0) -> tuple[int, int]:
    """SOL round-trip sanity check: activate the payload, send a marker
    `iterations` times and count BMC acknowledgements. Returns
    (acked, iterations). Does not require a terminal."""
    console = SOLConsole(session)
    console.activate()
    proto = console.proto
    sock = session.transport._socket()
    sock.setblocking(False)
    acked = 0
    marker = b"."
    try:
        for _ in range(iterations):
            pkt = proto.make_data_packet(marker)
            if pkt is None:                    # outstanding stuck — force resend
                pkt = proto.make_retransmit()
            sent_seq = parse_sol_packet(pkt)["seq"]
            session.send_sol_payload(pkt)
            deadline = time.time() + timeout
            while time.time() < deadline:
                rlist, _, _ = select.select([sock], [], [], deadline - time.time())
                if not rlist:
                    break
                try:
                    raw = sock.recv(4096)
                except (BlockingIOError, InterruptedError):
                    continue
                res = session.decode_rmcp_payload(raw)
                if res is None or res[0] != PAYLOAD_TYPE_SOL:
                    continue
                sp = parse_sol_packet(res[1])
                if sp is None:
                    continue
                out = proto.on_recv(sp)         # clears outstanding, builds ack
                if out["ack"] is not None:      # ack any BMC char data promptly
                    session.send_sol_payload(out["ack"])
                if sp["ack_seq"] == sent_seq:   # BMC acknowledged our packet
                    acked += 1
                    break
            time.sleep(interval)
    finally:
        sock.setblocking(True)
        sock.settimeout(session.transport.timeout)
        console.deactivate()
    return acked, iterations


# -- auto bit-rate detection ----------------------------------------------
#
# Neither ipmitool nor `sol baud` can catch a host whose UART runs at a
# different rate than the BMC is configured for — they only report the
# BMC's *configured* value. autobaud() measures the actual wire: it retunes
# the BMC's volatile SOL bit rate to each candidate, samples the host's
# serial output, and scores how much of it is printable ASCII. The rate
# that yields clean text is the host's real baud.

# Printable = tab, LF, CR + the printable ASCII range. Control bytes and
# high bytes (the hallmark of a baud mismatch) score as non-printable.
_PRINTABLE = frozenset({0x09, 0x0A, 0x0D}) | frozenset(range(0x20, 0x7F))

# Standard SOL rates, fastest first (most modern hosts boot fast).
AUTOBAUD_CANDIDATES = (115200, 57600, 38400, 19200, 9600)


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (0.0–1.0). Empty → 0.0."""
    if not data:
        return 0.0
    return sum(b in _PRINTABLE for b in data) / len(data)


def _set_volatile_bitrate(session: Session, channel: int, baud: int) -> None:
    code = encode_sol_bitrate(baud)
    if code is None:
        raise IPMIError(f"unsupported SOL baud {baud}")
    session.send_raw(0x0C, 0x21, bytes([channel & 0x0F, 6, code & 0x0F]))


def _safe_deactivate(session: Session) -> None:
    try:
        session.send_raw(0x06, 0x49, bytes(DeactivatePayloadReq(
            payload_type=PAYLOAD_TYPE_SOL, payload_instance=1)))
    except Exception:
        pass


def _capture(session: Session, console: SOLConsole, dwell: float,
             prompt: bytes) -> bytes:
    """Send `prompt` (to elicit output) and collect SOL char data for
    `dwell` seconds, acknowledging BMC packets so it keeps streaming."""
    sock = session.transport._socket()
    sock.setblocking(False)
    proto = console.proto
    if prompt:
        pkt = proto.make_data_packet(prompt)
        if pkt is not None:
            session.send_sol_payload(pkt)
    got = bytearray()
    end = time.time() + dwell
    try:
        while time.time() < end:
            rlist, _, _ = select.select([sock], [], [], max(0.0, end - time.time()))
            if not rlist:
                continue
            try:
                raw = sock.recv(4096)
            except (BlockingIOError, InterruptedError):
                continue
            res = session.decode_rmcp_payload(raw)
            if res is None or res[0] != PAYLOAD_TYPE_SOL:
                continue
            p = parse_sol_packet(res[1])
            if p is None:
                continue
            out = proto.on_recv(p)
            if out["display"]:
                got += out["display"]
            if out["ack"] is not None:
                session.send_sol_payload(out["ack"])
    finally:
        sock.setblocking(True)
        sock.settimeout(session.transport.timeout)
    return bytes(got)


def autobaud(session: Session, *, channel: int = 0x0E,
             candidates: tuple[int, ...] = AUTOBAUD_CANDIDATES,
             dwell: float = 2.5, prompt: bytes = b"\r") -> list[tuple[int, float, bytes]]:
    """Probe each candidate SOL bit rate against the live host serial.

    For each rate: deactivate any active payload, set the BMC's *volatile*
    SOL bit rate, activate SOL, send `prompt`, capture `dwell` seconds, and
    score printable-ASCII ratio. Returns [(baud, ratio, sample), ...] sorted
    best-first. Does NOT persist a choice — the caller decides what to set.
    """
    results: list[tuple[int, float, bytes]] = []
    for baud in candidates:
        if encode_sol_bitrate(baud) is None:
            continue
        _safe_deactivate(session)
        _set_volatile_bitrate(session, channel, baud)
        console = SOLConsole(session)
        try:
            console.activate()
        except IPMIError:
            results.append((baud, 0.0, b""))
            continue
        sample = _capture(session, console, dwell, prompt)
        _safe_deactivate(session)
        results.append((baud, printable_ratio(sample), sample))
    results.sort(key=lambda r: r[1], reverse=True)
    return results
