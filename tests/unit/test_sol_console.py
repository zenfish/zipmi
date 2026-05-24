"""Unit coverage for the SOL console state machine + escape handling.

No live BMC needed: SOLProto is pure logic, and SOLConsole's tilde-escape
filter is driven through a fake session that records sent payloads.
"""

import pytest

from zipmi.sol import (
    SOL_OP_BREAK,
    SOL_STATUS_DEACTIVATED,
    SOL_STATUS_NACK,
    SOLConsole,
    SOLProto,
    build_sol_packet,
    parse_sol_packet,
)


# -- packet codec ---------------------------------------------------------

def test_build_parse_roundtrip():
    wire = build_sol_packet(seq=3, ack_seq=5, accepted=7, operation=0, data=b"hi")
    assert wire == bytes([3, 5, 7, 0]) + b"hi"
    p = parse_sol_packet(wire)
    assert p == {"seq": 3, "ack_seq": 5, "accepted": 7, "status": 0, "data": b"hi"}


def test_parse_too_short():
    assert parse_sol_packet(b"\x01\x02") is None


# -- send side: stop-and-wait + sequencing --------------------------------

def test_make_data_packet_sets_outstanding_and_blocks_second():
    p = SOLProto()
    pkt = p.make_data_packet(b"abc")
    assert parse_sol_packet(pkt)["seq"] == 1
    assert parse_sol_packet(pkt)["data"] == b"abc"
    assert p.outstanding == (1, b"abc")
    # Only one packet may be outstanding at a time (spec §15.5).
    assert p.make_data_packet(b"def") is None


def test_seq_wraps_1_to_15_skipping_zero():
    p = SOLProto()
    seqs = []
    for _ in range(16):
        pkt = p.make_data_packet(b"x")
        seqs.append(parse_sol_packet(pkt)["seq"])
        # ack it so the next packet can go out
        p.on_recv({"seq": 0, "ack_seq": seqs[-1], "accepted": 1, "status": 0, "data": b""})
    assert seqs[:3] == [1, 2, 3]
    assert seqs[14] == 15
    assert seqs[15] == 1            # wrapped, never 0
    assert 0 not in seqs


def test_max_outbound_chunks():
    p = SOLProto(max_outbound=4)
    pkt = p.make_data_packet(b"abcdefgh")
    assert parse_sol_packet(pkt)["data"] == b"abcd"


def test_make_retransmit_reuses_seq():
    p = SOLProto()
    first = p.make_data_packet(b"abc")
    rt = p.make_retransmit()
    assert rt == first             # same seq + data


def test_make_break_sets_operation_bit():
    p = SOLProto()
    brk = parse_sol_packet(p.make_break())
    assert brk["status"] & SOL_OP_BREAK       # operation byte carries break


# -- receive side ---------------------------------------------------------

def test_recv_bmc_data_displays_and_acks():
    p = SOLProto()
    out = p.on_recv({"seq": 4, "ack_seq": 0, "accepted": 0, "status": 0, "data": b"boot"})
    assert out["display"] == b"boot"
    ack = parse_sol_packet(out["ack"])
    assert ack["seq"] == 0                     # ACK-only packet
    assert ack["ack_seq"] == 4                 # acks the BMC's packet
    assert ack["accepted"] == 4                # we took all 4 chars


def test_recv_full_ack_clears_outstanding():
    p = SOLProto()
    p.make_data_packet(b"hello")               # seq 1 outstanding
    out = p.on_recv({"seq": 0, "ack_seq": 1, "accepted": 5, "status": 0, "data": b""})
    assert out["consumed_tx"] == 5
    assert p.outstanding is None


def test_recv_partial_nack_consumes_prefix():
    p = SOLProto()
    p.make_data_packet(b"hello")
    out = p.on_recv({"seq": 0, "ack_seq": 1, "accepted": 2,
                     "status": SOL_STATUS_NACK, "data": b""})
    assert out["consumed_tx"] == 2             # 'he' accepted; 'llo' resent next
    assert p.outstanding is None


def test_recv_zero_count_ack_treated_as_full():
    p = SOLProto()
    p.make_data_packet(b"hi")
    out = p.on_recv({"seq": 0, "ack_seq": 1, "accepted": 0, "status": 0, "data": b""})
    assert out["consumed_tx"] == 2             # ACK w/ 0 count = full accept


def test_recv_deactivated_flag():
    p = SOLProto()
    out = p.on_recv({"seq": 0, "ack_seq": 0, "accepted": 0,
                     "status": SOL_STATUS_DEACTIVATED, "data": b""})
    assert out["deactivated"] is True


# -- escape handling ------------------------------------------------------

class _FakeSession:
    def __init__(self):
        self.sent = []

    def send_sol_payload(self, payload):
        self.sent.append(payload)


def _console():
    c = SOLConsole(_FakeSession())
    c.proto = SOLProto()
    return c


def test_escape_dot_requests_exit():
    c = _console()
    assert c._process_input(b"~.") is None


def test_escape_only_at_line_start():
    c = _console()
    # A tilde mid-line is literal, not an escape.
    assert c._process_input(b"ab~.") == b"ab~."


def test_double_tilde_is_literal():
    c = _console()
    assert c._process_input(b"~~") == b"~"


def test_escape_break_sends_break_and_filters():
    c = _console()
    kept = c._process_input(b"~B")
    assert kept == b""                          # the ~B itself isn't forwarded
    assert len(c.s.sent) == 1
    assert parse_sol_packet(c.s.sent[0])["status"] & SOL_OP_BREAK


def test_normal_input_passes_through():
    c = _console()
    assert c._process_input(b"ls -l\r") == b"ls -l\r"


def test_escape_resets_after_newline():
    c = _console()
    # After a CR, we're at line start again, so ~. exits.
    assert c._process_input(b"ls\r") == b"ls\r"
    assert c._process_input(b"~.") is None


# -- autobaud scoring -----------------------------------------------------

from zipmi.sol import printable_ratio


def test_printable_ratio_clean_text():
    assert printable_ratio(b"login: root\r\n") == 1.0


def test_printable_ratio_baud_garbage():
    # High bytes / control noise = baud mismatch → low score.
    assert printable_ratio(bytes([0xfd, 0x80, 0x01, 0xff])) == 0.0


def test_printable_ratio_mixed():
    assert printable_ratio(b"ok" + bytes([0xfd, 0x80])) == 0.5


def test_printable_ratio_empty():
    assert printable_ratio(b"") == 0.0
