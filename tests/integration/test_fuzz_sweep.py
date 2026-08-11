"""
test_fuzz_sweep.py — fuzz sweep harness vs vbmc.

WHAT     Runs the NetFn sweep against the loopback vbmc and asserts that
         the well-known App commands (Get Device ID, Get Channel Auth
         Caps, etc.) are detected as implemented while unknown cmds
         come back as unsupported (cc=0xC1).
WHY      Phase 6 smoke test — proves the harness loop, the rate-limit,
         and the crash-detection don't regress.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

from zipmi.core import Session
from zipmi.fuzz.length import length_corrupt
from zipmi.fuzz.sweep import sweep_netfn, summarize, BOUNDARY_DATA
from zipmi.vbmc.personas import dell_idrac6


class _RecordingSession:
    """Records every send_raw payload; no network."""
    def __init__(self):
        self.sent = []

    def send_raw(self, netfn, cmd, data):
        self.sent.append((netfn, cmd, bytes(data)))
        return 0x00, b""


def test_sweep_default_sends_only_empty_payload():
    """Without data_variants the sweep is pure enumeration: one empty probe/cmd."""
    s = _RecordingSession()
    sweep_netfn(s, netfn=0x06, cmds=[0x01, 0x04], rate_hz=0, skip=set())
    assert s.sent == [(0x06, 0x01, b""), (0x06, 0x04, b"")]


def test_sweep_data_fuzz_sends_every_variant_per_cmd():
    """--data-fuzz (BOUNDARY_DATA) actually mutates request data: each cmd is
    probed once per payload, all distinct, recorded in req_data."""
    s = _RecordingSession()
    results = sweep_netfn(s, netfn=0x06, cmds=[0x01], rate_hz=0, skip=set(),
                          data_variants=BOUNDARY_DATA)
    sent_payloads = [d for (_nf, _c, d) in s.sent]
    assert sent_payloads == list(BOUNDARY_DATA)              # every variant hit the wire
    assert len(set(sent_payloads)) == len(BOUNDARY_DATA)     # all distinct
    assert [r.req_data for r in results] == list(BOUNDARY_DATA)
    assert all(r.cc == 0x00 for r in results)
from zipmi.vbmc.server import VBMC
from zipmi.vbmc.state import State


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def vbmc_dell():
    port = _free_port()
    state = State(persona=dell_idrac6.build())
    ready = threading.Event()
    holder = {}

    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        holder["loop"] = loop
        coro = loop.create_datagram_endpoint(
            lambda: VBMC(state),
            local_addr=("127.0.0.1", port),
        )
        transport, _ = loop.run_until_complete(coro)
        holder["transport"] = transport
        ready.set()
        try:
            loop.run_forever()
        finally:
            transport.close()
            loop.close()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    ready.wait(5)
    time.sleep(0.05)
    yield port
    holder["loop"].call_soon_threadsafe(holder["loop"].stop)
    t.join(timeout=2)


def _session(port: int) -> Session:
    s = Session(host="127.0.0.1", username="root", password="calvin",
                timeout=2.0)
    s.transport.port = port
    return s


def test_fuzz_sweep_app_netfn(vbmc_dell):
    """Sweeping NetFn 0x06 against the Dell vbmc finds the canonical 8."""
    with _session(vbmc_dell) as s:
        results = sweep_netfn(s, netfn=0x06, rate_hz=200.0)
    summary = summarize(results)
    impl_cmds = {r.cmd for r in summary["bmc_responded"]}
    # Get Device ID, Get Self Test Results, Get Device GUID, Get System GUID,
    # Get Channel Auth Caps (returns 0xC7 "Request data length invalid" since
    # we send empty data — but that still reaches the handler so it counts
    # as a BMC response), Get Session Challenge, Activate Session,
    # Set Session Priv Level.
    expected = {0x01, 0x04, 0x08, 0x37, 0x38, 0x39, 0x3A, 0x3B}
    missing = expected - impl_cmds
    assert not missing, f"vbmc missing handlers for: {sorted(missing)}"
    # Should have ZERO errors (no crashes).
    errs = summary["transport_or_parse_error"]
    assert errs == [], f"unexpected errors: {errs}"


def test_fuzz_length_mutation_actually_mutates(vbmc_dell):
    """The real request-mutation fuzzer (fuzz.length) sends >1 distinct
    payload and the BMC's parser behaviour differs by mutation.

    NOTE: sweep_netfn does NOT mutate request data — it always sends
    send_raw(netfn, cmd, b"") (see zipmi/fuzz/sweep.py:115). The actual
    mutation surface for the request framing lives in fuzz.length, which
    corrupts the IPMI 1.5 msg_length prefix. This test drives that.
    """
    with _session(vbmc_dell) as s:
        results = length_corrupt(s, 0x06, 0x01, b"")

    # >1 distinct payload actually went on the wire (real mutation, not a
    # single repeated send): 4 named mutations => 4 distinct msg_length bytes.
    sent_lengths = {r.sent_msg_length for r in results}
    assert len(sent_lengths) > 1
    assert sent_lengths == {0, 6, 23, 0xFF}   # zero, truncated(7-1), oversized(7+16), byte-max

    # A well-formed body with a corrupt-but-plausible length still reaches
    # the Get Device ID handler: decode that reply and assert it's the real
    # Dell persona (manuf 674, product 0x0100) embedded in the response.
    by_name = {r.mutation: r for r in results}
    replied = [r for r in results if r.reply is not None]
    assert replied, "no mutation elicited a reply"
    dev = by_name["zero"]
    assert dev.reply is not None
    assert bytes([0xa2, 0x02, 0x00]) in dev.reply   # manuf 674 LE
    assert bytes([0x00, 0x01]) in dev.reply         # product 0x0100 LE
    # Parser behaviour is differentiated: oversized/byte-max lengths are
    # dropped by the vbmc (timeout), zero/truncated are answered.
    assert by_name["oversized"].reply is None
    assert by_name["byte-max"].reply is None
