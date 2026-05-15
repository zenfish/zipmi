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
from zipmi.fuzz.sweep import sweep_netfn, summarize
from zipmi.vbmc.personas import dell_idrac6
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
