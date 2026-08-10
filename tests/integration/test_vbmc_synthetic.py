"""
test_vbmc_synthetic.py — synthetic OEM-response replay through the vbmc.

WHAT     Loads a small sweep-style fixture into a generic vbmc persona and
         verifies the client gets back exactly the canned (cc, data) over the
         wire — plus the loader's skip rules (transport errors + the 0xFF
         no-response sentinel are dropped).

WHY      Locks in the JSON-driven mock path (Persona.oem_responses +
         server._dispatch fallback + vbmc/fixtures.py) so faux-real OEM
         answers can drive tests/decoder validation with no live BMC.

RELATED  scripts/oem_sweep.py (producer), zipmi/vbmc/fixtures.py.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time

import pytest

from zipmi.core import Session
from zipmi.vbmc.fixtures import apply_fixture, load_oem_fixture
from zipmi.vbmc.personas import generic
from zipmi.vbmc.server import VBMC
from zipmi.vbmc.state import State

# A miniature sweep file: OK entries, one explicit-CC, one transport error
# (no "cc" -> skipped), one 0xFF no-response sentinel (-> skipped).
# The (0x06,0x01) entry is a *decoy*: it collides with the built-in Get
# Device ID handler. server._dispatch tries DISPATCH first, so this OEM
# body must NEVER reach the wire — test_synthetic_does_not_shadow_builtins
# proves it. Its recognizable manuf field is 0x424344 ("DCB" LE) != 0.
BUILTIN_DECOY_HEX = "20000000000044434200000000000000"  # 16B, manuf bytes[6:9]=44 43 42
SAMPLE = {
    "_meta": {"source": "unit-test"},
    "fixtures": {
        "intel": {
            "0x30,0x01": {"netfn": 0x30, "cmd": 0x01, "cc": 0x00,
                          "response_hex": "046e6f6e65"},
            "0x30,0x66": {"netfn": 0x30, "cmd": 0x66, "cc": 0x00,
                          "response_hex": "0f20"},
            "0x30,0x9a": {"netfn": 0x30, "cmd": 0x9a, "cc": 0xff,
                          "response_hex": ""},          # no-response -> skipped
            "0x06,0x01": {"netfn": 0x06, "cmd": 0x01, "cc": 0x00,
                          "response_hex": BUILTIN_DECOY_HEX},  # decoy: builtin must win
        },
        "ampere": {
            "0x3c,0x02": {"netfn": 0x3c, "cmd": 0x02, "cc": 0xd4,
                          "response_hex": ""},          # firewall CC, no data
            "0x3c,0x99": {"netfn": 0x3c, "cmd": 0x99,
                          "error": "timeout"},          # transport err -> skipped
        },
    },
}


@pytest.fixture
def sample_fixture(tmp_path):
    p = tmp_path / "oem.json"
    p.write_text(json.dumps(SAMPLE))
    return str(p)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def vbmc_synth(sample_fixture):
    """Generic vbmc with the SAMPLE fixture's OEM responses applied."""
    port = _free_port()
    persona = generic.build()
    n = apply_fixture(persona, sample_fixture)
    assert n == 4                      # 3 intel + 1 ampere kept; 2 skipped
    state = State(persona=persona)

    ready = threading.Event()
    holder = {}

    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        holder["loop"] = loop
        transport, _ = loop.run_until_complete(
            loop.create_datagram_endpoint(
                lambda: VBMC(state), local_addr=("127.0.0.1", port))
        )
        holder["transport"] = transport
        ready.set()
        try:
            loop.run_forever()
        finally:
            transport.close()
            loop.close()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    ready.wait(timeout=5)
    time.sleep(0.05)
    yield port
    holder["loop"].call_soon_threadsafe(holder["loop"].stop)
    t.join(timeout=2)


def _session(port: int) -> Session:
    s = Session(host="127.0.0.1", username="root", password="calvin",
                lanplus=False, cipher_suite=3, timeout=2.0)
    s.transport.port = port
    return s


def test_loader_skips_errors_and_no_response(sample_fixture):
    table = load_oem_fixture(sample_fixture)
    assert (0x30, 0x01) in table
    assert (0x3c, 0x02) in table
    assert table[(0x30, 0x01)] == (0x00, bytes.fromhex("046e6f6e65"))
    assert table[(0x3c, 0x02)] == (0xd4, b"")
    assert (0x30, 0x9a) not in table   # 0xFF sentinel skipped
    assert (0x3c, 0x99) not in table   # transport error skipped


def test_loader_vendor_filter(sample_fixture):
    only_ampere = load_oem_fixture(sample_fixture, vendors=["ampere"])
    assert (0x3c, 0x02) in only_ampere
    assert (0x30, 0x01) not in only_ampere


def test_synthetic_ok_response(vbmc_synth):
    with _session(vbmc_synth) as s:
        cc, body = s.send_raw(0x30, 0x01)
    assert cc == 0x00
    assert body == bytes.fromhex("046e6f6e65")


def test_synthetic_explicit_cc(vbmc_synth):
    with _session(vbmc_synth) as s:
        cc, body = s.send_raw(0x3c, 0x02)
    assert cc == 0xd4
    assert body == b""


def test_synthetic_unknown_cmd_is_invalid(vbmc_synth):
    """A (netfn,cmd) not in the fixture nor built-ins -> 0xC1 Invalid Command."""
    with _session(vbmc_synth) as s:
        cc, body = s.send_raw(0x30, 0x77)
    assert cc == 0xC1
    assert body == b""


def test_synthetic_does_not_shadow_builtins(vbmc_synth):
    """Built-in Get Device ID wins over a colliding OEM fallback entry.

    SAMPLE plants a decoy OEM (0x06,0x01) response (manuf field 0x424344).
    server._dispatch consults DISPATCH before oem_responses, so the client
    must get the built-in generic-persona device-id (manuf 0, product
    0x0001, 15 bytes) — NOT the 16-byte decoy. Decoding both fields proves
    which handler answered.
    """
    with _session(vbmc_synth) as s:
        cc, body = s.send_raw(0x06, 0x01)
    assert cc == 0x00
    assert len(body) == 15                                   # builtin, not 16B decoy
    assert int.from_bytes(body[6:9], "little") == 0          # generic persona manuf
    assert int.from_bytes(body[9:11], "little") == 0x0001    # generic persona product
    assert int.from_bytes(body[6:9], "little") != 0x424344   # decoy did NOT win
