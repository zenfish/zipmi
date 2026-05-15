"""
test_vbmc_loopback.py — vbmc integration tests.

WHAT     Spins up a virtual BMC on a loopback port in a background thread,
         then exercises the zipmi client (1.5 + lanplus paths) against it.
WHY      Reproduces real BMC interaction without hardware. Catches
         end-to-end regressions that unit tests would miss (Scapy
         dispatch, AES wrap, IPMB checksums).
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

from zipmi.core import Session
from zipmi.vbmc.personas import dell_idrac6
from zipmi.vbmc.server import VBMC
from zipmi.vbmc.state import State


def _free_port() -> int:
    """Pick an unused UDP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def vbmc_dell():
    """Run a Dell-iDRAC6-personality vbmc in a background thread; tear down."""
    port = _free_port()
    state = State(persona=dell_idrac6.build())

    loop_ready = threading.Event()
    loop_holder = {}

    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop_holder["loop"] = loop
        coro = loop.create_datagram_endpoint(
            lambda: VBMC(state),
            local_addr=("127.0.0.1", port),
        )
        transport, _proto = loop.run_until_complete(coro)
        loop_holder["transport"] = transport
        loop_ready.set()
        try:
            loop.run_forever()
        finally:
            transport.close()
            loop.close()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    loop_ready.wait(timeout=5)
    time.sleep(0.05)            # let the listener settle
    yield port
    loop_holder["loop"].call_soon_threadsafe(loop_holder["loop"].stop)
    t.join(timeout=2)


def _session(port: int, lanplus: bool = False) -> Session:
    s = Session(host="127.0.0.1", username="root", password="calvin",
                lanplus=lanplus, cipher_suite=3, timeout=2.0)
    s.transport.port = port
    return s


def test_vbmc_get_device_id_15(vbmc_dell):
    with _session(vbmc_dell) as s:
        d = s.get_device_id()
    assert d.manufacturer_id_int() == 674
    assert d.product_id == 0x0100
    assert d.device_id == 0x20


def test_vbmc_get_chassis_status_15(vbmc_dell):
    with _session(vbmc_dell) as s:
        c = s.get_chassis_status()
    assert c.power_on() is True


def test_vbmc_sel_info_15(vbmc_dell):
    with _session(vbmc_dell) as s:
        si = s.send_cmd(0x0A, 0x40)
    assert si.entries == 3
    assert si.version == 0x51


def test_vbmc_lanplus_mc_info(vbmc_dell):
    with _session(vbmc_dell, lanplus=True) as s:
        d = s.get_device_id()
    assert d.manufacturer_id_int() == 674
    assert d.product_id == 0x0100


def test_vbmc_send_raw_15(vbmc_dell):
    """raw 0x06 0x01 returns the same 15-byte Get Device ID payload."""
    with _session(vbmc_dell) as s:
        cc, body = s.send_raw(0x06, 0x01)
    assert cc == 0
    # 6 fixed fields + 3 manuf + 2 product + 4 aux = 15 bytes.
    assert len(body) == 15
