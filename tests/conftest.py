"""
tests/conftest.py — pytest configuration and shared fixtures.

WHAT     Gates `@pytest.mark.live` tests behind ZIPMI_LIVE_TARGET env var so
         CI runs unit tests offline by default.
WHY      We need both reproducible offline tests and live verification
         against a real BMC; this lets one repo support both modes.
RELATED  pyproject.toml [tool.pytest.ini_options] markers.
"""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.environ.get("ZIPMI_LIVE_TARGET"):
        return  # live target configured; let live tests run.
    skip_live = pytest.mark.skip(reason="set ZIPMI_LIVE_TARGET to enable")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


@pytest.fixture
def live_target() -> str:
    target = os.environ.get("ZIPMI_LIVE_TARGET")
    if not target:
        pytest.skip("ZIPMI_LIVE_TARGET not set")
    return target


@pytest.fixture
def clean_oem_registry():
    """Give a test a guaranteed-empty OEM command registry, then restore it.

    `load_vendor()` mutates module-global dicts in scapy_ipmi.oem._registry,
    and Python's import memoization means those registrations persist for the
    rest of the session. Tests that must see UNPOLLUTED standard command names
    (e.g. the firewall probe, where 0x06/0x01 must resolve to "Get Device ID",
    not a vendor OEM name leaked by an earlier test) request this fixture. It
    snapshots, clears, yields, then restores — so it neither sees prior
    pollution nor disturbs later tests.
    """
    from zipmi.scapy_ipmi.oem import _registry as reg
    names = ("OEM_CMD_NAMES", "OEM_PAYLOADS", "ENTERPRISE_IDS")
    saved = {n: dict(getattr(reg, n)) for n in names}
    for n in names:
        getattr(reg, n).clear()
    try:
        yield
    finally:
        for n, snapshot in saved.items():
            d = getattr(reg, n)
            d.clear()
            d.update(snapshot)
