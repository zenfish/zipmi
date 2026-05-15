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
