"""Bounded regression tests for the X14 CVE-2021-39296 live probe."""

from __future__ import annotations

import pytest

from scripts.x14_cve_2021_39296_probe import run_probe
from zipmi.core import IPMIError
from zipmi.scapy_ipmi.rakp import RAKP1, RAKP2


class _Reply:
    def __init__(self, status: int = 0):
        self.rakp2 = RAKP2(rmcp_status=status)

    def haslayer(self, layer) -> bool:
        return layer is RAKP2

    def __getitem__(self, layer):
        assert layer is RAKP2
        return self.rakp2


class _Session:
    session_id = 0x20D7E77F

    def __init__(self, *, baseline_admin: bool = False):
        self.calls = []
        self.baseline_admin = baseline_admin
        self.privilege_attempts = 0

    def _set_privilege(self, privilege: int) -> None:
        self.calls.append(("privilege", privilege))
        self.privilege_attempts += 1
        if self.privilege_attempts == 1 and not self.baseline_admin:
            raise IPMIError("exceeds user privilege", comp_code=0x81)

    def send_raw(self, netfn: int, cmd: int, data: bytes):
        self.calls.append(("raw", netfn, cmd, data))
        return (0xD4, b"") if self.privilege_attempts == 1 else (0, bytes.fromhex("10410274"))

    def _send_lanplus_outside_session(self, payload_type: int, payload: bytes):
        self.calls.append(("outside", payload_type, payload))
        return _Reply()


def test_probe_relabels_active_session_without_rakp3():
    session = _Session()

    result = run_probe(session, "ADMIN")

    outside = [call for call in session.calls if call[0] == "outside"]
    assert [call[1] for call in outside] == [0x12]
    rakp1 = RAKP1(outside[0][2])
    assert rakp1.managed_session_id == session.session_id
    assert rakp1.role == 0x14
    assert bytes(rakp1.user_name) == b"ADMIN"
    assert [call for call in session.calls if call[0] == "privilege"] == [
        ("privilege", 4), ("privilege", 4)
    ]
    assert result["before_cc"] == 0xD4
    assert result["after_cc"] == 0
    assert result["after_data"] == bytes.fromhex("10410274")


def test_probe_aborts_if_session_already_has_admin():
    session = _Session(baseline_admin=True)

    with pytest.raises(IPMIError, match="baseline unexpectedly obtained ADMIN"):
        run_probe(session, "ADMIN")

    assert session.calls == [("privilege", 4)]
