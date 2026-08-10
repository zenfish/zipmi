"""
test_attacks_dell.py — verify Dell attack primitives ingestion.

WHAT     Sanity-checks that every documented attack ended up in the
         catalog with the right bytes.
"""

from __future__ import annotations


def test_prochot_assert_bytes():
    from zipmi.attacks.dell import PROCHOT_ASSERT
    assert PROCHOT_ASSERT.netfn == 0x30
    assert PROCHOT_ASSERT.cmd == 0xC0
    assert PROCHOT_ASSERT.data == b"\x01\x01"
    assert PROCHOT_ASSERT.destructive is True
    assert PROCHOT_ASSERT.confirmed is True


def test_prochot_release_not_destructive():
    from zipmi.attacks.dell import PROCHOT_RELEASE
    assert PROCHOT_RELEASE.data == b"\x01\x00"
    assert PROCHOT_RELEASE.destructive is False


def test_psu_info_psu1():
    from zipmi.attacks.dell import PSU_INFO_PSU1
    assert PSU_INFO_PSU1.cmd == 0xB0
    assert PSU_INFO_PSU1.data == b"\x0a\x01"


def test_threshold_tamper_factory():
    from zipmi.attacks.dell import threshold_tamper
    p = threshold_tamper(sensor=0x0E, ucr=0xDF, unr=0xE3)
    assert p.netfn == 0x04
    assert p.cmd == 0x26
    assert p.data == bytes([0x0E, 0x06, 0x00, 0x00, 0x00, 0xDF, 0xE3])
    assert p.destructive is True


def test_destructive_requires_force():
    """AttackPrimitive.send refuses to fire destructive without force=True."""
    from zipmi.attacks.dell import PROCHOT_ASSERT
    class FakeSession:
        def send_raw(self, *a, **kw): return (0, b"")
    s = FakeSession()
    try:
        PROCHOT_ASSERT.send(s)            # type: ignore[arg-type]
        raised = False
    except RuntimeError:
        raised = True
    assert raised, "destructive primitive must require force=True"
    cc, _ = PROCHOT_ASSERT.send(s, force=True)  # type: ignore[arg-type]
    assert cc == 0


def test_attack_catalog_resolves_primitives_by_name():
    """Named catalog entries resolve to their exact wire bytes + gating.

    Pins two independent primitives fully — not just a count — so a
    mis-wired netfn/cmd/data or a flipped destructive flag is caught.
    """
    from zipmi.attacks.dell import ATTACKS
    assert len(ATTACKS) >= 10

    a = ATTACKS["DellCmdThrottleCPU.assert"]
    assert (a.netfn, a.cmd, a.data) == (0x30, 0xC0, b"\x01\x01")
    assert a.destructive is True

    p = ATTACKS["DellCmdReadPSUInfo.psu1"]
    assert (p.netfn, p.cmd, p.data) == (0x30, 0xB0, b"\x0a\x01")
    assert p.destructive is False


def test_extended_config_get_factory():
    from zipmi.attacks.dell import extended_config_get
    p = extended_config_get(group=0x01, idx=0x0042)
    assert p.cmd == 0x27
    assert p.data == bytes([0x01, 0x42, 0x00, 0x00])
