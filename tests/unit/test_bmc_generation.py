"""
test_bmc_generation.py — verify BMC generation fingerprint heuristic.

WHAT     guess_bmc_generation((iana, product_id)) returns a human label
         like "iDRAC6 (Monolithic)" for known pairs and "iDRAC9 (guess)"
         for high-byte fallbacks. CLI's `mc info` prints the result as
         "Manufacturer Generation".
WHY      Operators want a quick "is this iDRAC6/8/9?" answer without
         memorising the Dell product-ID table. The (guess) suffix flags
         when we're inferring from byte pattern rather than exact match.
"""
from __future__ import annotations

from zipmi.consts import guess_bmc_generation


def test_known_idrac_versions():
    assert guess_bmc_generation(674, 0x0100) == "iDRAC6 (Monolithic)"
    assert guess_bmc_generation(674, 0x0103) == "iDRAC7 Modular"
    assert guess_bmc_generation(674, 0x0200) == "iDRAC8"
    assert guess_bmc_generation(674, 0x0300) == "iDRAC9"
    assert guess_bmc_generation(674, 0x0400) == "iDRAC10"


def test_high_byte_fallback_marked_guess():
    """Unknown Dell product ID with known high byte → labelled (guess)."""
    assert guess_bmc_generation(674, 0x0299) == "iDRAC8 (guess)"
    assert guess_bmc_generation(674, 0x03ff) == "iDRAC9 (guess)"


def test_unknown_returns_unknown():
    assert guess_bmc_generation(674, 0x0500) == "unknown"
    assert guess_bmc_generation(10876, 0x0001) == "unknown"
    assert guess_bmc_generation(0, 0) == "unknown"
