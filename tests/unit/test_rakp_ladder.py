"""test_rakp_ladder.py — scan rakp-hash must probe only the auth algos the BMC
ADVERTISES, opening each with an actually-offered cipher suite.

The old code hardcoded bare suites 6/1/17 and opened sessions for all three
blindly, drawing "no matching cipher suite" on BMCs that offer only full suites
(e.g. iDRAC9 offers 3 & 17, not 6 or 1). _rakp_ladder(offered) fixes that: the
RAKP2 auth code depends only on the auth algo, so SHA1 can be harvested via the
offered suite 3, SHA256 via 17.
"""
from __future__ import annotations

from zipmi.core import Session
from zipmi.scapy_ipmi.crypto import CIPHER_SUITES


def _pairs(ladder):
    """(auth_alg, suite_opened) pairs from a ladder."""
    return [(m[0], m[2]) for m in ladder]


def test_idrac9_offers_3_17_uses_those_suites():
    # iDRAC9: offers 3 (SHA1+AES) and 17 (SHA256+AES), NOT the bare 6/1.
    ladder = Session._rakp_ladder({3, 17})
    pairs = _pairs(ladder)
    assert (1, 3) in pairs, "SHA1 hash must be grabbed via the offered suite 3"
    assert (3, 17) in pairs, "SHA256 hash must be grabbed via the offered suite 17"
    assert all(a != 2 for a, _ in pairs), "MD5 (auth 2) not offered -> must be skipped"
    # every suite chosen is one the BMC actually advertised
    assert all(s in {3, 17} for _, s in pairs)


def test_full_offering_uses_default_bare_suites():
    # A BMC that offers the bare suites keeps using them (x10 offers 0-14).
    ladder = Session._rakp_ladder(set(range(0, 15)))
    pairs = _pairs(ladder)
    assert (2, 6) in pairs and (1, 1) in pairs   # MD5->6, SHA1->1 (defaults offered)


def test_empty_offered_falls_back_to_full_blind_ladder():
    # Reachable-but-unparseable discovery -> last-resort blind try of all algos.
    assert Session._rakp_ladder(set()) == list(Session._RAKP_HASH_ALGOS)


def test_no_crackable_auth_algo_yields_empty_ladder():
    # Only cipher 0 (auth = none) offered -> nothing to harvest.
    assert Session._rakp_ladder({0}) == []


def test_chosen_suites_have_matching_auth_alg():
    # Invariant: the suite opened for each algo genuinely uses that auth algo.
    for offered in ({3, 17}, {1, 2, 3}, set(range(0, 20))):
        for auth_alg, _n, suite, *_ in Session._rakp_ladder(offered):
            assert CIPHER_SUITES[suite].auth_alg == auth_alg
