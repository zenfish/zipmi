"""test_cipher_query_abort.py — a timed-out Get Channel Cipher Suites must ABORT,
not silently fall back to [3] and fire an Open Session Request.

RMCP+ session establishment depends on cipher-suite discovery; if the BMC never
answers it (unreachable), opening a session can only time out too. Regression
guard for that: on timeout/unreachable we raise, but a *reachable* BMC that
returns nothing usable still falls back to [3].
"""
from __future__ import annotations

import pytest

from zipmi.core import Session, IPMIError


def _sess() -> Session:
    # cipher_suite=None -> auto-discover path that calls _query_cipher_suites.
    return Session(host="192.0.2.1", username="root", password="calvin",
                   lanplus=True, cipher_suite=None, timeout=0.01)


def _boom(*_a, **_k):
    raise TimeoutError("timed out")


def test_cipher_query_timeout_raises_not_empty_set():
    s = _sess()
    s._send_lanplus_outside_session = _boom            # BMC never answers
    with pytest.raises(IPMIError, match="not opening a session"):
        s._query_cipher_suites()


def test_activate_lanplus_aborts_before_open_session_on_timeout():
    s = _sess()
    s._send_lanplus_outside_session = _boom            # transport times out (real path)
    calls: list[int] = []
    s._establish_with_cipher = lambda sid: calls.append(sid)   # would send Open Session
    with pytest.raises(IPMIError):
        s._activate_lanplus()
    assert calls == [], "must NOT attempt Open Session after a cipher-query timeout"


def test_reachable_but_garbage_still_falls_back_to_empty_set():
    # Short (<17B) reply => reachable BMC, no usable records => empty set (caller
    # then uses the [3] fallback). Only the timeout/unreachable case aborts.
    s = _sess()
    s._send_lanplus_outside_session = lambda *_a, **_k: b"\x00" * 4
    assert s._query_cipher_suites() == set()
