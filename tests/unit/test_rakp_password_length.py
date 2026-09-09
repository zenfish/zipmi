"""RMCP+ accepts 20-byte passwords; IPMI 1.5 retains its 16-byte limit."""

import hmac

import pytest

from zipmi.scapy_ipmi.crypto import (
    CIPHER_SUITES, derive_sik, pad_password, rakp2_authcode, rakp3_authcode,
)


@pytest.mark.parametrize("suite", [3, 17])
@pytest.mark.parametrize("length", [16, 17, 20])
def test_rmcp_password_length(suite, length):
    password = b"a" * length
    cipher = CIPHER_SUITES[suite]
    rc, rm, guid, user = b"c" * 16, b"m" * 16, b"g" * 16, b"USERID"
    sid_c, sid_m, role = 1, 2, 0x14
    identity = bytes([role, len(user)]) + user
    client_id = sid_c.to_bytes(4, "little")
    managed_id = sid_m.to_bytes(4, "little")
    digest = lambda data: hmac.new(password, data, cipher.auth_hash).digest()
    assert rakp2_authcode(cipher, password, sid_c, sid_m, rc, rm, guid, role, user) == digest(client_id + managed_id + rc + rm + guid + identity)
    assert rakp3_authcode(cipher, password, sid_c, rm, role, user) == digest(rm + client_id + identity)
    assert derive_sik(cipher, password, rc, rm, role, user) == digest(rc + rm + identity)


def test_protocol_limits_remain_enforced():
    with pytest.raises(ValueError):
        pad_password(b"a" * 17)
    with pytest.raises(ValueError):
        derive_sik(CIPHER_SUITES[17], b"a" * 21, b"c" * 16, b"m" * 16, 0x14, b"USERID")
