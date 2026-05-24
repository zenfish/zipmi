"""Unit coverage for SOL config + payload command codecs (Phase 1)."""

from zipmi.scapy_ipmi.commands import (
    ActivatePayloadReq,
    ActivatePayloadResp,
    DeactivatePayloadReq,
    GetPayloadActivationStatusReq,
    GetPayloadActivationStatusResp,
    GetSOLConfigParamReq,
    GetSOLConfigParamResp,
    SetSOLConfigParamReq,
    decode_sol_bitrate,
    encode_sol_bitrate,
    lookup,
)


# -- bit-rate helpers -----------------------------------------------------

def test_bitrate_decode_known_codes():
    assert decode_sol_bitrate(0x06) == 9600
    assert decode_sol_bitrate(0x07) == 19200      # iDRAC6 default
    assert decode_sol_bitrate(0x0A) == 115200


def test_bitrate_decode_masks_high_nibble():
    # Only the low nibble carries the code; high bits are reserved.
    assert decode_sol_bitrate(0xA7) == 19200


def test_bitrate_decode_unknown_is_none():
    assert decode_sol_bitrate(0x00) is None
    assert decode_sol_bitrate(0x0F) is None


def test_bitrate_encode_roundtrip():
    for baud in (9600, 19200, 38400, 57600, 115200):
        code = encode_sol_bitrate(baud)
        assert code is not None
        assert decode_sol_bitrate(code) == baud


def test_bitrate_encode_unsupported_is_none():
    assert encode_sol_bitrate(12345) is None


# -- Get/Set SOL Config Parameters ---------------------------------------

def test_get_sol_config_req_wire():
    # channel=1, volatile bit-rate selector (6).
    assert bytes(GetSOLConfigParamReq(channel=1, parameter_selector=6)).hex() == "01060000"


def test_get_sol_config_resp_parse():
    # [cc=0][param_rev=0x11][data=0x07] → volatile bit rate code 7 (19200).
    r = GetSOLConfigParamResp(bytes([0x00, 0x11, 0x07]))
    assert r.comp_code == 0x00
    assert r.parameter_revision == 0x11
    assert r.data == b"\x07"
    assert decode_sol_bitrate(r.data[0]) == 19200


def test_set_sol_config_req_wire():
    # channel=1, enable selector (1), data byte 0x01 (enable).
    assert bytes(SetSOLConfigParamReq(
        channel=1, parameter_selector=1, parameter_data=bytes([1]))).hex() == "010101"


# -- Activate / Deactivate Payload ---------------------------------------

def test_activate_payload_req_wire_sol_encrypt_auth():
    # type=SOL(1), instance=1, aux1=encrypt|auth (0xC0), 3 reserved bytes.
    assert bytes(ActivatePayloadReq(
        payload_type=1, payload_instance=1, aux1=0xC0)).hex() == "0101c0000000"


def test_activate_payload_resp_parse():
    raw = (bytes([0x00])                       # cc
           + (0).to_bytes(4, "little")         # aux
           + (80).to_bytes(2, "little")        # inbound size
           + (76).to_bytes(2, "little")        # outbound size
           + (623).to_bytes(2, "little")       # udp port
           + (0xFFFF).to_bytes(2, "little"))   # vlan
    r = ActivatePayloadResp(raw)
    assert r.comp_code == 0x00
    assert r.inbound_size == 80
    assert r.outbound_size == 76
    assert r.payload_udp_port == 623
    assert r.payload_vlan == 0xFFFF


def test_deactivate_payload_req_wire():
    assert bytes(DeactivatePayloadReq()).hex() == "010100000000"


def test_payload_activation_status_req_wire():
    assert bytes(GetPayloadActivationStatusReq(payload_type=1)).hex() == "01"


def test_payload_activation_status_resp_parse():
    # capacity=1 instance, instance 1 activated (bit 0 set).
    r = GetPayloadActivationStatusResp(bytes([0x00, 0x01, 0x01, 0x00]))
    assert r.comp_code == 0x00
    assert r.instance_capacity == 1
    assert r.activated_instances == 0x0001


# -- registry -------------------------------------------------------------

def test_commands_registered():
    assert lookup(0x0C, 0x22) == (GetSOLConfigParamReq, GetSOLConfigParamResp)
    assert lookup(0x0C, 0x21)[0] is SetSOLConfigParamReq
    assert lookup(0x06, 0x48) == (ActivatePayloadReq, ActivatePayloadResp)
    assert lookup(0x06, 0x49)[0] is DeactivatePayloadReq
    assert lookup(0x06, 0x4A) == (
        GetPayloadActivationStatusReq, GetPayloadActivationStatusResp)


# -- CLI helpers (pure) ---------------------------------------------------

from zipmi.cli.zipmi import _fmt_kbps, _parse_bitrate_value


def test_parse_bitrate_value_kbps_and_baud():
    assert _parse_bitrate_value("19.2") == 19200
    assert _parse_bitrate_value("115.2") == 115200
    assert _parse_bitrate_value("9.6") == 9600
    assert _parse_bitrate_value("19200") == 19200      # already baud
    assert _parse_bitrate_value("9600") == 9600
    assert _parse_bitrate_value("115.2k") == 115200    # trailing k tolerated


def test_parse_bitrate_value_bad():
    assert _parse_bitrate_value("fast") is None


def test_fmt_kbps():
    assert _fmt_kbps(19200) == "19.2"
    assert _fmt_kbps(115200) == "115.2"
    assert _fmt_kbps(9600) == "9.6"
