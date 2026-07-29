"""Pure-decode tests for scripts/ipmi_firewall.py (no BMC needed)."""
import importlib.util, pathlib
_spec = importlib.util.spec_from_file_location(
    "ipmi_firewall", pathlib.Path(__file__).parents[2] / "scripts" / "ipmi_firewall.py")
fw = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(fw)


def test_bits_lsb_first():
    # byte0=0x01 -> cmd0; byte1=0xc0 -> cmds 14,15 (bits 6,7 of byte1)
    assert fw._bits(bytes([0x01, 0xc0])) == [0, 14, 15]
    assert fw._bits(bytes([0x00, 0x00])) == []


class _FakeSess:
    """Replays the real Get NetFn Support response captured from the Cray XD670."""
    def send_raw(self, netfn, cmd, data=b""):
        if (netfn, cmd) == (0x06, 0x09):   # Get NetFn Support, channel 0x0e
            return 0, bytes.fromhex("026f004083000000000000000000000000")
        return 0xc1, b""


def test_netfn_support_decode_matches_cray():
    # reserved byte0 skipped; pairs -> even NetFns. 0x6f 0x00 0x40 0x83 ...
    got = fw.get_netfn_support(_FakeSess(), 0x0e)
    assert got == [0x00, 0x02, 0x04, 0x06, 0x0a, 0x0c, 0x2c, 0x30, 0x32, 0x3e]


def test_subfn_mask_decode():
    class S:
        # req data = [channel, NetFn, LUN, Cmd]; target (nf,cmd) is in the DATA,
        # not the send_raw netfn/cmd (always 0x06/0x0C).
        def send_raw(self, netfn, cmd, data=b""):
            if (netfn, cmd) == (0x06, 0x0C) and data[1] == 0x2c and data[3] == 0x01:
                return 0, bytes([0x0b, 0x00])   # subfns 0,1,3
            return 0xc1, b""
    d = fw.get_subfn_mask(S(), 0x0C, 0x0e, 0x2c, 0x01)
    assert d == bytes([0x0b, 0x00])
    assert fw._bits(d) == [0, 1, 3]
    # unsupported command -> None (cc!=0)
    assert fw.get_subfn_mask(S(), 0x0C, 0x0e, 0x06, 0x99) is None
