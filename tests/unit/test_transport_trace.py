"""Wire traces identify both a hostname and its resolved IP address."""

from zipmi.core import Transport


class _Socket:
    def __init__(self, peer_ip):
        self.peer_ip = peer_ip

    def getpeername(self):
        return self.peer_ip, 623


def test_target_label_shows_resolved_ip_for_hostname():
    t = Transport(host="x14bmc")
    assert t._target_label(_Socket("10.250.0.21")) == \
        "x14bmc (10.250.0.21):623"


def test_target_label_does_not_repeat_literal_ip():
    t = Transport(host="10.250.0.21")
    assert t._target_label(_Socket("10.250.0.21")) == "10.250.0.21:623"
