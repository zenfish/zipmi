"""Native Redfish transport and Lenovo XCC catalog contracts."""
from __future__ import annotations

import json


def test_lenovo_redfish_catalog_covers_all_static_surfaces():
    from zipmi.redfish import find_lenovo_action, lenovo_action_catalog

    catalog = lenovo_action_catalog()
    assert catalog["counts"] == {
        "actions": 88,
        "nativeBinary": 74,
        "inputTemplate": 76,
        "versionedSchema": 37,
        "exactTargets": 15,
    }
    reset = find_lenovo_action("NodeVirtualReset")
    assert reset["name"] == "#LenovoChassis.NodeVirtualReset"
    assert [p["name"] for p in reset["parameters"]] == ["ResetType", "NodeId"]
    assert reset["parameterSource"] == "input-template"


def test_advertised_actions_walks_standard_and_oem_nesting():
    from zipmi.redfish import advertised_actions

    resource = {"Actions": {
        "#ComputerSystem.Reset": {"target": "/reset"},
        "Oem": {"#LenovoChassis.NodeVirtualReset": {"target": "/lenovo-reset"}},
    }}
    assert advertised_actions(resource) == {
        "#ComputerSystem.Reset": "/reset",
        "#LenovoChassis.NodeVirtualReset": "/lenovo-reset",
    }


def test_redfish_client_emits_exact_authenticated_json_request(monkeypatch):
    from zipmi.redfish import RedfishClient

    captured = {}

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}
        def read(self): return b'{"ok":true}'
        def __enter__(self): return self
        def __exit__(self, *_): return False

    def urlopen(request, **kwargs):
        captured.update(request=request, kwargs=kwargs)
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    response = RedfishClient("https://bmc.example", "USERID", "secret", timeout=9).post(
        "/redfish/v1/Actions/Oem/#Lenovo.Test", {"NodeId": 2}
    )
    request = captured["request"]
    assert request.full_url == "https://bmc.example/redfish/v1/Actions/Oem/%23Lenovo.Test"
    assert request.get_method() == "POST"
    assert request.data == b'{"NodeId":2}'
    assert request.get_header("Authorization") == "Basic VVNFUklEOnNlY3JldA=="
    assert captured["kwargs"]["timeout"] == 9
    assert response.status == 200 and response.data == {"ok": True}


def test_redfish_catalog_cli_is_host_independent(capsys):
    import argparse
    from zipmi.cli.redfish_cmds import cmd_redfish_catalog

    args = argparse.Namespace(query="NodeVirtualReset", json=True)
    assert cmd_redfish_catalog(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"]["actions"] == 88
    assert [a["name"] for a in result["actions"]] == [
        "#LenovoChassis.NodeVirtualReset"
    ]
