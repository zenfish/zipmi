"""CLI commands for native Redfish and the decoded Lenovo XCC action surface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import _msg
from ..redfish import (
    RedfishClient,
    advertised_actions,
    find_lenovo_action,
    lenovo_action_catalog,
)


def _client(args: argparse.Namespace) -> RedfishClient:
    if not args.host:
        _msg.error("-H/--host is required")
        raise SystemExit(2)
    return RedfishClient(
        f"https://{args.host}:{args.redfish_port}", args.user, args.password,
        args.timeout, args.verify_tls,
    )


def _emit_response(args: argparse.Namespace, response) -> int:
    value = response.data
    if value is None:
        value = {"status": response.status, "bodyHex": response.body.hex()}
    if getattr(args, "json", False):
        print(json.dumps(value, indent=2, sort_keys=True))
    elif isinstance(value, (dict, list)):
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(value)
    if not 200 <= response.status < 300:
        _msg.error(f"Redfish HTTP {response.status}")
        return 1
    return 0


def cmd_redfish_get(args: argparse.Namespace) -> int:
    return _emit_response(args, _client(args).get(args.path))


def cmd_redfish_actions(args: argparse.Namespace) -> int:
    response = _client(args).get(args.path)
    if not 200 <= response.status < 300 or response.data is None:
        return _emit_response(args, response)
    actions = advertised_actions(response.data)
    if getattr(args, "json", False):
        print(json.dumps(actions, indent=2, sort_keys=True))
    else:
        for name, target in sorted(actions.items()):
            print(f"{name:<64} {target}")
    return 0


def cmd_redfish_catalog(args: argparse.Namespace) -> int:
    catalog = lenovo_action_catalog()
    actions = catalog["actions"]
    if args.query:
        query = args.query.lower()
        actions = [a for a in actions if query in a["name"].lower()]
    if getattr(args, "json", False):
        print(json.dumps({**catalog, "actions": actions}, indent=2))
    else:
        print(f"Lenovo XCC Redfish: {len(actions)} shown / {catalog['counts']['actions']} decoded actions")
        for action in actions:
            flags = ",".join(name for name, enabled in (
                ("native", action["nativeBinary"]),
                ("template", action["inputTemplate"]),
                ("schema", action["versionedSchema"]),
                ("metadata", action["metadata"]),
            ) if enabled)
            params = ", ".join(
                p["name"] + ("*" if p.get("required") else "")
                for p in action["parameters"]
            ) or "-"
            target = action["targets"][0]["target"] if action["targets"] else "discover from resource"
            print(f"{action['name']}\n  evidence: {flags or '-'}\n  params: {params}\n  target: {target}")
    return 0 if actions else 1


def _body(args: argparse.Namespace):
    if args.body_file:
        text = sys.stdin.read() if args.body_file == "-" else Path(args.body_file).read_text()
    else:
        text = args.body
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("Redfish action body must be a JSON object")
    return value


def _read_body(args: argparse.Namespace):
    try:
        return _body(args)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        _msg.error(f"invalid Redfish JSON body: {error}")
        return None


def cmd_redfish_patch(args: argparse.Namespace) -> int:
    body = _read_body(args)
    if body is None:
        return 2
    return _emit_response(args, _client(args).patch(args.path, body))


def cmd_redfish_action(args: argparse.Namespace) -> int:
    try:
        action = find_lenovo_action(args.name)
    except KeyError:
        _msg.error(f"unknown Lenovo Redfish action: {args.name}")
        return 1
    client = _client(args)
    target = args.target
    if args.resource:
        response = client.get(args.resource)
        if not 200 <= response.status < 300 or response.data is None:
            return _emit_response(args, response)
        available = advertised_actions(response.data)
        target = available.get(action["name"])
        if not target:
            _msg.error(f"{action['name']} is not advertised by {args.resource}")
            return 1
    if not target and action["targets"]:
        target = action["targets"][0]["target"]
    if not target:
        _msg.error("no exact target decoded; pass --resource to resolve the advertised target")
        return 1
    body = _read_body(args)
    if body is None:
        return 2
    return _emit_response(args, client.post(target, body))


def add_redfish_parser(sub) -> None:
    parser = sub.add_parser("redfish", aliases=["rf"], help="native Redfish client and Lenovo XCC action catalog")
    parser.add_argument("--redfish-port", type=int, default=443, help="HTTPS port (default 443)")
    parser.add_argument("--verify-tls", action="store_true", help="verify the BMC TLS certificate")
    commands = parser.add_subparsers(dest="redfish_action", required=True)

    get = commands.add_parser("get", help="GET a Redfish resource")
    get.add_argument("path")
    get.set_defaults(func=cmd_redfish_get)

    patch = commands.add_parser("patch", help="PATCH a Redfish resource")
    patch.add_argument("path")
    patch_body = patch.add_mutually_exclusive_group(required=True)
    patch_body.add_argument("--body", help="JSON object")
    patch_body.add_argument("--body-file", help="JSON file, or - for stdin")
    patch.set_defaults(func=cmd_redfish_patch)

    actions = commands.add_parser("actions", help="list actions advertised by one resource")
    actions.add_argument("path")
    actions.set_defaults(func=cmd_redfish_actions)

    catalog = commands.add_parser("catalog", help="list 88 decoded Lenovo XCC OEM actions")
    catalog.add_argument("query", nargs="?", help="case-insensitive action-name filter")
    catalog.set_defaults(func=cmd_redfish_catalog)

    action = commands.add_parser("action", help="POST a decoded Lenovo XCC OEM action")
    action.add_argument("name", help="full action name or unique method name")
    body = action.add_mutually_exclusive_group(required=True)
    body.add_argument("--body", help="JSON object")
    body.add_argument("--body-file", help="JSON file, or - for stdin")
    location = action.add_mutually_exclusive_group()
    location.add_argument("--resource", help="GET this resource and use its advertised target")
    location.add_argument("--target", help="exact action target path")
    action.set_defaults(func=cmd_redfish_action)


__all__ = ["add_redfish_parser"]
