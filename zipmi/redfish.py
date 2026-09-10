"""Small Redfish client plus the decoded Lenovo XCC action catalog."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class RedfishResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    data: Any | None


class RedfishClient:
    def __init__(self, base_url: str, username: str | None = None,
                 password: str | None = None, timeout: float = 5.0,
                 verify_tls: bool = False):
        self.base_url = base_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.context = ssl.create_default_context()
        if not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def url(self, path: str) -> str:
        # Lenovo embeds the Redfish action key (leading '#') in several target
        # paths.  A raw '#' is a client-side URI fragment and never reaches the
        # BMC, so encode it as a path byte before handing the URL to urllib.
        path = path.replace("#", "%23")
        url = urljoin(self.base_url, path.lstrip("/"))
        if urlsplit(url).netloc != urlsplit(self.base_url).netloc:
            raise ValueError("Redfish target must use the configured BMC origin")
        return url

    def request(self, method: str, path: str, data: Any | None = None) -> RedfishResponse:
        body = None if data is None else json.dumps(data, separators=(",", ":")).encode()
        req = urllib.request.Request(self.url(path), data=body, method=method.upper())
        req.add_header("Accept", "application/json")
        req.add_header("OData-Version", "4.0")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if self.username is not None:
            token = base64.b64encode(
                f"{self.username}:{self.password or ''}".encode()
            ).decode()
            req.add_header("Authorization", f"Basic {token}")
        try:
            response = urllib.request.urlopen(
                req, timeout=self.timeout, context=self.context
            )
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            try:
                parsed = json.loads(raw) if raw else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
            return RedfishResponse(
                response.status,
                {key: value for key, value in response.headers.items()},
                raw,
                parsed,
            )

    def get(self, path: str) -> RedfishResponse:
        return self.request("GET", path)

    def post(self, path: str, data: Any) -> RedfishResponse:
        return self.request("POST", path, data)

    def patch(self, path: str, data: Any) -> RedfishResponse:
        return self.request("PATCH", path, data)


@lru_cache(maxsize=1)
def lenovo_action_catalog() -> dict:
    path = files("zipmi").joinpath("data/sources/lenovo-xcc-redfish-actions.json")
    return json.loads(path.read_text())


def find_lenovo_action(query: str) -> dict:
    normalized = query.lower().lstrip("#")
    actions = lenovo_action_catalog()["actions"]
    exact = [a for a in actions if a["name"].lower().lstrip("#") == normalized]
    if exact:
        return exact[0]
    suffix = [a for a in actions if a["name"].lower().split(".")[-1] == normalized]
    if len(suffix) == 1:
        return suffix[0]
    raise KeyError(query)


def advertised_actions(resource: Any) -> dict[str, str]:
    """Return every action-name to target pair advertised in a resource."""
    found: dict[str, str] = {}

    def walk(value: Any, key: str | None = None) -> None:
        if isinstance(value, dict):
            target = value.get("target")
            if key and key.startswith("#") and isinstance(target, str):
                found[key] = target
            for child_key, child in value.items():
                walk(child, child_key)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(resource)
    return found


__all__ = [
    "RedfishClient", "RedfishResponse", "advertised_actions",
    "find_lenovo_action", "lenovo_action_catalog",
]
