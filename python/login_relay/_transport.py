"""Outbound-only HTTPS with urllib, bounded bodies, and no redirects."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from .errors import ProtocolError, TransportError

_MAX_RESPONSE = 131072


@dataclass(frozen=True, repr=False)
class HTTPResponse:
    status: int
    body: bytes


class Transport(Protocol):
    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> HTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """Uses the operating system trust store and refuses HTTP redirects."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> HTTPResponse:
        request = urllib.request.Request(url, data=body if body else None, headers=dict(headers), method=method)
        try:
            try:
                response = self._opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read(_MAX_RESPONSE + 1)
                if len(data) > _MAX_RESPONSE:
                    raise ProtocolError("Relay response exceeded size limit")
                return HTTPResponse(response.status, data)
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
            raise TransportError("Relay transport failed") from None
