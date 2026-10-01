"""Signed outbound requests and locally decrypted, callback-only deliveries."""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import json
import math
import re
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import Any, Protocol
from urllib.parse import urlsplit

from jwcrypto import jwk

from ._crypto import b64url, decrypt_compact_jwe, load_signing_key, parse_json, recipient_public_jwk, signing_public_jwk, unb64url
from ._transport import Transport, UrllibTransport
from .errors import CallbackError, ConfigurationError, InvalidEnvelope, ProtocolError, RelayHTTPError, RelayTimeout, RequestClosed, RequestExpired, TransportError

_CLIENT_ID = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
_TRANSIENT = {408, 425, 429, 500, 502, 503, 504}


class Clock(Protocol):
    def time(self) -> float: ...
    def monotonic(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        if parsed.scheme != "https" or not hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
            raise ValueError
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError
        if ":" in hostname:
            host = "[" + ipaddress.IPv6Address(hostname).compressed + "]"
        else:
            host = hostname.encode("idna").decode("ascii").lower()
            if not re.fullmatch(r"[a-z0-9.-]+", host):
                raise ValueError
        canonical = "https://" + host + (f":{port}" if port and port != 443 else "")
        if value != canonical or port == 0:
            raise ValueError
    except (ValueError, TypeError, UnicodeError):
        raise ConfigurationError("Expected an exact canonical HTTPS origin") from None
    return value


def _response_object(body: bytes) -> dict[str, Any]:
    if len(body) > 131072:
        raise ProtocolError("Relay response exceeded size limit")
    try:
        result = parse_json(body)
    except InvalidEnvelope:
        raise ProtocolError("Invalid relay response") from None
    if not isinstance(result, dict):
        raise ProtocolError("Invalid relay response")
    return result


def _expiry(value: Any) -> float:
    if type(value) is not int or value <= 0:
        raise ProtocolError("Invalid relay deadline")
    return value / 1000


def _identifier(value: Any, length: int) -> str:
    if not isinstance(value, str) or len(value) != length:
        raise ProtocolError("Invalid relay identifier")
    try:
        unb64url(value)
    except InvalidEnvelope:
        raise ProtocolError("Invalid relay identifier") from None
    return value


class RelayClient:
    """Client authenticated with an existing caller-owned Ed25519 PEM key file.

    Register ``public_key_jwk`` out of band before creating requests. No private
    key is generated, exported, uploaded, printed, or persisted by this SDK.
    ``transport`` and ``clock`` are injectable for isolated tests.
    """

    def __init__(self, relay_origin: str, client_id: str, signing_key_path: str | Path, *, public_base_domain: str, key_password: bytes | None = None, transport: Transport | None = None, clock: Clock | None = None) -> None:
        self._origin = _origin(relay_origin)
        _origin("https://" + public_base_domain)
        if self._origin != "https://relay-login." + public_base_domain:
            raise ConfigurationError("Relay host does not match the configured base domain")
        self._public_base_domain = public_base_domain
        if not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id):
            raise ConfigurationError("Invalid client ID")
        self._client_id = client_id
        self._signing_key = load_signing_key(signing_key_path, key_password)
        self._transport = transport if transport is not None else UrllibTransport()
        self._clock = clock if clock is not None else time

    @property
    def public_key_jwk(self) -> dict[str, str]:
        """The stable public key to register with the relay operator."""
        return signing_public_jwk(self._signing_key)

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None, *, timeout: float = 30.0) -> tuple[int, dict[str, Any]]:
        body = b"" if payload is None else _json_bytes(payload)
        timestamp = str(int(self._clock.time()))
        nonce = secrets.token_hex(16)
        canonical = "\n".join(("login-relay-v1", method, path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode("utf-8")
        headers = {
            "x-relay-client": self._client_id,
            "x-relay-timestamp": timestamp,
            "x-relay-nonce": nonce,
            "x-relay-signature": b64url(self._signing_key.sign(canonical)),
            "Accept": "application/json",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        response = self._transport.request(method, self._origin + path, headers, body, max(0.001, timeout))
        if response.status == 410:
            raise RequestExpired("Relay request is no longer available")
        if response.status < 200 or response.status >= 300:
            raise RelayHTTPError(response.status)
        return response.status, _response_object(response.body)

    def create_request(self, slug: str, label: str, target_origin: str) -> LoginRequest:
        """Create immutable service metadata and an in-memory RSA2048 recipient.

        Creation is not automatically retried: a lost response is ambiguous,
        and the remote waiting request expires without polling.
        """
        if not isinstance(slug, str) or not 1 <= len(slug) <= 32 or not _SLUG.fullmatch(slug) or slug == "relay":
            raise ConfigurationError("Invalid service slug")
        if not isinstance(label, str) or not 1 <= len(label) <= 100 or not label.strip() or any(ord(char) < 32 or ord(char) == 127 for char in label):
            raise ConfigurationError("Invalid service label")
        _origin(target_origin)
        key = jwk.JWK.generate(kty="RSA", size=2048, public_exponent=65537)
        status, response = self._request("POST", "/v1/requests", {
            "slug": slug,
            "label": label,
            "targetOrigin": target_origin,
            "recipientPublicKey": recipient_public_jwk(key),
        })
        if status != 201 or set(response) != {"id", "loginUrl", "status", "waitExpiresAt"} or response["status"] != "waiting":
            raise ProtocolError("Invalid request creation response")
        request_id = _identifier(response["id"], 32)
        if response["loginUrl"] != "https://" + slug + "-login." + self._public_base_domain + "/login?id=" + request_id:
            raise ProtocolError("Invalid login URL")
        wait_expiry = _expiry(response["waitExpiresAt"])
        return LoginRequest(self, request_id, response["loginUrl"], slug, target_origin, key, wait_expiry)


class LoginRequest:
    """One ephemeral recipient and delivery; use a context manager for cleanup.

    The callback is invoked once after identity and JWE authentication. Only
    successful callbacks are acknowledged. Retries preserve in-memory dedup;
    exactly-once side effects across process crashes require an idempotent
    caller-owned callback. Python cannot guarantee memory zeroization.
    """

    def __init__(self, client: RelayClient, request_id: str, login_url: str, slug: str, target_origin: str, key: jwk.JWK, wait_expiry: float) -> None:
        self._client = client
        self._id = request_id
        self._login_url = login_url
        self._slug = slug
        self._target_origin = target_origin
        self._key: jwk.JWK | None = key
        self._wait_expiry = wait_expiry
        self._payload_expiry: float | None = None
        self._delivered_id: str | None = None
        self._delivered_digest: str | None = None
        self._closed = False
        self._receiving = Lock()

    @property
    def id(self) -> str:
        return self._id

    @property
    def login_url(self) -> str:
        """Share only with the person authorized to submit this login."""
        return self._login_url

    def __enter__(self) -> LoginRequest:
        if self._closed:
            raise RequestClosed("Request is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._cancel_safely()

    def _dispose(self) -> None:
        self._key = None
        self._closed = True

    def cancel(self) -> None:
        """Cancel remotely and discard the local recipient key, even on error."""
        if self._closed:
            return
        try:
            try:
                status, response = self._client._request("DELETE", f"/v1/requests/{self._id}")
                if status != 200 or response != {"status": "cancelled"}:
                    raise ProtocolError("Invalid cancellation response")
            except RequestExpired:
                pass
        finally:
            self._dispose()

    close = cancel

    def _cancel_safely(self) -> None:
        try:
            self.cancel()
        except Exception:
            pass

    def _remaining(self, overall_deadline: float | None) -> float:
        clock = self._client._clock
        if overall_deadline is not None and clock.monotonic() >= overall_deadline:
            raise RelayTimeout("Credential wait timed out")
        expiry = self._payload_expiry if self._payload_expiry is not None else self._wait_expiry
        remaining = expiry - clock.time()
        if remaining <= 0:
            raise RequestExpired("Relay request expired")
        if overall_deadline is not None:
            remaining = min(remaining, overall_deadline - clock.monotonic())
        return remaining

    def _retry(self, operation: Callable[[float], Any], overall_deadline: float | None) -> Any:
        delay = 0.5
        while True:
            remaining = self._remaining(overall_deadline)
            try:
                return operation(min(30.0, remaining))
            except TransportError:
                pass
            except RelayHTTPError as error:
                if error.status not in _TRANSIENT:
                    raise
            remaining = self._remaining(overall_deadline)
            self._client._clock.sleep(min(delay, remaining))
            delay = min(delay * 2, 5.0)

    def _credentials(self, compact: str, delivery_id: str) -> tuple[str, str]:
        if self._key is None:
            raise RequestClosed("Request is closed")
        plaintext = decrypt_compact_jwe(compact, self._key, {"alg": "RSA-OAEP-256", "enc": "A256GCM", "typ": "JWE", "kid": self._id})
        payload = parse_json(plaintext)
        if not isinstance(payload, dict) or set(payload) != {"requestId", "slug", "targetOrigin", "deliveryId", "username", "password"}:
            raise InvalidEnvelope("Invalid credential payload")
        expected = {"requestId": self._id, "slug": self._slug, "targetOrigin": self._target_origin, "deliveryId": delivery_id}
        if any(payload[name] != value for name, value in expected.items()):
            raise InvalidEnvelope("Credential identity binding failed")
        username, password = payload["username"], payload["password"]
        try:
            valid = isinstance(username, str) and isinstance(password, str) and 1 <= len(username.encode("utf-8")) <= 512 and 1 <= len(password.encode("utf-8")) <= 4096
        except UnicodeError:
            valid = False
        if not valid:
            raise InvalidEnvelope("Invalid credential field lengths")
        return username, password

    @staticmethod
    def _call_callback(callback: Callable[[str, str], None], username: str, password: str) -> None:
        failed = False
        try:
            result = callback(username, password)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                failed = True
        except Exception:
            failed = True
        if failed:
            # Raised outside the callback's exception handler so its exception
            # text (which could contain a credential) is not retained as context.
            raise CallbackError("Local credential callback failed")

    def receive(self, callback: Callable[[str, str], None], *, timeout: float | None = None) -> None:
        """Longpoll outbound for 25s at a time, decrypt locally, then ack.

        ``timeout`` is an optional total seconds limit. Without it, successful
        polls keep the waiting request alive. Failures cancel the request and
        discard its private recipient; no credentials are returned or stored.
        """
        if self._closed:
            raise RequestClosed("Request is closed")
        if not callable(callback):
            raise ConfigurationError("A local credential callback is required")
        if timeout is not None and (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0):
            raise ConfigurationError("Timeout must be positive finite seconds")
        if not self._receiving.acquire(blocking=False):
            raise RequestClosed("Request is already receiving")
        overall_deadline = None if timeout is None else self._client._clock.monotonic() + timeout
        try:
            while True:
                status, response = self._retry(lambda request_timeout: self._client._request("GET", f"/v1/requests/{self._id}/payload", timeout=request_timeout), overall_deadline)
                if status != 200:
                    raise ProtocolError("Invalid payload response")
                if response == {"status": "acked"}:
                    if self._delivered_id is None:
                        raise ProtocolError("Request was acknowledged before local delivery")
                    self._dispose()
                    return
                if response.get("status") == "waiting":
                    if set(response) != {"status", "waitExpiresAt"}:
                        raise ProtocolError("Invalid waiting response")
                    self._wait_expiry = _expiry(response["waitExpiresAt"])
                    self._remaining(overall_deadline)
                    self._client._clock.sleep(min(0.05, self._remaining(overall_deadline)))
                    continue
                if response.get("status") != "submitted" or set(response) != {"status", "deliveryId", "jwe", "payloadExpiresAt"}:
                    raise ProtocolError("Invalid submitted response")
                delivery_id = _identifier(response["deliveryId"], 22)
                compact = response["jwe"]
                if not isinstance(compact, str) or not compact.isascii():
                    raise InvalidEnvelope("Invalid encrypted delivery")
                self._payload_expiry = _expiry(response["payloadExpiresAt"])
                self._remaining(overall_deadline)
                digest = hashlib.sha256(compact.encode("utf-8")).hexdigest()
                if self._delivered_id is not None:
                    if delivery_id != self._delivered_id or digest != self._delivered_digest:
                        raise InvalidEnvelope("Delivery identity changed")
                else:
                    username, password = self._credentials(compact, delivery_id)
                    try:
                        self._call_callback(callback, username, password)
                    finally:
                        del username, password
                    self._delivered_id, self._delivered_digest = delivery_id, digest
                self._remaining(overall_deadline)
                ack_status, ack = self._retry(lambda request_timeout: self._client._request("POST", f"/v1/requests/{self._id}/ack", {"deliveryId": delivery_id}, timeout=request_timeout), overall_deadline)
                if ack_status != 200 or ack != {"status": "acked"}:
                    raise ProtocolError("Invalid acknowledgment response")
                self._dispose()
                return
        except BaseException:
            self._cancel_safely()
            raise
        finally:
            self._receiving.release()
