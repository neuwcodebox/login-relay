"""Narrow JOSE primitives built on PyCA cryptography; no secret serialization."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jwcrypto import jwk, jwe

from .errors import ConfigurationError, InvalidEnvelope

_BASE64URL = re.compile(r"[A-Za-z0-9_-]*\Z")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value) or len(value) % 4 == 1:
        raise InvalidEnvelope("Invalid base64url encoding")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise InvalidEnvelope("Invalid base64url encoding") from None
    if b64url(result) != value:
        raise InvalidEnvelope("Noncanonical base64url encoding")
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEnvelope("Duplicate JSON member")
        result[key] = value
    return result


def parse_json(data: bytes) -> Any:
    failed = False
    try:
        return json.loads(data, object_pairs_hook=_unique_object, parse_constant=lambda _: _invalid_json())
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        failed = True
    if failed:
        raise InvalidEnvelope("Invalid JSON")


def _invalid_json() -> None:
    raise InvalidEnvelope("Invalid JSON constant")


def load_signing_key(path: str | Path, password: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    """Load a caller-provisioned Ed25519 PEM. Never creates or prints key material."""
    try:
        data = Path(path).read_bytes()
        if len(data) > 16384:
            raise ConfigurationError("Signing key file is too large")
        key = serialization.load_pem_private_key(data, password=password)
    except (OSError, ValueError, TypeError):
        raise ConfigurationError("Could not load the configured signing key") from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ConfigurationError("The signing key must be Ed25519")
    return key


def signing_public_jwk(key: ed25519.Ed25519PrivateKey) -> dict[str, str]:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def recipient_public_jwk(key: jwk.JWK) -> dict[str, str]:
    exported = key.export_public(as_dict=True)
    return {name: exported[name] for name in ("kty", "n", "e")}


def decrypt_compact_jwe(compact: str, key: jwk.JWK, expected_header: dict[str, Any]) -> bytes:
    """Authenticate a Compact JWE and reject all other algorithms/header extensions."""
    if not isinstance(compact, str) or len(compact) > 65536:
        raise InvalidEnvelope("Invalid envelope size")
    parts = compact.split(".")
    if len(parts) != 5 or any(not part for part in parts):
        raise InvalidEnvelope("Expected Compact JWE")
    if len(parts[0]) > 4096:
        raise InvalidEnvelope("Invalid protected header size")
    header = parse_json(unb64url(parts[0]))
    if header != expected_header:
        raise InvalidEnvelope("Unexpected protected header")
    encrypted_key, iv, ciphertext, tag = map(unb64url, parts[1:])
    if len(encrypted_key) != 256 or len(iv) != 12 or len(tag) != 16:
        raise InvalidEnvelope("Invalid envelope parameters")
    try:
        envelope = jwe.JWE(algs=["RSA-OAEP-256", "A256GCM"])
        envelope.deserialize(compact)
        envelope.decrypt(key, max_plaintext=32768)
        return envelope.payload
    except Exception:
        raise InvalidEnvelope("Envelope authentication failed") from None
