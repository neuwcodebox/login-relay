"""Synthetic SDK/server interoperability; no network or production keys."""
import base64
import json
from pathlib import Path
import tempfile
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from login_relay import RelayClient
from login_relay._crypto import signing_public_jwk
from login_relay._transport import HTTPResponse


class StdioTransport:
    def request(self, method, url, headers, body, timeout):
        print(json.dumps({"kind": "request", "method": method, "url": url,
                          "headers": dict(headers), "body": base64.b64encode(body).decode(),
                          "timeout": timeout}), flush=True)
        response = json.loads(sys.stdin.readline())
        return HTTPResponse(response["status"], base64.b64decode(response["body"]))


with tempfile.TemporaryDirectory() as folder:
    key = ed25519.Ed25519PrivateKey.generate()
    path = Path(folder) / "synthetic-signing.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    print(json.dumps({"kind": "ready", "publicKey": signing_public_jwk(key)}), flush=True)
    client = RelayClient("https://relay-login.example.test", "desktop", path,
                         public_base_domain="example.test", transport=StdioTransport())
    received = []

    def callback(username, password):
        assert username == "SYNTHETIC_ID" and password == "SYNTHETIC_PASSWORD"
        received.append(True)

    with client.create_request("sample", "Sample service", "https://service.example.test") as request:
        request.receive(callback, timeout=10)
    assert received == [True]
    print('{"kind":"done","callbackCount":1}', flush=True)
