"""Isolated protocol tests. Every credential and key is generated test data."""

import hashlib
import json
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto import jwk, jwe

from login_relay import CallbackError, ConfigurationError, InvalidEnvelope, ProtocolError, RelayClient, RelayTimeout, RequestClosed, RequestExpired, TransportError
from login_relay._crypto import b64url, unb64url
from login_relay._transport import HTTPResponse

REQUEST_ID = b64url(bytes(range(24)))
DELIVERY_ID = b64url(bytes(range(16)))
ORIGIN = "https://relay-login.example.invalid"
TARGET = "https://service.example.invalid"


def response(status, value):
    return HTTPResponse(status, json.dumps(value, separators=(",", ":")).encode())


class FakeClock:
    def __init__(self):
        self.now = 1700000000.0
        self.elapsed = 0.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.now += seconds
        self.elapsed += seconds


class FakeTransport:
    def __init__(self, clock, signing_key):
        self.clock = clock
        self.signing_key = signing_key
        self.calls = []
        self.recipient = None
        self.overrides = {}
        self.header_overrides = {}
        self.waits = 0
        self.ack_results = []
        self.payload_ttl = 120
        self.corrupt = False

    def request(self, method, url, headers, body, timeout):
        path = urlsplit(url).path
        assert not urlsplit(url).query
        canonical = "\n".join(("login-relay-v1", method, path, headers["x-relay-timestamp"], headers["x-relay-nonce"], hashlib.sha256(body).hexdigest())).encode()
        self.signing_key.public_key().verify(unb64url(headers["x-relay-signature"]), canonical)
        assert len(headers["x-relay-nonce"]) == 32
        assert headers["x-relay-client"] == "demo"
        self.calls.append((method, path, dict(headers), body, timeout))
        if method == "POST" and path == "/v1/requests":
            creation = json.loads(body)
            assert set(creation) == {"slug", "label", "targetOrigin", "recipientPublicKey"}
            assert set(creation["recipientPublicKey"]) == {"kty", "n", "e"}
            assert creation["recipientPublicKey"]["e"] == "AQAB"
            assert len(unb64url(creation["recipientPublicKey"]["n"])) == 256
            self.recipient = jwk.JWK(**creation["recipientPublicKey"])
            return response(201, {"id": REQUEST_ID, "loginUrl": "https://demo-login.example.invalid/login?id=" + REQUEST_ID, "status": "waiting", "waitExpiresAt": int((self.clock.time() + 60) * 1000)})
        if method == "GET":
            assert body == b""
            if self.waits:
                self.waits -= 1
                self.clock.sleep(min(25, timeout))
                return response(200, {"status": "waiting", "waitExpiresAt": int((self.clock.time() + 60) * 1000)})
            payload = {"requestId": REQUEST_ID, "slug": "demo", "targetOrigin": TARGET, "deliveryId": DELIVERY_ID, "username": "synthetic-user", "password": "synthetic-password"}
            payload.update(self.overrides)
            header = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "typ": "JWE", "kid": REQUEST_ID}
            header.update(self.header_overrides)
            envelope = jwe.JWE(json.dumps(payload).encode(), protected=json.dumps(header), recipient=self.recipient)
            compact = envelope.serialize(compact=True)
            if self.corrupt:
                parts = compact.split(".")
                tag = bytearray(unb64url(parts[-1]))
                tag[0] ^= 1
                parts[-1] = b64url(tag)
                compact = ".".join(parts)
            return response(200, {"status": "submitted", "deliveryId": DELIVERY_ID, "jwe": compact, "payloadExpiresAt": int((self.clock.time() + self.payload_ttl) * 1000)})
        if method == "POST" and path.endswith("/ack"):
            assert json.loads(body) == {"deliveryId": DELIVERY_ID}
            result = self.ack_results.pop(0) if self.ack_results else 200
            if isinstance(result, Exception):
                raise result
            return response(result, {"status": "acked"} if result == 200 else {"error": "temporary"})
        if method == "DELETE":
            assert body == b""
            return response(200, {"status": "cancelled"})
        raise AssertionError("Unexpected request")


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.signing_key = Ed25519PrivateKey.generate()
        self.transport = FakeTransport(self.clock, self.signing_key)
        with patch("login_relay.client.load_signing_key", return_value=self.signing_key):
            self.client = RelayClient(ORIGIN, "demo", "caller-owned.pem", public_base_domain="example.invalid", transport=self.transport, clock=self.clock)
        self.request = self.client.create_request("demo", "Demo service", TARGET)

    def methods(self):
        return [method for method, *_ in self.transport.calls]

    def test_signed_happy_path(self):
        delivered = []
        self.request.receive(lambda username, password: delivered.append((username, password)))
        self.assertEqual(delivered, [("synthetic-user", "synthetic-password")])
        self.assertEqual(self.methods(), ["POST", "GET", "POST"])
        self.assertIsNone(self.request._key)
        self.assertEqual(set(self.client.public_key_jwk), {"kty", "crv", "x"})
        self.assertEqual(self.request.login_url, "https://demo-login.example.invalid/login?id=" + REQUEST_ID)
        with self.assertRaises(RequestClosed):
            self.request.receive(lambda *_: None)

    def test_waiting_longpoll_refreshes_past_five_minutes(self):
        self.transport.waits = 13
        delivered = []
        self.request.receive(lambda *_: delivered.append(True))
        self.assertGreater(self.clock.monotonic(), 300)
        self.assertEqual(delivered, [True])
        self.assertTrue(all(call[-1] <= 30 for call in self.transport.calls))

    def test_ack_retry_does_not_repeat_callback(self):
        self.transport.ack_results = [TransportError("synthetic transport failure"), 503, 200]
        delivered = []
        self.request.receive(lambda *_: delivered.append(True))
        self.assertEqual(delivered, [True])
        self.assertEqual(self.methods(), ["POST", "GET", "POST", "POST", "POST"])
        nonces = [call[2]["x-relay-nonce"] for call in self.transport.calls]
        self.assertEqual(len(set(nonces)), len(nonces))
        self.assertGreater(self.clock.monotonic(), 0)

    def test_callback_failure_is_sanitized_and_cancelled(self):
        def failing_callback(username, password):
            raise ValueError("unsafe callback text: " + password)
        with self.assertRaises(CallbackError) as result:
            self.request.receive(failing_callback)
        self.assertEqual(str(result.exception), "Local credential callback failed")
        self.assertIsNone(result.exception.__context__)
        self.assertEqual(self.methods(), ["POST", "GET", "DELETE"])
        self.assertIsNone(self.request._key)

    def test_all_identity_bindings_are_checked(self):
        for name in ("requestId", "slug", "targetOrigin", "deliveryId"):
            with self.subTest(binding=name):
                self.setUp()
                self.transport.overrides[name] = "wrong-synthetic-binding"
                delivered = []
                with self.assertRaises(InvalidEnvelope):
                    self.request.receive(lambda *_: delivered.append(True))
                self.assertEqual(delivered, [])
                self.assertEqual(self.methods()[-1], "DELETE")
                self.assertNotIn("/ack", " ".join(call[1] for call in self.transport.calls))

    def test_header_extensions_and_bad_tag_are_rejected(self):
        for mutate in ("header", "tag"):
            with self.subTest(mutate=mutate):
                self.setUp()
                if mutate == "header":
                    self.transport.header_overrides["extra"] = "unsupported"
                else:
                    self.transport.corrupt = True
                with self.assertRaises(InvalidEnvelope):
                    self.request.receive(lambda *_: self.fail("No callback expected"))

    def test_payload_members_and_utf8_lengths(self):
        for overrides in ({"extra": "unsupported"}, {"username": "é" * 257}, {"password": "🙂" * 1025}, {"username": ""}, {"password": ""}):
            with self.subTest(fields=list(overrides)):
                self.setUp()
                self.transport.overrides = overrides
                with self.assertRaises(InvalidEnvelope):
                    self.request.receive(lambda *_: self.fail("No callback expected"))
        self.setUp()
        self.transport.overrides = {"username": "é" * 256, "password": "🙂" * 1024}
        self.request.receive(lambda *_: None)

    def test_ack_retries_stop_at_ciphertext_expiry(self):
        self.transport.payload_ttl = 1
        self.transport.ack_results = [503, 503, 503]
        delivered = []
        with self.assertRaises(RequestExpired):
            self.request.receive(lambda *_: delivered.append(True))
        self.assertEqual(delivered, [True])
        self.assertEqual(self.methods()[-1], "DELETE")

    def test_optional_wait_timeout_cancels(self):
        self.transport.waits = 100
        with self.assertRaises(RelayTimeout):
            self.request.receive(lambda *_: None, timeout=10)
        self.assertEqual(self.methods()[-1], "DELETE")

    def test_context_exit_cancels_and_discards_recipient(self):
        with self.request:
            pass
        self.assertIsNone(self.request._key)
        self.assertEqual(self.methods(), ["POST", "DELETE"])
        self.request.close()
        self.assertEqual(self.methods(), ["POST", "DELETE"])

    def test_invalid_service_metadata_is_rejected_locally(self):
        before = len(self.transport.calls)
        for slug, label, origin in (("relay", "Demo", TARGET), ("bad-slug-", "Demo", TARGET), ("1demo", "Demo", TARGET), ("demo", "", TARGET), ("demo", "   ", TARGET), ("demo", "Demo\nlabel", TARGET), ("demo", "Demo\x7flabel", TARGET), ("demo", "Demo", TARGET + "/"), ("demo", "Demo", "http://service.example.invalid"), ("demo", "Demo", "https://user@service.example.invalid")):
            with self.subTest(slug=slug, origin=origin), self.assertRaises(ConfigurationError):
                self.client.create_request(slug, label, origin)
        self.assertEqual(len(self.transport.calls), before)

    def test_response_url_and_identifier_validation(self):
        original = self.transport.request
        for field, value in (("loginUrl", "https://other.example.invalid/login?id=" + REQUEST_ID), ("id", "short")):
            def altered(*args, **kwargs):
                result = original(*args, **kwargs)
                data = json.loads(result.body)
                data[field] = value
                return response(result.status, data)
            with self.subTest(field=field), patch.object(self.transport, "request", side_effect=altered), self.assertRaises(ProtocolError):
                self.client.create_request("demo", "Demo", TARGET)


if __name__ == "__main__":
    unittest.main()
