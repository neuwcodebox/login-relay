# Python SDK

Python 3.10+ with standard JOSE decryption (`jwcrypto`) and outbound HTTPS (`urllib`). It never opens a callback server, stores decrypted credentials, logs credential values, or implements a service-specific login. Run the commands below from the repository root.

## Install and configure

```sh
python -m venv .venv
.venv/bin/python -m pip install ./python
```

Provision an Ed25519 PEM signing key separately. Keep its private file on the caller's machine with appropriately restrictive file permissions. Register the matching public JWK and client ID with the relay operator out of band; there is no public key-enrollment endpoint. The SDK loads the configured key path and only exposes its public JWK through `client.public_key_jwk`. An encrypted PEM can be loaded using the optional `key_password` argument, supplied locally by the application.

Configure the relay's public base domain and the HTTPS API origin `https://relay-login.<base-domain>`. The constructor rejects a host that does not match this domain. Service metadata is immutable for each request; `target_origin` must be an exact canonical HTTPS origin, without a trailing slash, path, query, fragment, or user information.

## Use an approved local callback

Integrate the SDK into the caller's application. Define `approved_local_callback(username, password)` there and have it perform only the action the user approved. It must be synchronous and return only after successful handling. The SDK deliberately does not provide a command that prints credentials or a password environment-variable shortcut.

```python
from login_relay import RelayClient

client = RelayClient(
    relay_origin=config.relay_origin,
    client_id=config.client_id,
    signing_key_path=config.signing_key_path,
    public_base_domain=config.public_base_domain,
)

with client.create_request(
    slug=config.service_slug,
    label=config.service_label,
    target_origin=config.service_origin,
) as request:
    present_link_to_authorized_user(request.login_url)
    request.receive(approved_local_callback)
```

`config`, `present_link_to_authorized_user`, and `approved_local_callback` are caller-owned application code. Share the login URL only with the person authorized to enter the requested credentials. It has the exact form `https://<slug>-login.<base-domain>/login?id=<request-id>`.

`receive(callback, timeout=seconds)` accepts an optional total wait limit. Without it, the SDK continues outbound polling while the caller is waiting. Each server poll holds for up to 25 seconds and refreshes the waiting deadline. Network/temporary HTTP failures use bounded backoff while the current deadline remains valid. Submitted ciphertext expires independently after 120 seconds.

After authenticating the Compact JWE and validating request ID, slug, target origin, and delivery ID, the SDK calls the callback once and acknowledges the delivery. Every retry has a fresh timestamp and nonce. Lost/transient acknowledgment responses do not repeat the callback within the active request. Callback failures cancel the request and raise a fixed `CallbackError`; their original exception text is suppressed. Asynchronous callbacks are rejected rather than silently acknowledged.

`request.cancel()` (also `close()`) cancels remotely and drops the local recipient key. Context exit attempts cancellation automatically. Expiry, timeout, and protocol failures also attempt cancellation. If the relay cannot be reached during cleanup, its normal deadlines remove the remaining remote request. Creation is not automatically retried because a lost creation response is ambiguous.

## Boundaries

- Only `RSA-OAEP-256` / `A256GCM` Compact JWE is accepted, with the exact protected header `{alg, enc, typ: "JWE", kid: requestId}`
- RSA2048 recipients are generated per request and kept in process memory; only `{kty, n, e}` is transmitted
- Username/password limits are 1–512 / 1–4096 UTF-8 bytes
- Response redirects are refused; TLS uses the normal trust store
- A successful callback followed by process failure cannot offer durable exactly-once behavior; the caller must make consequential callback side effects idempotent
- Python cannot guarantee secret-memory zeroization. The application must not log callback arguments, local-variable tracebacks, or store credentials
- A request is consumed by one synchronous `receive` call; coordinate cancellation from the same application thread

## Isolated verification

```sh
PYTHONPATH=python .venv/bin/python -m unittest discover -s python/tests -v
```

Tests use generated keys, synthetic values, a fake transport, and a fake clock. No external service, live account, or real credential is used.
