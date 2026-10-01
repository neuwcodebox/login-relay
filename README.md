# Login relay

A service-agnostic encrypted login form for a waiting local Python application.
The Hono/TypeScript broker runs one in-memory process and has no database, browser,
persistent volume or outbound service connection.

## Flow

1. A registered client signs a request with its stable Ed25519 key and supplies a
   service slug, display label, exact HTTPS target origin and ephemeral RSA public key
2. The user opens `https://<slug>-login.<base-domain>/login?id=<request-id>`
3. The form displays the destination and encrypts entered ID/password in the
   browser with standard Compact JWE (`RSA-OAEP-256` / `A256GCM`)
4. Python receives ciphertext through an authenticated outbound 25-second poll,
   decrypts locally, checks identity bindings and calls an approved local callback
5. A successful callback is acknowledged once; the broker drops ciphertext

Only the Python process holds the ephemeral recipient private key. The server
configuration contains public client signing keys. Submission and read rights are
separate: the form link cannot read a delivery, and API access requires a registered
client's fresh signature. Service metadata cannot be changed after creation.

## Install and check

Use Node 24 and Python 3.12 or newer:

```sh
npm ci --ignore-scripts --no-audit --no-fund
python -m venv .venv
.venv/bin/python -m pip install ./python
npm run check
TEST_PYTHON=.venv/bin/python npm test
PYTHONPATH=python .venv/bin/python -m unittest discover -s python/tests -v
```

The six server/integration tests and twelve SDK tests use generated test keys,
synthetic credentials and an in-process transport. The interoperability test runs
an actual Python SDK against Hono through stdio, including signatures, JWE,
local callback and acknowledgment. It does not open a socket or use a live account.

## Server configuration

Required values are deployment-owned; there are no production domain/key defaults:

- `PUBLIC_BASE_DOMAIN`, such as `example.test`
- `API_HOST`, exactly `relay-login.example.test` for that base domain
- `CLIENT_TRUST_FILE`, an absolute path to a read-only public-key JSON document
- `PORT`, optional, defaults to `3000`

The trust document has this shape, with the operator's real public JWK substituted:

```json
{"clients":{"your-client":{"kty":"OKP","crv":"Ed25519","x":"REPLACE_WITH_32_BYTE_PUBLIC_KEY_BASE64URL"}}}
```

The broker accepts 1–64 registered public clients. Private JWK fields, unknown
algorithms and malformed keys are rejected. Registration is an operator-managed
configuration operation; there is no unauthenticated enrollment endpoint. Client
private signing keys stay on the local caller's computer. They are never installed
on the broker. Rotate registration deliberately when a client is retired.

```sh
npm run build
PUBLIC_BASE_DOMAIN=example.test API_HOST=relay-login.example.test \
CLIENT_TRUST_FILE=/absolute/path/to/clients.json npm start
```

Terminate TLS at an explicitly configured ingress. The application uses exact Host
and HTTPS Origin binding, host-only HttpOnly/Secure/SameSite=Strict form cookies,
CSRF tokens, restrictive CSP and no-referrer/no-store responses. Trust the serving
host and shipped form code: browser-delivered JavaScript cannot protect against an
actively compromised host replacing that JavaScript or the recipient public key.
The encryption boundary protects the broker's normal ciphertext handling and
storage-free transport; it is not an assertion of that stronger threat model.

## Lifetime and limits

- Initial waiting deadline: 60 seconds; each authenticated poll refreshes it
- A waiting client's active polls keep the request and form usable without a fixed
  total login timeout; callers can set their own optional overall wait limit
- Submitted ciphertext: 120 seconds, independent of polling activity
- Acknowledgment tombstone: 60 seconds; matching acknowledgments are idempotent
- Cancel, expiry and process restart fail explicitly as `request_gone`
- At most 256 records overall and 32 per client, with one outstanding poll per request
- Bodies are capped at 20 KiB and Compact JWE at 16 KiB
- Global traffic is capped at 1024 requests/minute and signed traffic at 120/client/minute
- Form reads are capped at 30/request/minute; nonce replay memory is capped at 512/client

No password, decrypted delivery, request body or exception text is logged by the
application. The SDK does not return credentials to a command or print/save them;
its callback is caller-owned application code. Callbacks must avoid secret logging
and be idempotent for consequential side effects. In-memory dedup does not promise
durable exactly-once handling across a client crash, and managed runtimes cannot
promise complete memory zeroization.

See [the protocol](PROTOCOL.md) and [Python SDK](python/README.md) for integration.
No service-specific login script is included.

## Container and release

The Dockerfile supports Linux ARM64 with the official Node image. Runtime UID/GID
is `10001:10001`; it works with a read-only root filesystem, no service-account
credentials, no writable mount and no egress. `/healthz` and `/readyz` return local
process state only. SIGTERM clears transient records, resolves pending polls and
closes HTTP gracefully, with a five-second shutdown bound. Run one replica using
Recreate: state is intentionally not shared between processes.

The ordinary CI workflow has read-only repository permissions and runs checks.
The ARM64 image workflow is explicit `workflow_dispatch`; publication is opt-in
and requires owner authorization. It checks the source, builds an ARM64 image and
runs a non-root/read-only/no-network container smoke before publication. No workflow
deploys infrastructure or changes network policy. For a new GHCR package, verify
public visibility and anonymous image access before claiming the image is public
or consuming it from deployment.

Domain routing, TLS wildcard coverage, public-key enrollment, image visibility,
network policy and cluster rollout are separate operator-controlled steps. This
repository does not embed production domain configuration, real credentials,
private keys or infrastructure manifests.
