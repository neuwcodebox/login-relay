# Protocol v1

HTTPS API host: `relay-login.<base-domain>`
Form host: `<slug>-login.<base-domain>`

Slugs start with a lowercase letter and contain lowercase letters, digits and
single internal hyphens, up to 32 characters. `relay` is reserved. Labels contain
1–100 Unicode characters and no C0/DEL controls. Target origins must be exact
canonical HTTPS origins without credentials, path, query or fragment.

## Client authentication

Every API operation is signed using an operator-registered Ed25519 public key.
Headers are `x-relay-client`, `x-relay-timestamp`, `x-relay-nonce`,
`x-relay-signature`. The timestamp is Unix seconds; the nonce is 16 fresh random
bytes encoded as 32 lowercase hex characters; the signature is unpadded base64url.

Sign UTF-8 bytes joined with LF, with no final LF:

```text
login-relay-v1
UPPERCASE_METHOD
/exact/path
TIMESTAMP
NONCE
SHA256_HEX_OF_EXACT_BODY_BYTES
```

No query strings are allowed on API requests. GET/DELETE bodies are empty. POST
bodies have Content-Type `application/json`. Freshness is within 60 seconds; used
nonces are rejected for 120 seconds. Every retry has a new timestamp and nonce.
Only the creating client may poll, acknowledge or cancel its request.

## Operations

POST `/v1/requests` accepts exactly:

```json
{"slug":"sample","label":"Sample service","targetOrigin":"https://service.example.test","recipientPublicKey":{"kty":"RSA","n":"EPHEMERAL_RSA2048_PUBLIC_MODULUS_BASE64URL","e":"AQAB"}}
```

201 response: `{id,loginUrl,status:"waiting",waitExpiresAt}`. Request IDs are 24
random bytes encoded as 32 base64url characters. Deadlines are Unix milliseconds.

GET `/v1/requests/<id>/payload` holds for up to 25 seconds when waiting and returns:

- `{status:"waiting",waitExpiresAt}`
- `{status:"submitted",deliveryId,jwe,payloadExpiresAt}`
- `{status:"acked"}` after acknowledgment

POST `/v1/requests/<id>/ack` accepts exactly `{deliveryId}` and returns
`{status:"acked"}`. A matching repeat is idempotent. DELETE `/v1/requests/<id>`
returns `{status:"cancelled"}`. Missing, expired and restarted requests return 410
`{error:"request_gone"}`. Other fixed errors are `invalid_request` (400),
`forbidden` (403), `busy` (409) and `capacity` (429). Oversized bodies return 413.

## Browser submission and local delivery

GET `/login?id=<id>` binds the request to its exact service host and issues a
request-specific host-only form cookie plus a matching CSRF token. POST to the
same URL requires that cookie, exact HTTPS Origin, JSON Content-Type and exactly
`{csrf,deliveryId,jwe}`. Submitted ciphertext cannot be replaced.

`deliveryId` is 16 random bytes encoded as 22 base64url characters. Compact JWE
has the exact protected header:

```json
{"alg":"RSA-OAEP-256","enc":"A256GCM","typ":"JWE","kid":"REQUEST_ID"}
```

The encrypted JSON contains exactly:

```json
{"requestId":"REQUEST_ID","slug":"sample","targetOrigin":"https://service.example.test","deliveryId":"DELIVERY_ID","username":"USER_ENTERED_ID","password":"USER_ENTERED_PASSWORD"}
```

The SDK authenticates the JWE and matches all four identity fields against its
immutable local request. Username/password are limited to 512/4096 UTF-8 bytes
and must be nonempty. The local callback must succeed before acknowledgment.
Ciphertext is removed on acknowledgment, expiry, cancellation or shutdown.
