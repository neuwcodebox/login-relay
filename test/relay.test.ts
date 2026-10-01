import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import test from 'node:test';
import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair, importJWK } from 'jose';
import { createApp } from '../src/app.js';
import { configFromValues } from '../src/config.js';
import { PAYLOAD_MS, WAIT_MS } from '../src/broker.js';

async function fixture() {
  let now = 1_790_900_000_000;
  const client = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519');
  const config = configFromValues('example.test', 'relay-login.example.test', { clients: {
    desktop: client.publicKey.export({ format: 'jwk' }), other: other.publicKey.export({ format: 'jwk' }) } });
  const relay = createApp(config, { formScript: '/* synthetic test only */', now: () => now, pollMs: 1 });
  const recipient = await generateKeyPair('RSA-OAEP-256', { modulusLength: 2048, extractable: true });
  const jwk = await exportJWK(recipient.publicKey);
  const info = { slug: 'sample', label: 'Sample service', targetOrigin: 'https://service.example.test',
    recipientPublicKey: { kty: 'RSA', n: jwk.n, e: 'AQAB' } };
  function signed(method: string, path: string, value?: unknown, owner = 'desktop', changes: Record<string, string> = {}) {
    const body = value === undefined ? '' : JSON.stringify(value);
    const timestamp = String(Math.floor(now / 1000)), nonce = randomBytes(16).toString('hex');
    const canonical = ['login-relay-v1', method, path, timestamp, nonce,
      createHash('sha256').update(body).digest('hex')].join('\n');
    const signature = sign(null, Buffer.from(canonical), owner === 'desktop' ? client.privateKey : other.privateKey).toString('base64url');
    return new Request('https://relay-login.example.test' + path, { method,
      headers: { 'Content-Type': 'application/json', 'x-relay-client': owner, 'x-relay-timestamp': timestamp,
        'x-relay-nonce': nonce, 'x-relay-signature': signature, ...changes },
      ...(method !== 'GET' && method !== 'HEAD' ? { body } : {}) });
  }
  async function create(value = info) {
    const response = await relay.app.request(signed('POST', '/v1/requests', value));
    assert.equal(response.status, 201); return response.json();
  }
  async function form(id: string) {
    const response = await relay.app.request(`https://sample-login.example.test/login?id=${id}`);
    assert.equal(response.status, 200);
    const html = await response.text();
    const data = JSON.parse(html.match(/id="relay-config">([^<]+)<\/script>/)![1]);
    const cookie = response.headers.get('set-cookie')!.split(';')[0];
    assert.match(response.headers.get('set-cookie')!, /HttpOnly/);
    assert.match(response.headers.get('set-cookie')!, /Secure/);
    assert.match(response.headers.get('set-cookie')!, /SameSite=Strict/);
    assert.doesNotMatch(response.headers.get('set-cookie')!, /Domain=/);
    return { data, cookie, html };
  }
  async function envelope(id: string, deliveryId = randomBytes(16).toString('base64url')) {
    const plain = { requestId: id, slug: info.slug, targetOrigin: info.targetOrigin, deliveryId,
      username: 'SYNTHETIC_ID', password: 'SYNTHETIC_PASSWORD' };
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(plain)))
      .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'JWE', kid: id })
      .encrypt(await importJWK(info.recipientPublicKey, 'RSA-OAEP-256'));
    return { plain, jwe, deliveryId };
  }
  async function submit(id: string, data: unknown, cookie: string, origin = 'https://sample-login.example.test', host = 'sample-login.example.test') {
    return relay.app.request(`https://${host}/login?id=${id}`, { method: 'POST', headers: {
      'Content-Type': 'application/json', Origin: origin, Cookie: cookie }, body: JSON.stringify(data) });
  }
  return { relay, recipient, info, signed, create, form, envelope, submit, advance: (ms: number) => now += ms };
}

test('signed create, browser JWE submission, recipient-only decrypt and idempotent ack', async () => {
  const f = await fixture(), request = await f.create();
  assert.match(request.id, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(request.loginUrl, `https://sample-login.example.test/login?id=${request.id}`);
  const { data, cookie, html } = await f.form(request.id);
  assert.doesNotMatch(html, /SYNTHETIC_PASSWORD/);
  const encrypted = await f.envelope(request.id);
  const submitted = await f.submit(request.id, { csrf: data.csrf, jwe: encrypted.jwe, deliveryId: encrypted.deliveryId }, cookie);
  assert.equal(submitted.status, 200);
  const payloadResponse = await f.relay.app.request(f.signed('GET', `/v1/requests/${request.id}/payload`));
  const payload = await payloadResponse.json();
  assert.equal(payload.status, 'submitted'); assert.equal(payload.jwe, encrypted.jwe);
  assert.doesNotMatch(JSON.stringify(payload), /SYNTHETIC_PASSWORD|SYNTHETIC_ID/);
  const decrypted = await compactDecrypt(payload.jwe, f.recipient.privateKey,
    { keyManagementAlgorithms: ['RSA-OAEP-256'], contentEncryptionAlgorithms: ['A256GCM'] });
  assert.deepEqual(JSON.parse(new TextDecoder().decode(decrypted.plaintext)), encrypted.plain);
  for (let i = 0; i < 2; i++) {
    const ack = await f.relay.app.request(f.signed('POST', `/v1/requests/${request.id}/ack`, { deliveryId: encrypted.deliveryId }));
    assert.deepEqual(await ack.json(), { status: 'acked' });
  }
  const after = await f.relay.app.request(f.signed('GET', `/v1/requests/${request.id}/payload`));
  assert.deepEqual(await after.json(), { status: 'acked' });
});

test('signature freshness, body/path binding, replay and owner rights fail closed', async () => {
  const f = await fixture();
  const signed = f.signed('POST', '/v1/requests', f.info);
  const copy = signed.clone();
  assert.equal((await f.relay.app.request(signed)).status, 201);
  assert.equal((await f.relay.app.request(copy)).status, 403);
  const stale = f.signed('POST', '/v1/requests', f.info); f.advance(61_000);
  assert.equal((await f.relay.app.request(stale)).status, 403);
  const tampered = f.signed('POST', '/v1/requests', f.info);
  assert.equal((await f.relay.app.request(new Request(tampered.url, { method: 'POST', headers: tampered.headers, body: '{}' }))).status, 403);
  const created = await f.create();
  for (const method of ['GET', 'DELETE']) {
    const path = `/v1/requests/${created.id}` + (method === 'GET' ? '/payload' : '');
    assert.equal((await f.relay.app.request(f.signed(method, path, undefined, 'other'))).status, 403);
  }
});

test('service host, HTTPS Origin and host-only CSRF submission are required', async () => {
  const f = await fixture(), request = await f.create(), { data, cookie } = await f.form(request.id);
  assert.equal((await f.relay.app.request(`https://other-login.example.test/login?id=${request.id}`)).status, 403);
  const encrypted = await f.envelope(request.id), body = { csrf: data.csrf, deliveryId: encrypted.deliveryId, jwe: encrypted.jwe };
  assert.equal((await f.submit(request.id, body, cookie, 'https://other-login.example.test')).status, 403);
  assert.equal((await f.submit(request.id, body, '')).status, 403);
  assert.equal((await f.submit(request.id, body, cookie, 'https://sample-login.example.test', 'other-login.example.test')).status, 403);
  assert.equal((await f.submit(request.id, body, cookie)).status, 200);
  assert.notEqual((await f.submit(request.id, body, cookie)).status, 200);
});

test('waiting activity refreshes wait lifetime, ciphertext expiry stays independent', async () => {
  const f = await fixture(), request = await f.create();
  f.advance(WAIT_MS - 1);
  const waiting = await f.relay.app.request(f.signed('GET', `/v1/requests/${request.id}/payload`));
  assert.equal((await waiting.json()).status, 'waiting');
  f.advance(WAIT_MS - 1);
  const { data, cookie } = await f.form(request.id), encrypted = await f.envelope(request.id);
  assert.equal((await f.submit(request.id, { csrf: data.csrf, deliveryId: encrypted.deliveryId, jwe: encrypted.jwe }, cookie)).status, 200);
  f.advance(PAYLOAD_MS - 1);
  assert.equal((await f.relay.app.request(f.signed('GET', `/v1/requests/${request.id}/payload`))).status, 200);
  f.advance(1);
  assert.equal((await f.relay.app.request(f.signed('GET', `/v1/requests/${request.id}/payload`))).status, 410);
});

test('cancel/restart, malformed public metadata and size bounds are explicit', async () => {
  const f = await fixture(), request = await f.create();
  assert.equal((await f.relay.app.request(f.signed('DELETE', `/v1/requests/${request.id}`))).status, 200);
  assert.equal((await f.relay.app.request(f.signed('GET', `/v1/requests/${request.id}/payload`))).status, 410);
  for (const changed of [{ ...f.info, slug: 'relay' }, { ...f.info, slug: 'bad--slug' },
      { ...f.info, targetOrigin: 'http://service.example.test' },
      { ...f.info, recipientPublicKey: { ...f.info.recipientPublicKey, d: 'SYNTHETIC_PRIVATE' } }]) {
    assert.equal((await f.relay.app.request(f.signed('POST', '/v1/requests', changed))).status, 400);
  }
  assert.equal((await f.relay.app.request(f.signed('POST', '/v1/requests', { padding: 'x'.repeat(21 * 1024) }))).status, 413);
  const beforeShutdown = await f.create(); f.relay.shutdown();
  assert.equal((await f.relay.app.request(f.signed('GET', `/v1/requests/${beforeShutdown.id}/payload`))).status, 410);
});
