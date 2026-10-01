import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { CompactEncrypt, importJWK } from 'jose';
import { createApp } from '../src/app.js';
import { configFromValues } from '../src/config.js';

test('Python SDK signs against Hono, decrypts browser-compatible JWE and acknowledges once', { timeout: 15_000 }, async () => {
  const child = spawn(process.env.TEST_PYTHON ?? 'python3', ['test/interop.py'], {
    env: { ...process.env, PYTHONPATH: `${process.cwd()}/python` }, stdio: ['pipe', 'pipe', 'pipe'] });
  let errors = '', relay: ReturnType<typeof createApp> | undefined, done = false;
  child.stderr.on('data', data => { errors += data; });
  const lines = createInterface({ input: child.stdout });
  try {
    for await (const line of lines) {
      const item = JSON.parse(line);
      if (item.kind === 'ready') {
        relay = createApp(configFromValues('example.test', 'relay-login.example.test', {
          clients: { desktop: item.publicKey } }), { formScript: '/* synthetic only */', pollMs: 1 });
      } else if (item.kind === 'request') {
        assert.ok(relay);
        const body = Buffer.from(item.body, 'base64');
        assert.doesNotMatch(body.toString(), /SYNTHETIC_PASSWORD|SYNTHETIC_ID/);
        const response = await relay.app.request(new Request(item.url, { method: item.method,
          headers: item.headers, ...(item.method !== 'GET' ? { body } : {}) }));
        const returned = Buffer.from(await response.arrayBuffer());
        if (item.method === 'POST' && new URL(item.url).pathname === '/v1/requests') {
          assert.equal(response.status, 201);
          const request = JSON.parse(returned.toString()), metadata = JSON.parse(body.toString());
          const form = await relay.app.request(request.loginUrl);
          const html = await form.text(), info = JSON.parse(html.match(/id="relay-config">([^<]+)<\/script>/)![1]);
          const deliveryId = randomBytes(16).toString('base64url');
          const credentials = { requestId: request.id, slug: metadata.slug, targetOrigin: metadata.targetOrigin,
            deliveryId, username: 'SYNTHETIC_ID', password: 'SYNTHETIC_PASSWORD' };
          const jwe = await new CompactEncrypt(Buffer.from(JSON.stringify(credentials)))
            .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'JWE', kid: request.id })
            .encrypt(await importJWK(metadata.recipientPublicKey, 'RSA-OAEP-256'));
          const submitted = await relay.app.request(request.loginUrl, { method: 'POST', headers: {
            'Content-Type': 'application/json', Origin: new URL(request.loginUrl).origin,
            Cookie: form.headers.get('set-cookie')!.split(';')[0] },
            body: JSON.stringify({ csrf: info.csrf, deliveryId, jwe }) });
          assert.equal(submitted.status, 200);
        }
        child.stdin.write(JSON.stringify({ status: response.status, body: returned.toString('base64') }) + '\n');
      } else if (item.kind === 'done') {
        assert.equal(item.callbackCount, 1); done = true;
      } else { assert.fail('Unexpected interoperability event'); }
    }
    assert.ok(done, 'SDK did not complete the synthetic delivery');
    assert.equal(errors, '');
  } finally { lines.close(); child.kill(); relay?.shutdown(); }
});
