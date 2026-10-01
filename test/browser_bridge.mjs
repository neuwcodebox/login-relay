// Synthetic-browser fixture: concurrent HTTP semantics through stdio, no socket,
// credential logging, TLS bypass, production keys or deployment changes.
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { createApp } from '../dist/app.js';
import { configFromValues } from '../dist/config.js';

let relay;
const lines = createInterface({ input: process.stdin });
const send = value => process.stdout.write(JSON.stringify(value) + '\n');
lines.on('line', line => { void (async () => {
  let seq;
  try {
    const item = JSON.parse(line); seq = item.seq;
    if (item.kind === 'configure' && !relay) {
      relay = createApp(configFromValues('example.test', 'relay-login.example.test', { clients: item.clients }),
        { formScript: readFileSync(new URL('../dist/public/form.js', import.meta.url), 'utf8') });
      send({ seq, configured: true }); return;
    }
    if (!relay || item.kind !== 'http') throw new Error();
    const response = await relay.app.request(new Request(item.url, { method: item.method, headers: item.headers,
      ...(!['GET', 'HEAD'].includes(item.method) ? { body: Buffer.from(item.body, 'base64') } : {}) }));
    send({ seq, status: response.status, headers: [...response.headers],
      body: Buffer.from(await response.arrayBuffer()).toString('base64') });
  } catch { send({ seq, error: 'fixture_request_failed' }); }
})(); });
lines.on('close', () => relay?.shutdown());
