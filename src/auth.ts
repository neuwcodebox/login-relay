import { createHash, verify } from 'node:crypto';
import type { Config } from './config.js';
import { RelayError } from './broker.js';

export class Authenticator {
  private nonces = new Map<string, Map<string, number>>();
  private rates = new Map<string, { count: number; window: number }>();
  constructor(private config: Config, private now: () => number = Date.now) {}
  authenticate(method: string, path: string, body: Uint8Array, headers: Headers): string {
    const id = headers.get('x-relay-client') ?? '';
    const timestamp = headers.get('x-relay-timestamp') ?? '';
    const nonce = headers.get('x-relay-nonce') ?? '';
    const signature = headers.get('x-relay-signature') ?? '';
    const key = this.config.clients.get(id), now = this.now();
    if (!key || !/^\d{10}$/.test(timestamp) || Math.abs(Number(timestamp) * 1000 - now) > 60_000
        || !/^[a-f0-9]{32}$/.test(nonce) || !/^[A-Za-z0-9_-]{86}$/.test(signature))
      throw new RelayError('forbidden');
    const used = this.nonces.get(id) ?? new Map<string, number>();
    for (const [value, deadline] of used) if (now >= deadline) used.delete(value);
    if (used.has(nonce)) throw new RelayError('forbidden');
    if (used.size >= 512) throw new RelayError('capacity');
    const canonical = ['login-relay-v1', method, path, timestamp, nonce,
      createHash('sha256').update(body).digest('hex')].join('\n');
    if (!verify(null, Buffer.from(canonical), key, Buffer.from(signature, 'base64url')))
      throw new RelayError('forbidden');
    used.set(nonce, now + 120_000); this.nonces.set(id, used);
    const rate = this.rates.get(id) ?? { count: 0, window: now };
    if (now - rate.window >= 60_000) { rate.window = now; rate.count = 0; }
    this.rates.set(id, rate);
    if (++rate.count > 120) throw new RelayError('capacity');
    return id;
  }
}
