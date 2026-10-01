import { randomBytes, timingSafeEqual } from 'node:crypto';
import { decodeProtectedHeader } from 'jose';
import { SLUG } from './config.js';

export const WAIT_MS = 60_000, PAYLOAD_MS = 120_000, TOMBSTONE_MS = 60_000, POLL_MS = 25_000;
export type Metadata = { slug: string; label: string; targetOrigin: string;
  recipientPublicKey: { kty: 'RSA'; n: string; e: 'AQAB' } };
type RecordState = Metadata & { id: string; owner: string; status: 'waiting' | 'submitted' | 'acked';
  waitExpiresAt: number; payloadExpiresAt?: number; tombstoneExpiresAt?: number;
  csrf?: string; deliveryId?: string; jwe?: string; wake?: () => void;
  formCount: number; formWindow: number };
export class RelayError extends Error {
  constructor(public code: 'invalid_request' | 'request_gone' | 'forbidden' | 'busy' | 'capacity') { super(code); }
}
const token = (bytes = 24) => randomBytes(bytes).toString('base64url');

export function metadata(input: unknown): Metadata {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new RelayError('invalid_request');
  const value = input as Metadata;
  if (Object.keys(value).sort().join() !== 'label,recipientPublicKey,slug,targetOrigin'
      || typeof value.slug !== 'string' || !SLUG.test(value.slug) || value.slug.length > 32 || value.slug === 'relay'
      || typeof value.label !== 'string' || !value.label.trim() || Array.from(value.label).length > 100
      || /[\x00-\x1f\x7f]/.test(value.label) || typeof value.targetOrigin !== 'string')
    throw new RelayError('invalid_request');
  try {
    const url = new URL(value.targetOrigin);
    if (url.protocol !== 'https:' || url.username || url.password || url.origin !== value.targetOrigin)
      throw new Error();
  } catch { throw new RelayError('invalid_request'); }
  const key = value.recipientPublicKey;
  if (!key || typeof key !== 'object' || Array.isArray(key) || Object.keys(key).sort().join() !== 'e,kty,n'
      || key.kty !== 'RSA' || key.e !== 'AQAB' || typeof key.n !== 'string'
      || !/^[A-Za-z0-9_-]{342}$/.test(key.n) || Buffer.from(key.n, 'base64url').length !== 256)
    throw new RelayError('invalid_request');
  // Copy only public metadata; neither caller objects nor private JWK fields survive.
  return { slug: value.slug, label: value.label, targetOrigin: value.targetOrigin,
    recipientPublicKey: { kty: 'RSA', n: key.n, e: 'AQAB' } };
}

export class Broker {
  private records = new Map<string, RecordState>();
  constructor(public baseDomain: string, private now: () => number = Date.now, private pollMs = POLL_MS) {}
  sweep() {
    const now = this.now();
    for (const [id, state] of this.records) {
      const deadline = state.status === 'waiting' ? state.waitExpiresAt : state.status === 'submitted'
        ? state.payloadExpiresAt! : state.tombstoneExpiresAt!;
      if (now >= deadline) { this.records.delete(id); state.wake?.(); }
    }
  }
  private find(id: string, owner?: string): RecordState {
    this.sweep();
    const state = this.records.get(id);
    if (!state) throw new RelayError('request_gone');
    if (owner !== undefined && state.owner !== owner) throw new RelayError('forbidden');
    return state;
  }
  create(owner: string, input: unknown) {
    this.sweep();
    const info = metadata(input);
    if (this.records.size >= 256 || [...this.records.values()].filter(r => r.owner === owner).length >= 32)
      throw new RelayError('capacity');
    const id = token();
    const state: RecordState = { ...info, id, owner, status: 'waiting', waitExpiresAt: this.now() + WAIT_MS,
      formCount: 0, formWindow: this.now() };
    this.records.set(id, state);
    return { id, loginUrl: `https://${info.slug}-login.${this.baseDomain}/login?id=${id}`,
      status: 'waiting', waitExpiresAt: state.waitExpiresAt };
  }
  form(id: string, host: string) {
    const state = this.find(id);
    if (host !== `${state.slug}-login.${this.baseDomain}`) throw new RelayError('forbidden');
    if (state.status !== 'waiting') throw new RelayError('request_gone');
    if (this.now() - state.formWindow >= 60_000) { state.formCount = 0; state.formWindow = this.now(); }
    if (++state.formCount > 30) throw new RelayError('capacity');
    state.csrf = token(32);
    return { id, csrf: state.csrf, slug: state.slug, label: state.label,
      targetOrigin: state.targetOrigin, recipientPublicKey: state.recipientPublicKey };
  }
  submit(id: string, host: string, origin: string, cookie: string | undefined, input: unknown) {
    const state = this.find(id);
    if (host !== `${state.slug}-login.${this.baseDomain}` || origin !== `https://${host}`)
      throw new RelayError('forbidden');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new RelayError('invalid_request');
    const body = input as { csrf: string; deliveryId: string; jwe: string };
    if (Object.keys(body).sort().join() !== 'csrf,deliveryId,jwe' || typeof body.csrf !== 'string'
        || !state.csrf || body.csrf !== cookie || body.csrf.length !== state.csrf.length
        || !timingSafeEqual(Buffer.from(body.csrf), Buffer.from(state.csrf))) throw new RelayError('forbidden');
    if (state.status !== 'waiting') throw new RelayError('request_gone');
    if (!/^[A-Za-z0-9_-]{22}$/.test(body.deliveryId) || typeof body.jwe !== 'string'
        || body.jwe.length > 16_384 || !/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){4}$/.test(body.jwe))
      throw new RelayError('invalid_request');
    try {
      const header = decodeProtectedHeader(body.jwe);
      const parts = body.jwe.split('.');
      if (Object.keys(header).sort().join() !== 'alg,enc,kid,typ' || header.alg !== 'RSA-OAEP-256'
          || header.enc !== 'A256GCM' || header.typ !== 'JWE' || header.kid !== id
          || Buffer.from(parts[1], 'base64url').length !== 256
          || Buffer.from(parts[2], 'base64url').length !== 12 || Buffer.from(parts[4], 'base64url').length !== 16)
        throw new Error();
    } catch { throw new RelayError('invalid_request'); }
    state.status = 'submitted'; state.csrf = undefined;
    state.deliveryId = body.deliveryId; state.jwe = body.jwe;
    state.payloadExpiresAt = this.now() + PAYLOAD_MS; state.wake?.();
    return { status: 'submitted' };
  }
  private snapshot(state: RecordState) {
    if (state.status === 'waiting') return { status: 'waiting', waitExpiresAt: state.waitExpiresAt };
    if (state.status === 'submitted') return { status: 'submitted', deliveryId: state.deliveryId,
      jwe: state.jwe, payloadExpiresAt: state.payloadExpiresAt };
    return { status: 'acked' };
  }
  async poll(id: string, owner: string, signal?: AbortSignal) {
    const state = this.find(id, owner);
    if (state.wake) throw new RelayError('busy');
    if (state.status !== 'waiting') return this.snapshot(state);
    state.waitExpiresAt = this.now() + WAIT_MS;
    await new Promise<void>(resolve => {
      let timer: ReturnType<typeof setTimeout>;
      const done = () => { clearTimeout(timer); signal?.removeEventListener('abort', done); state.wake = undefined; resolve(); };
      state.wake = done; timer = setTimeout(done, this.pollMs);
      signal?.addEventListener('abort', done, { once: true });
      if (signal?.aborted) done();
    });
    return this.snapshot(this.find(id, owner));
  }
  ack(id: string, owner: string, input: unknown) {
    const state = this.find(id, owner);
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || Object.keys(input).join() !== 'deliveryId'
        || (input as { deliveryId: unknown }).deliveryId !== state.deliveryId || state.status === 'waiting')
      throw new RelayError('invalid_request');
    if (state.status === 'submitted') {
      state.status = 'acked'; state.jwe = undefined; state.tombstoneExpiresAt = this.now() + TOMBSTONE_MS;
      state.wake?.();
    }
    return { status: 'acked' };
  }
  cancel(id: string, owner: string) {
    const state = this.find(id, owner); this.records.delete(id); state.wake?.();
    return { status: 'cancelled' };
  }
  shutdown() {
    const states = [...this.records.values()]; this.records.clear();
    for (const state of states) { state.jwe = undefined; state.csrf = undefined; state.wake?.(); }
  }
}
