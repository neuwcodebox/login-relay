import { createPublicKey, type KeyObject } from 'node:crypto';

export type Config = { baseDomain: string; apiHost: string; clients: Map<string, KeyObject> };
export const SLUG = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const CLIENT_ID = /^[a-z][a-z0-9-]{0,31}$/;
const DOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

export function configFromValues(baseDomain: string, apiHost: string, document: unknown): Config {
  if (!DOMAIN.test(baseDomain) || !DOMAIN.test(apiHost) || apiHost !== `relay-login.${baseDomain}`)
    throw new Error('configuration');
  if (!document || typeof document !== 'object' || Array.isArray(document)
      || Object.keys(document).join() !== 'clients') throw new Error('configuration');
  const entries = (document as { clients: unknown }).clients;
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) throw new Error('configuration');
  const keys = Object.entries(entries);
  if (keys.length < 1 || keys.length > 64) throw new Error('configuration');
  const clients = new Map<string, KeyObject>();
  for (const [id, value] of keys) {
    if (!CLIENT_ID.test(id) || !value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('configuration');
    const key = value as Record<string, string>;
    if (Object.keys(key).sort().join() !== 'crv,kty,x' || key.kty !== 'OKP' || key.crv !== 'Ed25519'
        || !/^[A-Za-z0-9_-]{43}$/.test(key.x) || Buffer.from(key.x, 'base64url').length !== 32)
      throw new Error('configuration');
    clients.set(id, createPublicKey({ key, format: 'jwk' }));
  }
  return { baseDomain, apiHost, clients };
}
