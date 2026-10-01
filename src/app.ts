import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { setCookie, getCookie } from 'hono/cookie';
import { Authenticator } from './auth.js';
import { Broker, RelayError } from './broker.js';
import type { Config } from './config.js';

const escape = (s: string) => s.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;',
  '"': '&quot;', "'": '&#39;' })[ch]!);
const CSS = 'body{font:16px system-ui;margin:3rem auto;padding:0 1rem;max-width:34rem;background:#f5f7fb;color:#152236}form{display:grid;gap:1rem;background:white;padding:2rem;border-radius:1rem}label{display:grid;gap:.4rem}input,button{font:inherit;padding:.8rem;border:1px solid #9ba8ba;border-radius:.4rem}button{background:#1649ba;color:white}small,p{overflow-wrap:anywhere}';
type Bindings = { Variables: { owner: string; raw: Uint8Array } };

export function createApp(config: Config, options: { formScript: string; now?: () => number; pollMs?: number }) {
  const now = options.now ?? Date.now;
  const broker = new Broker(config.baseDomain, now, options.pollMs);
  const auth = new Authenticator(config, now);
  const app = new Hono<Bindings>();
  let stopped = false, globalWindow = now(), globalCount = 0;
  app.use('*', async (c, next) => {
    c.header('Cache-Control', 'no-store'); c.header('Referrer-Policy', 'no-referrer');
    c.header('X-Content-Type-Options', 'nosniff'); c.header('X-Frame-Options', 'DENY');
    c.header('Strict-Transport-Security', 'max-age=31536000');
    c.header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    if (stopped && c.req.path !== '/healthz') return c.json({ error: 'request_gone' }, 410);
    if (!['/healthz', '/readyz'].includes(c.req.path)) {
      if (now() - globalWindow >= 60_000) { globalWindow = now(); globalCount = 0; }
      if (++globalCount > 1024) return c.json({ error: 'capacity' }, 429);
    }
    await next();
  });
  app.use('*', bodyLimit({ maxSize: 20 * 1024, onError: c => c.json({ error: 'invalid_request' }, 413) }));
  app.onError((error, c) => {
    const code = error instanceof RelayError ? error.code : 'invalid_request';
    const status = code === 'request_gone' ? 410 : code === 'forbidden' ? 403
      : code === 'capacity' ? 429 : code === 'busy' ? 409 : 400;
    return c.json({ error: code }, status);
  });
  app.get('/healthz', c => c.json({ status: 'ok' }));
  app.get('/readyz', c => c.json({ status: 'ready' }));
  const host = (c: { req: { url: string; header: (name: string) => string | undefined } }) =>
    (c.req.header('host') ?? new URL(c.req.url).host).toLowerCase();
  app.use('/v1/*', async (c, next) => {
    if (host(c) !== config.apiHost || new URL(c.req.url).search) throw new RelayError('forbidden');
    const raw = new Uint8Array(await c.req.arrayBuffer());
    if (c.req.method === 'POST' && c.req.header('content-type') !== 'application/json')
      throw new RelayError('invalid_request');
    if (['GET', 'DELETE'].includes(c.req.method) && raw.length) throw new RelayError('invalid_request');
    c.set('raw', raw);
    c.set('owner', auth.authenticate(c.req.method, c.req.path, raw, c.req.raw.headers));
    await next();
  });
  const parsed = (raw: Uint8Array) => {
    try { return JSON.parse(Buffer.from(raw).toString('utf8')); }
    catch { throw new RelayError('invalid_request'); }
  };
  app.post('/v1/requests', c => c.json(broker.create(c.get('owner'), parsed(c.get('raw'))), 201));
  app.get('/v1/requests/:id/payload', async c => {
    if (!/^[A-Za-z0-9_-]{32}$/.test(c.req.param('id'))) throw new RelayError('invalid_request');
    return c.json(await broker.poll(c.req.param('id'), c.get('owner'), c.req.raw.signal));
  });
  app.post('/v1/requests/:id/ack', c => c.json(broker.ack(c.req.param('id'), c.get('owner'), parsed(c.get('raw')))));
  app.delete('/v1/requests/:id', c => c.json(broker.cancel(c.req.param('id'), c.get('owner'))));
  const requestId = (url: string) => {
    const search = new URL(url).searchParams, id = search.get('id') ?? '';
    if (search.size !== 1 || !/^[A-Za-z0-9_-]{32}$/.test(id)) throw new RelayError('invalid_request');
    return id;
  };
  app.get('/login', c => {
    const info = broker.form(requestId(c.req.url), host(c));
    setCookie(c, `relay_form_${info.id}`, info.csrf, { httpOnly: true, secure: true, sameSite: 'Strict', path: '/login' });
    const data = JSON.stringify(info).replace(/</g, '\\u003c');
    return c.html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escape(info.label)} login</title><link rel="stylesheet" href="/assets/form.css"></head><body><h1>${escape(info.label)}</h1><p>Credentials for <strong>${escape(info.targetOrigin)}</strong></p><p>The waiting local client receives encrypted credentials. Submit only if you requested this login.</p><form id="login-form"><label>ID<input name="username" autocomplete="username" maxlength="512" required></label><label>Password<input name="password" type="password" autocomplete="current-password" maxlength="4096" required></label><button type="submit">Send securely</button><small id="status" role="status"></small></form><script type="application/json" id="relay-config">${data}</script><script src="/assets/form.js" defer></script></body></html>`);
  });
  app.post('/login', async c => {
    if (c.req.header('content-type') !== 'application/json'
        || (c.req.header('sec-fetch-site') && c.req.header('sec-fetch-site') !== 'same-origin'))
      throw new RelayError('forbidden');
    const id = requestId(c.req.url);
    const result = broker.submit(id, host(c), c.req.header('origin') ?? '',
      getCookie(c, `relay_form_${id}`), parsed(new Uint8Array(await c.req.arrayBuffer())));
    setCookie(c, `relay_form_${id}`, '', { httpOnly: true, secure: true, sameSite: 'Strict', path: '/login', maxAge: 0 });
    return c.json(result);
  });
  app.get('/assets/form.js', c => { c.header('Content-Type', 'text/javascript; charset=utf-8'); return c.body(options.formScript); });
  app.get('/assets/form.css', c => { c.header('Content-Type', 'text/css; charset=utf-8'); return c.body(CSS); });
  app.notFound(c => c.json({ error: 'not_found' }, 404));
  return { app, broker, shutdown: () => { stopped = true; broker.shutdown(); } };
}
