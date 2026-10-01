import { readFileSync } from 'node:fs';
import { serve } from '@hono/node-server';
import { configFromValues } from './config.js';
import { createApp } from './app.js';

try {
  const path = process.env.CLIENT_TRUST_FILE;
  if (!path || !path.startsWith('/')) throw new Error('configuration');
  const config = configFromValues(process.env.PUBLIC_BASE_DOMAIN ?? '', process.env.API_HOST ?? '',
    JSON.parse(readFileSync(path, 'utf8')));
  const port = Number(process.env.PORT ?? '3000');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('configuration');
  const relay = createApp(config, { formScript: readFileSync(new URL('./public/form.js', import.meta.url), 'utf8') });
  const server = serve({ fetch: relay.app.fetch, port, hostname: '0.0.0.0' });
  const sweep = setInterval(() => relay.broker.sweep(), 10_000); sweep.unref();
  let stopping = false;
  const stop = () => {
    if (stopping) return; stopping = true;
    clearInterval(sweep); relay.shutdown();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
} catch {
  process.stderr.write('configuration\n'); process.exit(1);
}
