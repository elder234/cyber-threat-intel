import type { FastifyInstance } from 'fastify';
import type { WebSocket } from 'ws';
import fastifyWebsocket from '@fastify/websocket';
import { redisSub } from '../lib/redis.js';

/**
 * Module 16 (real-time) — WebSocket hub. Clients connect to /ws and must send a
 * first message `{"type":"auth","token":"<accessToken>"}` before receiving any
 * events — the token is never carried in the URL or handshake headers, so it
 * cannot leak into proxy/access logs. Events are fanned out from the Redis
 * "events" channel and filtered per client by the caller's permissions.
 */

// Which permission a client needs to receive a given event type. Events without
// an entry are broadcast to every authenticated client.
const EVENT_PERM: Record<string, string> = {
  'ioc.new': 'ioc:read',
  'alert.new': 'alert:read',
};

const AUTH_TIMEOUT_MS = 10_000;

interface Client {
  ws: WebSocket;
  perms: Set<string>;
}

export default async function registerWs(app: FastifyInstance): Promise<void> {
  await app.register(fastifyWebsocket);

  const clients = new Set<Client>();

  // Subscribe once to the Redis events channel and broadcast to all clients.
  await redisSub.connect().catch(() => undefined);
  await redisSub.subscribe('events');
  redisSub.on('message', (_channel, message) => {
    let required: string | undefined;
    try {
      const { type } = JSON.parse(message) as { type?: string };
      required = type ? EVENT_PERM[type] : undefined;
    } catch {
      required = undefined;
    }
    for (const c of clients) {
      if (c.ws.readyState !== c.ws.OPEN) continue;
      if (required && !c.perms.has(required)) continue;
      c.ws.send(message);
    }
  });

  app.get('/ws', { websocket: true }, (socket) => {
    let authed = false;
    let perms = new Set<string>();
    let client: Client | undefined;

    const rejectAndClose = (message: string): void => {
      socket.send(JSON.stringify({ type: 'error', message }));
      socket.close();
    };

    const authTimer = setTimeout(() => {
      if (!authed) rejectAndClose('auth timeout');
    }, AUTH_TIMEOUT_MS);

    socket.on('message', (data) => {
      if (authed) return;

      let msg: { type?: string; token?: unknown };
      try {
        msg = JSON.parse(data.toString()) as { type?: string; token?: unknown };
      } catch {
        rejectAndClose('malformed auth');
        return;
      }
      if (msg.type !== 'auth' || typeof msg.token !== 'string') {
        rejectAndClose('missing token');
        return;
      }

      try {
        const claims = app.jwt.verify(msg.token) as { sub: string; perms?: string[] };
        authed = true;
        perms = new Set(claims.perms ?? []);
        client = { ws: socket, perms };
        clients.add(client);
        clearTimeout(authTimer);
        socket.send(JSON.stringify({ type: 'hello', ts: Date.now() }));
      } catch {
        rejectAndClose('invalid token');
      }
    });

    socket.on('close', () => { if (client) clients.delete(client); });
    socket.on('error', () => { if (client) clients.delete(client); });
  });
}
