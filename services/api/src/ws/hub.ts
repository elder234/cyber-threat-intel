import type { FastifyInstance } from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import { redisSub } from '../lib/redis.js';

/**
 * Module 16 (real-time) — WebSocket hub. Clients connect to /ws with a valid
 * access token (?token=… or Authorization header). The API publishes domain
 * events to the Redis "events" channel; this hub fans them out to sockets.
 */
export default async function registerWs(app: FastifyInstance): Promise<void> {
  await app.register(fastifyWebsocket);

  const clients = new Set<import('ws').WebSocket>();

  // Subscribe once to the Redis events channel and broadcast to all clients.
  await redisSub.connect().catch(() => undefined);
  await redisSub.subscribe('events');
  redisSub.on('message', (_channel, message) => {
    for (const ws of clients) {
      if (ws.readyState === ws.OPEN) ws.send(message);
    }
  });

  app.get('/ws', { websocket: true }, (conn, req) => {
    // Authenticate: token via query string or Authorization header.
    const token =
      (req.query as { token?: string }).token ??
      (req.headers.authorization?.replace(/^Bearer\s+/i, ''));
    if (!token) {
      conn.socket.send(JSON.stringify({ type: 'error', message: 'missing token' }));
      conn.socket.close();
      return;
    }
    try {
      app.jwt.verify(token);
    } catch {
      conn.socket.send(JSON.stringify({ type: 'error', message: 'invalid token' }));
      conn.socket.close();
      return;
    }

    clients.add(conn.socket);
    conn.socket.send(JSON.stringify({ type: 'hello', ts: Date.now() }));

    conn.socket.on('close', () => clients.delete(conn.socket));
    conn.socket.on('error', () => clients.delete(conn.socket));
  });
}
