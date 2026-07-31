import type { FastifyInstance } from 'fastify';
import type { WebSocket } from 'ws';
import fastifyWebsocket from '@fastify/websocket';
import { redisSub } from '../lib/redis.js';

/**
 * Module 16 (real-time) — WebSocket hub. Clients connect to /ws with a valid
 * access token (?token=… or Authorization header). The API publishes domain
 * events to the Redis "events" channel; this hub fans them out to sockets.
 */
export default async function registerWs(app: FastifyInstance): Promise<void> {
  await app.register(fastifyWebsocket);

  const clients = new Set<WebSocket>();

  // Subscribe once to the Redis events channel and broadcast to all clients.
  await redisSub.connect().catch(() => undefined);
  await redisSub.subscribe('events');
  redisSub.on('message', (_channel, message) => {
    for (const ws of clients) {
      if (ws.readyState === ws.OPEN) ws.send(message);
    }
  });

  app.get('/ws', { websocket: true }, (socket, req) => {
    // Authenticate: token via query string or Authorization header.
    const token =
      (req.query as { token?: string }).token ??
      (req.headers.authorization?.replace(/^Bearer\s+/i, ''));
    if (!token) {
      socket.send(JSON.stringify({ type: 'error', message: 'missing token' }));
      socket.close();
      return;
    }
    try {
      app.jwt.verify(token);
    } catch {
      socket.send(JSON.stringify({ type: 'error', message: 'invalid token' }));
      socket.close();
      return;
    }

    clients.add(socket);
    socket.send(JSON.stringify({ type: 'hello', ts: Date.now() }));

    socket.on('close', () => clients.delete(socket));
    socket.on('error', () => clients.delete(socket));
  });
}
