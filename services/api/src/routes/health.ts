import type { FastifyInstance } from 'fastify';
import { pool } from '../db/pool.js';
import { redis } from '../lib/redis.js';

/** Liveness/readiness + system health for the dashboard "System Health" widget. */
export default async function healthRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/health — liveness (no auth) */
  app.get('/health', { schema: { tags: ['system'], summary: 'Liveness probe' } }, async () => ({
    status: 'ok',
    service: 'aegis-api',
    ts: new Date().toISOString(),
  }));

  /** GET /api/health/ready — readiness: dependencies reachable */
  app.get('/health/ready', { schema: { tags: ['system'] } }, async (_req, reply) => {
    const checks: Record<string, { ok: boolean; latencyMs?: number; error?: string }> = {};

    for (const [name, probe] of [
      ['postgres', async () => { await pool.query('SELECT 1'); }],
      ['redis', async () => { await redis.ping(); }],
    ] as const) {
      const t0 = Date.now();
      try {
        await probe();
        checks[name] = { ok: true, latencyMs: Date.now() - t0 };
      } catch (err) {
        checks[name] = { ok: false, error: (err as Error).message };
      }
    }
    const healthy = Object.values(checks).every((c) => c.ok);
    return reply.code(healthy ? 200 : 503).send({ status: healthy ? 'ready' : 'degraded', checks });
  });
}
