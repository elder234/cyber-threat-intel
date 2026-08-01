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

  /**
   * GET /api/health/ready — readiness: dependencies reachable. Public route, so
   * it returns only a bare status + HTTP code; driver errors and latencies are
   * logged server-side rather than leaked to unauthenticated callers (P4).
   */
  app.get('/health/ready', { schema: { tags: ['system'] } }, async (req, reply) => {
    const detail: Record<string, { ok: boolean; latencyMs?: number; error?: string }> = {};

    for (const [name, probe] of [
      ['postgres', async () => { await pool.query('SELECT 1'); }],
      ['redis', async () => { await redis.ping(); }],
    ] as const) {
      const t0 = Date.now();
      try {
        await probe();
        detail[name] = { ok: true, latencyMs: Date.now() - t0 };
      } catch (err) {
        detail[name] = { ok: false, error: (err as Error).message };
      }
    }
    const healthy = Object.values(detail).every((c) => c.ok);
    if (!healthy) req.log.warn({ deps: detail }, 'readiness degraded');
    return reply.code(healthy ? 200 : 503).send({ status: healthy ? 'ready' : 'degraded' });
  });
}
