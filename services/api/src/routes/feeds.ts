import type { FastifyInstance } from 'fastify';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';

/** Module 10 — feed management + manual trigger (enqueues a Rust collector job). */
export default async function feedRoutes(app: FastifyInstance): Promise<void> {
  app.get('/', { preHandler: [app.requirePerms('feed:read')], schema: { tags: ['feeds'] } },
    async () => {
      const { rows } = await pool.query(
        `SELECT id, name, provider, format, enabled, interval_secs, last_run_at,
                last_status, last_item_count FROM aegis.feeds ORDER BY name`);
      return { data: rows };
    });

  app.get('/:id/runs', { preHandler: [app.requirePerms('feed:read')], schema: { tags: ['feeds'] } },
    async (req) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query(
        `SELECT status, items_new, items_updated, error, started_at, finished_at
           FROM aegis.feed_runs WHERE feed_id = $1 ORDER BY started_at DESC LIMIT 50`, [id]);
      return { data: rows };
    });

  /** POST /api/feeds/:id/sync — enqueue an immediate pull for a Rust collector */
  app.post('/:id/sync', { preHandler: [app.requirePerms('feed:manage')], schema: { tags: ['feeds'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query('SELECT provider FROM aegis.feeds WHERE id = $1', [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      const { rows: job } = await pool.query(
        `SELECT aegis.enqueue_job('feed.pull', $1::jsonb, 'collectors', 1) AS id`,
        [JSON.stringify({ feed_id: id, provider: rows[0].provider })]);
      await audit(req, { action: 'feed.sync', resource: 'feed', resourceId: id });
      return reply.code(202).send({ enqueued: true, jobId: job[0].id });
    });
}
