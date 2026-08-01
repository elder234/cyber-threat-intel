import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';

const listQuery = z.object({
  status: z.enum(['open','acknowledged','resolved','suppressed']).optional(),
  severity: z.enum(['info','low','medium','high','critical']).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export default async function alertRoutes(app: FastifyInstance): Promise<void> {
  app.get('/', { preHandler: [app.requirePerms('alert:read')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const parsed = listQuery.safeParse(req.query);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request' });
      const { status, severity, limit, offset } = parsed.data;
      const where: string[] = [];
      const params: unknown[] = [];
      if (status) { params.push(status); where.push(`status = $${params.length}`); }
      if (severity) { params.push(severity); where.push(`severity = $${params.length}`); }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      params.push(limit, offset);
      const { rows } = await pool.query(
        `SELECT id, title, severity, status, source, body AS summary,
                created_at, acknowledged_at, resolved_at
           FROM aegis.alerts ${whereSql} ORDER BY created_at DESC
          LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
      return { data: rows, pagination: { limit, offset } };
    });

  app.post('/:id/ack', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query(
        `UPDATE aegis.alerts SET status='acknowledged', acknowledged_by=$2, acknowledged_at=now()
          WHERE id=$1 AND status='open'`, [id, req.user.sub]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found_or_not_open' });
      await audit(req, { action: 'alert.ack', resource: 'alert', resourceId: id });
      return { ok: true };
    });

  app.post('/:id/resolve', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query(
        `UPDATE aegis.alerts SET status='resolved', resolved_at=now() WHERE id=$1`, [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'alert.resolve', resource: 'alert', resourceId: id });
      return { ok: true };
    });
}
