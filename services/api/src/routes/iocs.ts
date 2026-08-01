import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';
import { publish } from '../lib/redis.js';

const IOC_TYPES = [
  'ipv4','ipv6','domain','url','md5','sha1','sha256','sha512',
  'email','cidr','asn','file_path','registry_key','mutex','user_agent','ja3',
] as const;
const SEVERITIES = ['info','low','medium','high','critical'] as const;
const CONFIDENCES = ['low','medium','high','confirmed'] as const;

const createBody = z.object({
  type: z.enum(IOC_TYPES),
  value: z.string().min(1).max(2048),
  severity: z.enum(SEVERITIES).default('medium'),
  confidence: z.enum(CONFIDENCES).default('medium'),
  description: z.string().max(4096).optional(),
  source: z.string().max(128).default('manual'),
  tags: z.array(z.string().max(64)).max(50).default([]),
  tlp: z.enum(['clear','green','amber','amber_strict','red']).default('amber'),
});

const listQuery = z.object({
  type: z.enum(IOC_TYPES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  source: z.string().optional(),
  q: z.string().optional(),
  active: z.coerce.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export default async function iocRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/iocs — filtered, paginated list */
  app.get('/', { preHandler: [app.requirePerms('ioc:read')], schema: { tags: ['iocs'] } },
    async (req, reply) => {
      const parsed = listQuery.safeParse(req.query);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const { type, severity, source, q, active, limit, offset } = parsed.data;

      const where: string[] = [];
      const params: unknown[] = [];
      const add = (clause: string, val: unknown) => { params.push(val); where.push(clause.replace('?', `$${params.length}`)); };
      if (type) add('type = ?', type);
      if (severity) add('severity = ?', severity);
      if (source) add('source = ?', source);
      if (active !== undefined) add('is_active = ?', active);
      if (q) add('value_norm ILIKE ?', `%${q.toLowerCase()}%`);
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      params.push(limit, offset);
      const { rows } = await pool.query(
        `SELECT id, type, value, severity, confidence, tlp, score, is_active, tags, source,
                first_seen, last_seen, expires_at
           FROM aegis.iocs ${whereSql}
          ORDER BY last_seen DESC
          LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      const { rows: [{ count }] } = await pool.query(
        `SELECT count(*)::int AS count FROM aegis.iocs ${whereSql}`, params.slice(0, -2),
      );
      return { data: rows, pagination: { total: count, limit, offset } };
    });

  /** GET /api/iocs/:id — single IOC with sightings */
  app.get('/:id', { preHandler: [app.requirePerms('ioc:read')], schema: { tags: ['iocs'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query(
        `SELECT id, type, value, severity, confidence, tlp, score, is_active, tags, source,
                first_seen, last_seen, expires_at
           FROM aegis.iocs WHERE id = $1`, [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      const { rows: sightings } = await pool.query(
        'SELECT source, context, observed_at FROM aegis.ioc_sightings WHERE ioc_id = $1 ORDER BY observed_at DESC LIMIT 100',
        [id],
      );
      return { ...rows[0], sightings };
    });

  /** POST /api/iocs — create/merge via upsert_ioc() */
  app.post('/', { preHandler: [app.requirePerms('ioc:write')], schema: { tags: ['iocs'] } },
    async (req, reply) => {
      const parsed = createBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;
      const { rows } = await pool.query(
        `SELECT aegis.upsert_ioc($1,$2,$3,$4,$5,$6,$7) AS id`,
        [b.type, b.value, b.severity, b.confidence, b.source, b.tags, b.tlp],
      );
      const id = rows[0].id;
      if (b.description) {
        await pool.query('UPDATE aegis.iocs SET description = $2, created_by = $3 WHERE id = $1',
          [id, b.description, req.user.sub]);
      }
      await audit(req, { action: 'ioc.create', resource: 'ioc', resourceId: id, metadata: { type: b.type } });
      await publish('events', { type: 'ioc.new', id, severity: b.severity, value: b.value });
      const { rows: created } = await pool.query(
        `SELECT id, type, value, severity, confidence, tlp, score, is_active, tags, source,
                first_seen, last_seen, expires_at
           FROM aegis.iocs WHERE id = $1`, [id]);
      return reply.code(201).send(created[0]);
    });

  /** POST /api/iocs/:id/enrich — enqueue an OSINT reputation lookup (Module 3) */
  app.post('/:id/enrich', { preHandler: [app.requirePerms('ioc:write')], schema: { tags: ['iocs'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query('SELECT id FROM aegis.iocs WHERE id = $1', [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      const { rows: job } = await pool.query(
        `SELECT aegis.enqueue_job('ioc.enrich', $1::jsonb, 'default', 5) AS id`,
        [JSON.stringify({ ioc_id: id })]);
      await audit(req, { action: 'ioc.enrich', resource: 'ioc', resourceId: id });
      return reply.code(202).send({ enqueued: true, jobId: job[0].id });
    });

  /** DELETE /api/iocs/:id — soft delete (deactivate) */
  app.delete('/:id', { preHandler: [app.requirePerms('ioc:delete')], schema: { tags: ['iocs'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query('UPDATE aegis.iocs SET is_active = false WHERE id = $1', [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'ioc.delete', resource: 'ioc', resourceId: id });
      return reply.code(204).send();
    });
}
