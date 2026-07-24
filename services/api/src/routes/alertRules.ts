import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';

/**
 * Module 11 — alert rule management. Rules bind an event type + conditions to a
 * severity and a set of notification channels. The AlertEngine evaluates enabled
 * rules against the Redis `events` stream.
 */

const EVENT_TYPES = ['ioc.new', 'cve.kev', 'cve.new', 'scan.finding', 'feed.error'] as const;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

const conditions = z.object({
  min_severity: z.enum(SEVERITIES).optional(),
  tags_any: z.array(z.string()).max(50).optional(),
  tags_all: z.array(z.string()).max(50).optional(),
  sources: z.array(z.string()).max(50).optional(),
  value_regex: z.string().max(500).optional(),
}).strict();

const createBody = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(1000).default(''),
  enabled: z.boolean().default(true),
  event_type: z.enum(EVENT_TYPES),
  conditions: conditions.default({}),
  severity: z.enum(SEVERITIES).default('medium'),
  channels: z.array(z.string().max(64)).max(20).default([]),
  throttle_secs: z.number().int().min(0).max(86_400).default(0),
});
const updateBody = createBody.partial();

export default async function alertRuleRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/alert-rules — list */
  app.get('/', { preHandler: [app.requirePerms('alert:read')], schema: { tags: ['alerts'] } },
    async () => {
      const { rows } = await pool.query(
        `SELECT id, name, description, enabled, event_type, conditions, severity,
                channels, throttle_secs, created_at, updated_at
           FROM aegis.alert_rules ORDER BY created_at DESC`);
      return { data: rows };
    });

  /** POST /api/alert-rules — create */
  app.post('/', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const parsed = createBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;
      const missing = await unknownChannels(b.channels);
      if (missing.length) return reply.code(400).send({ error: 'unknown_channels', missing });
      const { rows } = await pool.query(
        `INSERT INTO aegis.alert_rules
           (name, description, enabled, event_type, conditions, severity, channels, throttle_secs, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [b.name, b.description, b.enabled, b.event_type, JSON.stringify(b.conditions),
         b.severity, b.channels, b.throttle_secs, req.user.sub]);
      await audit(req, { action: 'alert_rule.create', resource: 'alert_rule', resourceId: rows[0].id });
      return reply.code(201).send(rows[0]);
    });

  /** PATCH /api/alert-rules/:id — update */
  app.patch('/:id', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const parsed = updateBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;
      if (b.channels) {
        const missing = await unknownChannels(b.channels);
        if (missing.length) return reply.code(400).send({ error: 'unknown_channels', missing });
      }

      const sets: string[] = [];
      const params: unknown[] = [];
      const set = (col: string, val: unknown) => { params.push(val); sets.push(`${col} = $${params.length}`); };
      if (b.name !== undefined) set('name', b.name);
      if (b.description !== undefined) set('description', b.description);
      if (b.enabled !== undefined) set('enabled', b.enabled);
      if (b.event_type !== undefined) set('event_type', b.event_type);
      if (b.conditions !== undefined) set('conditions', JSON.stringify(b.conditions));
      if (b.severity !== undefined) set('severity', b.severity);
      if (b.channels !== undefined) set('channels', b.channels);
      if (b.throttle_secs !== undefined) set('throttle_secs', b.throttle_secs);
      if (!sets.length) return reply.code(400).send({ error: 'no_fields' });

      params.push(id);
      const { rows } = await pool.query(
        `UPDATE aegis.alert_rules SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING *`, params);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'alert_rule.update', resource: 'alert_rule', resourceId: id });
      return rows[0];
    });

  /** DELETE /api/alert-rules/:id */
  app.delete('/:id', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query('DELETE FROM aegis.alert_rules WHERE id = $1', [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'alert_rule.delete', resource: 'alert_rule', resourceId: id });
      return reply.code(204).send();
    });
}

/** Return the subset of `channels` that do not exist as notification channels. */
async function unknownChannels(channels: string[]): Promise<string[]> {
  if (!channels.length) return [];
  const { rows } = await pool.query(
    'SELECT name FROM aegis.notification_channels WHERE name = ANY($1)', [channels]);
  const known = new Set(rows.map((r) => r.name));
  return channels.filter((c) => !known.has(c));
}
