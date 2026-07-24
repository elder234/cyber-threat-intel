import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';
import type { AlertMessage } from '../lib/notify/format.js';
import { dispatchToChannels } from '../lib/notify/dispatch.js';

/**
 * Module 11 — notification channel management. Channels are named delivery
 * destinations (Slack/Discord/Telegram/webhook/email) referenced by
 * alert_rules.channels. Secret-bearing config is never returned in list/get.
 */

const CHANNEL_TYPES = ['email', 'slack', 'discord', 'telegram', 'webhook'] as const;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

const createBody = z.object({
  name: z.string().min(1).max(64),
  type: z.enum(CHANNEL_TYPES),
  enabled: z.boolean().default(true),
  config: z.record(z.unknown()).default({}),
  min_severity: z.enum(SEVERITIES).default('low'),
});
const updateBody = createBody.partial().omit({ type: true });

// Fields safe to reveal. `config` may hold secrets, so we return a redacted view.
const PUBLIC_COLS = 'id, name, type, enabled, min_severity, last_ok_at, last_error, created_at, updated_at';

/** Redact secret-ish keys from a channel config before returning it. */
function redactConfig(type: string, config: Record<string, unknown>): Record<string, unknown> {
  const SECRET_KEYS = new Set(['bot_token', 'secret', 'password', 'pass', 'token']);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config ?? {})) {
    out[k] = SECRET_KEYS.has(k) && typeof v === 'string' && v.length ? '••••••' : v;
  }
  return out;
}

export default async function channelRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/channels — list (config redacted) */
  app.get('/', { preHandler: [app.requirePerms('alert:read')], schema: { tags: ['alerts'] } },
    async () => {
      const { rows } = await pool.query(
        `SELECT ${PUBLIC_COLS}, config FROM aegis.notification_channels ORDER BY name`);
      return { data: rows.map((r) => ({ ...r, config: redactConfig(r.type, r.config) })) };
    });

  /** POST /api/channels — create */
  app.post('/', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const parsed = createBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;
      try {
        const { rows } = await pool.query(
          `INSERT INTO aegis.notification_channels(name, type, enabled, config, min_severity, created_by)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING ${PUBLIC_COLS}`,
          [b.name, b.type, b.enabled, JSON.stringify(b.config), b.min_severity, req.user.sub]);
        await audit(req, { action: 'channel.create', resource: 'channel', resourceId: rows[0].id, metadata: { type: b.type } });
        return reply.code(201).send(rows[0]);
      } catch (err) {
        if ((err as { code?: string }).code === '23505') return reply.code(409).send({ error: 'name_taken' });
        throw err;
      }
    });

  /** PATCH /api/channels/:id — update */
  app.patch('/:id', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const parsed = updateBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;

      const sets: string[] = [];
      const params: unknown[] = [];
      const set = (col: string, val: unknown) => { params.push(val); sets.push(`${col} = $${params.length}`); };
      if (b.name !== undefined) set('name', b.name);
      if (b.enabled !== undefined) set('enabled', b.enabled);
      if (b.config !== undefined) set('config', JSON.stringify(b.config));
      if (b.min_severity !== undefined) set('min_severity', b.min_severity);
      if (!sets.length) return reply.code(400).send({ error: 'no_fields' });

      params.push(id);
      const { rows } = await pool.query(
        `UPDATE aegis.notification_channels SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING ${PUBLIC_COLS}`, params);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'channel.update', resource: 'channel', resourceId: id });
      return rows[0];
    });

  /** DELETE /api/channels/:id */
  app.delete('/:id', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query('DELETE FROM aegis.notification_channels WHERE id = $1', [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'channel.delete', resource: 'channel', resourceId: id });
      return reply.code(204).send();
    });

  /** POST /api/channels/:id/test — send a synthetic alert through this channel */
  app.post('/:id/test', { preHandler: [app.requirePerms('alert:manage')], schema: { tags: ['alerts'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query('SELECT name FROM aegis.notification_channels WHERE id = $1', [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });

      const msg: AlertMessage = {
        id: '00000000-0000-0000-0000-000000000000',
        title: 'Aegis test alert',
        body: `Test notification requested by ${req.user.email}.`,
        severity: 'info',
        source: 'channel-test',
        createdAt: new Date().toISOString(),
      };
      const [outcome] = await dispatchToChannels(pool, null, msg, [rows[0].name]);
      await audit(req, { action: 'channel.test', resource: 'channel', resourceId: id });
      return { ...(outcome ?? { channel: rows[0].name, ok: false, error: 'channel disabled' }) };
    });
}
