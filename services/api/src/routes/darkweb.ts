import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';

/**
 * Feature F-DARKWEB — dark-web monitor API.
 *
 * The Tor-routed collector (aegis-collectors::darkweb) writes rows into
 * `aegis.darkweb_hits`; this route surfaces them, manages the watchlist, and
 * raises an alert (via aegis.raise_alert) for any hit that hasn't been alerted
 * yet — so dark-web exposure reaches the live feed and notification channels
 * through the same engine as every other alert (Module 11).
 *
 * Permissions:
 *   - watchlist:write  → mutate the watchlist (admin, analyst)
 *   - darkweb:read     → read sources + hits (admin, analyst, viewer)
 */

const WATCH_KINDS = ['domain', 'email', 'keyword', 'brand', 'bin'] as const;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
const HIT_STATUS = ['new', 'reviewed', 'false_positive', 'actioned'] as const;

const createWatch = z.object({
  kind: z.enum(WATCH_KINDS),
  value: z.string().min(1).max(255),
  label: z.string().max(120).optional(),
  severity: z.enum(SEVERITIES).default('high'),
  enabled: z.boolean().default(true),
});
const updateWatch = createWatch.partial();

export default async function darkwebRoutes(app: FastifyInstance): Promise<void> {
  // ── Watchlist CRUD ─────────────────────────────────────────────────────────
  app.get('/watchlist', { preHandler: [app.requirePerms('darkweb:read')], schema: { tags: ['darkweb'] } },
    async () => {
      const { rows } = await pool.query(
        `SELECT id, kind, value, label, severity, enabled, created_at, updated_at
           FROM aegis.watchlist ORDER BY created_at DESC`);
      return { data: rows };
    });

  app.post('/watchlist', { preHandler: [app.requirePerms('watchlist:write')], schema: { tags: ['darkweb'] } },
    async (req, reply) => {
      const parsed = createWatch.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;
      try {
        const { rows } = await pool.query(
          `INSERT INTO aegis.watchlist (kind, value, label, severity, enabled, created_by)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
          [b.kind, b.value, b.label ?? null, b.severity, b.enabled, req.user.sub]);
        await audit(req, { action: 'watchlist.create', resource: 'watchlist', resourceId: rows[0].id });
        return reply.code(201).send(rows[0]);
      } catch (e) {
        if ((e as { code?: string }).code === '23505') {
          return reply.code(409).send({ error: 'duplicate', message: 'That kind+value is already watched.' });
        }
        throw e;
      }
    });

  app.patch('/watchlist/:id', { preHandler: [app.requirePerms('watchlist:write')], schema: { tags: ['darkweb'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const parsed = updateWatch.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;
      const sets: string[] = [];
      const params: unknown[] = [];
      const set = (col: string, val: unknown) => { params.push(val); sets.push(`${col} = $${params.length}`); };
      if (b.kind !== undefined) set('kind', b.kind);
      if (b.value !== undefined) set('value', b.value);
      if (b.label !== undefined) set('label', b.label);
      if (b.severity !== undefined) set('severity', b.severity);
      if (b.enabled !== undefined) set('enabled', b.enabled);
      if (!sets.length) return reply.code(400).send({ error: 'no_fields' });
      params.push(id);
      const { rows } = await pool.query(
        `UPDATE aegis.watchlist SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING *`, params);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'watchlist.update', resource: 'watchlist', resourceId: id });
      return rows[0];
    });

  app.delete('/watchlist/:id', { preHandler: [app.requirePerms('watchlist:write')], schema: { tags: ['darkweb'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query('DELETE FROM aegis.watchlist WHERE id = $1', [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'watchlist.delete', resource: 'watchlist', resourceId: id });
      return reply.code(204).send();
    });

  // ── Sources (read-only) ──────────────────────────────────────────────────────
  app.get('/sources', { preHandler: [app.requirePerms('darkweb:read')], schema: { tags: ['darkweb'] } },
    async () => {
      const { rows } = await pool.query(
        `SELECT id, name, kind, is_onion, enabled, poll_interval_secs, last_polled_at, health
           FROM aegis.darkweb_sources ORDER BY name`);
      // onion_url intentionally omitted from the list view — operators manage it
      // out-of-band; it is not needed by the console and shouldn't be broadcast.
      return { data: rows };
    });

  // ── Hits ─────────────────────────────────────────────────────────────────────
  /** GET /api/darkweb/hits — list recent hits, raising alerts for un-alerted ones. */
  app.get('/hits', { preHandler: [app.requirePerms('darkweb:read')], schema: { tags: ['darkweb'] } },
    async (req) => {
      const limit = Math.min(Number((req.query as { limit?: number })?.limit ?? 100), 500);
      await raiseAlertsForNewHits();
      const { rows } = await pool.query(
        `SELECT h.id, h.source_id, s.name AS source_name, h.watchlist_id, h.url,
                h.matched_value, h.snippet, h.severity, h.observed_at, h.alert_id, h.status
           FROM aegis.darkweb_hits h
           JOIN aegis.darkweb_sources s ON s.id = h.source_id
          ORDER BY h.observed_at DESC
          LIMIT $1`, [limit]);
      return { data: rows };
    });

  /** PATCH /api/darkweb/hits/:id — triage a hit (status). */
  app.patch('/hits/:id', { preHandler: [app.requirePerms('darkweb:read')], schema: { tags: ['darkweb'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const status = (req.body as { status?: string })?.status;
      if (!status || !HIT_STATUS.includes(status as typeof HIT_STATUS[number])) {
        return reply.code(400).send({ error: 'bad_request', message: `status must be one of ${HIT_STATUS.join(', ')}` });
      }
      const { rows } = await pool.query(
        'UPDATE aegis.darkweb_hits SET status = $2 WHERE id = $1 RETURNING id, status', [id, status]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'darkweb_hit.triage', resource: 'darkweb_hit', resourceId: id, metadata: { status } });
      return rows[0];
    });
}

/**
 * Raise an alert (dedupe-aware) for every darkweb_hit that doesn't yet have one,
 * and link it back via `alert_id`. Uses the shared aegis.raise_alert() so the
 * hit surfaces through the standard engine, live feed, and channels.
 */
async function raiseAlertsForNewHits(): Promise<void> {
  const { rows: pending } = await pool.query(
    `SELECT h.id, h.url, h.matched_value, h.severity, s.name AS source_name
       FROM aegis.darkweb_hits h
       JOIN aegis.darkweb_sources s ON s.id = h.source_id
      WHERE h.alert_id IS NULL
      LIMIT 200`);
  for (const h of pending) {
    const dedupe = `darkweb:${h.matched_value}:${h.url}`;
    const { rows } = await pool.query(
      `SELECT id, is_new FROM aegis.raise_alert(
         NULL, $1, $2, $3::aegis.severity, 'darkweb', 'darkweb_hit', $4, $5, $6::jsonb)`,
      [
        `Dark-web exposure: ${h.matched_value}`,
        `Watchlisted value "${h.matched_value}" was observed on ${h.source_name}.`,
        h.severity,
        h.id,
        dedupe,
        JSON.stringify({ source: h.source_name, url: h.url, matched_value: h.matched_value }),
      ]);
    if (rows[0]?.id) {
      await pool.query('UPDATE aegis.darkweb_hits SET alert_id = $2 WHERE id = $1', [h.id, rows[0].id]);
    }
  }
}
