import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';
import { validateRule } from '../lib/ruleValidate.js';

/**
 * Module 2 — YARA / Sigma detection-rule management.
 *
 * Rules are stored in `aegis.detection_rules`. On create/update we run a
 * structural validator (see lib/ruleValidate) and persist the result in
 * `is_valid` / `validation_error`; an invalid rule is still stored (so the
 * author can fix it) but flagged. ATT&CK technique ids parsed from the rule
 * are merged into `technique_ids`.
 */

const FORMATS = ['yara', 'sigma'] as const;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
const STATUSES = ['stable', 'test', 'experimental', 'deprecated'] as const;

const createBody = z.object({
  format: z.enum(FORMATS),
  name: z.string().min(1).max(256).optional(),
  content: z.string().min(1).max(200_000),
  description: z.string().max(4096).optional(),
  author: z.string().max(128).optional(),
  severity: z.enum(SEVERITIES).default('medium'),
  status: z.enum(STATUSES).default('experimental'),
  tags: z.array(z.string().max(64)).max(50).default([]),
  technique_ids: z.array(z.string().max(16)).max(50).default([]),
  is_enabled: z.boolean().default(true),
});

const updateBody = createBody.partial().omit({ format: true });

const listQuery = z.object({
  format: z.enum(FORMATS).optional(),
  status: z.enum(STATUSES).optional(),
  enabled: z.coerce.boolean().optional(),
  valid: z.coerce.boolean().optional(),
  q: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const uniq = (xs: string[]): string[] => [...new Set(xs)].sort();

export default async function ruleRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/rules — filtered, paginated list */
  app.get('/', { preHandler: [app.requirePerms('rule:read')], schema: { tags: ['rules'] } },
    async (req, reply) => {
      const parsed = listQuery.safeParse(req.query);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const { format, status, enabled, valid, q, limit, offset } = parsed.data;

      const where: string[] = [];
      const params: unknown[] = [];
      const add = (clause: string, val: unknown) => { params.push(val); where.push(clause.replace('?', `$${params.length}`)); };
      if (format) add('format = ?', format);
      if (status) add('status = ?', status);
      if (enabled !== undefined) add('is_enabled = ?', enabled);
      if (valid !== undefined) add('is_valid = ?', valid);
      if (q) {
        params.push(`%${q}%`);
        const p = `$${params.length}`;
        where.push(`(name ILIKE ${p} OR description ILIKE ${p})`);
      }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      params.push(limit, offset);
      const { rows } = await pool.query(
        `SELECT id, format, name, rule_id_ext, description, author, severity, status,
                tags, technique_ids, is_enabled, is_valid, validation_error,
                created_at, updated_at
           FROM aegis.detection_rules ${whereSql}
          ORDER BY updated_at DESC
          LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      const { rows: [{ count }] } = await pool.query(
        `SELECT count(*)::int AS count FROM aegis.detection_rules ${whereSql}`, params.slice(0, -2),
      );
      return { data: rows, pagination: { total: count, limit, offset } };
    });

  /** GET /api/rules/:id — full rule including raw content */
  app.get('/:id', { preHandler: [app.requirePerms('rule:read')], schema: { tags: ['rules'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query(
        `SELECT id, format, name, rule_id_ext, content, description, author, severity, status,
                tags, technique_ids, is_enabled, is_valid, validation_error, created_at, updated_at
           FROM aegis.detection_rules WHERE id = $1`, [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      return rows[0];
    });

  /** POST /api/rules/validate — dry-run validation without persisting */
  app.post('/validate', { preHandler: [app.requirePerms('rule:read')], schema: { tags: ['rules'] } },
    async (req, reply) => {
      const schema = z.object({ format: z.enum(FORMATS), content: z.string().min(1).max(200_000) });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      return validateRule(parsed.data.format, parsed.data.content);
    });

  /** POST /api/rules — create (validates; stores result) */
  app.post('/', { preHandler: [app.requirePerms('rule:write')], schema: { tags: ['rules'] } },
    async (req, reply) => {
      const parsed = createBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;

      const v = validateRule(b.format, b.content);
      const name = b.name ?? v.name;
      if (!name) return reply.code(400).send({ error: 'bad_request', message: 'name required (none found in rule)' });
      const techniques = uniq([...b.technique_ids, ...v.techniqueIds]);

      try {
        const { rows } = await pool.query(
          `INSERT INTO aegis.detection_rules
             (format, name, rule_id_ext, content, description, author, severity, status,
              tags, technique_ids, is_enabled, is_valid, validation_error, created_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text[],$10::text[],$11,$12,$13,$14)
           RETURNING *`,
          [b.format, name, v.ruleIdExt ?? null, b.content, b.description ?? '', b.author ?? null,
            b.severity, b.status, b.tags, techniques, b.is_enabled, v.valid, v.error ?? null, req.user.sub],
        );
        await audit(req, { action: 'rule.create', resource: 'rule', resourceId: rows[0].id, metadata: { format: b.format, valid: v.valid } });
        return reply.code(201).send(rows[0]);
      } catch (err) {
        if ((err as { code?: string }).code === '23505') {
          return reply.code(409).send({ error: 'conflict', message: 'a rule with this format+name already exists' });
        }
        throw err;
      }
    });

  /** PATCH /api/rules/:id — update; re-validates when content/format changes */
  app.patch('/:id', { preHandler: [app.requirePerms('rule:write')], schema: { tags: ['rules'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const parsed = updateBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;

      const { rows: existing } = await pool.query(
        'SELECT format, content FROM aegis.detection_rules WHERE id = $1', [id]);
      if (!existing.length) return reply.code(404).send({ error: 'not_found' });

      // Re-validate against the effective (post-update) content + format.
      const format = existing[0].format as 'yara' | 'sigma';
      const content = b.content ?? existing[0].content;
      const v = validateRule(format, content);

      const sets: string[] = [];
      const params: unknown[] = [];
      const set = (col: string, val: unknown) => { params.push(val); sets.push(`${col} = $${params.length}`); };
      if (b.name !== undefined) set('name', b.name);
      if (b.content !== undefined) set('content', b.content);
      if (b.description !== undefined) set('description', b.description);
      if (b.author !== undefined) set('author', b.author);
      if (b.severity !== undefined) set('severity', b.severity);
      if (b.status !== undefined) set('status', b.status);
      if (b.tags !== undefined) set('tags', b.tags);
      if (b.technique_ids !== undefined) set('technique_ids', uniq([...b.technique_ids, ...v.techniqueIds]));
      if (b.is_enabled !== undefined) set('is_enabled', b.is_enabled);
      // Always refresh validation + parsed external id.
      set('is_valid', v.valid);
      set('validation_error', v.error ?? null);
      if (v.ruleIdExt) set('rule_id_ext', v.ruleIdExt);

      params.push(id);
      const { rows } = await pool.query(
        `UPDATE aegis.detection_rules SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING *`,
        params,
      );
      await audit(req, { action: 'rule.update', resource: 'rule', resourceId: id, metadata: { valid: v.valid } });
      return rows[0];
    });

  /** DELETE /api/rules/:id */
  app.delete('/:id', { preHandler: [app.requirePerms('rule:write')], schema: { tags: ['rules'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query('DELETE FROM aegis.detection_rules WHERE id = $1', [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'rule.delete', resource: 'rule', resourceId: id });
      return reply.code(204).send();
    });
}
