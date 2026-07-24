import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';

/**
 * Module 6 (API side) — container security audits.
 *
 * An audit stores its raw input (a Dockerfile, an image `config` JSON, or a
 * Trivy `--format json` report) and enqueues a `container.audit` job. The Rust
 * `aegis-container` analyzer runs offline in the worker, persists findings +
 * a risk summary, and flips the audit to completed/failed.
 *
 * All analysis is offline (no daemon, no network). Actually building/pulling
 * images or invoking Trivy is out of scope here.
 *
 * ⚠️ RUNTIME VERIFICATION REQUIRED — enqueue + DB paths unverified (VM offline).
 */
const createAudit = z.object({
  name: z.string().min(1).max(255),
  kind: z.enum(['dockerfile', 'image_config', 'trivy']),
  // Dockerfile text or scanner JSON. Bounded to keep a single row/job sane.
  input: z.string().min(1).max(1_000_000),
});

export default async function containerRoutes(app: FastifyInstance): Promise<void> {
  app.get('/audits', { preHandler: [app.requirePerms('container:read')], schema: { tags: ['container'] } },
    async (req) => {
      const limit = Math.min(Number((req.query as any)?.limit ?? 50), 200);
      const { rows } = await pool.query(
        `SELECT id, name, kind, status, score, summary, error,
                created_at, updated_at, finished_at
           FROM aegis.container_audits
          ORDER BY created_at DESC LIMIT $1`, [limit]);
      return { data: rows };
    });

  app.get('/audits/:id', { preHandler: [app.requirePerms('container:read')], schema: { tags: ['container'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query(
        `SELECT id, name, kind, input, status, score, summary, error,
                created_at, updated_at, finished_at
           FROM aegis.container_audits WHERE id = $1`, [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      const { rows: findings } = await pool.query(
        `SELECT id, rule_id, category, severity, title, remediation, location, created_at
           FROM aegis.container_findings
          WHERE audit_id = $1
          ORDER BY severity DESC, id`, [id]);
      return { ...rows[0], findings };
    });

  /** POST /api/container/audits — create + enqueue a container audit */
  app.post('/audits', { preHandler: [app.requirePerms('container:run')], schema: { tags: ['container'] } },
    async (req, reply) => {
      const parsed = createAudit.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;

      const { rows } = await pool.query(
        `INSERT INTO aegis.container_audits(name, kind, input, status, requested_by)
         VALUES ($1,$2,$3,'queued',$4) RETURNING id`,
        [b.name, b.kind, b.input, req.user.sub]);
      const auditId = rows[0].id;

      await pool.query(
        `SELECT aegis.enqueue_job('container.audit', $1::jsonb, 'default', 3)`,
        [JSON.stringify({ audit_id: auditId })]);

      await audit(req, { action: 'container.audit.create', resource: 'container_audit',
        resourceId: auditId, metadata: { name: b.name, kind: b.kind } });
      return reply.code(202).send({ id: auditId, status: 'queued' });
    });

  /** DELETE /api/container/audits/:id — remove an audit (cascades findings) */
  app.delete('/audits/:id', { preHandler: [app.requirePerms('container:run')], schema: { tags: ['container'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rowCount } = await pool.query('DELETE FROM aegis.container_audits WHERE id = $1', [id]);
      if (!rowCount) return reply.code(404).send({ error: 'not_found' });
      await audit(req, { action: 'container.audit.delete', resource: 'container_audit', resourceId: id });
      return reply.code(204).send();
    });
}
