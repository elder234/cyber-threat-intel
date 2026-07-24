import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { audit } from '../lib/audit.js';

const createScan = z.object({
  assetId: z.string().uuid().optional(),
  target: z.string().min(1).max(255),
  scanType: z.enum(['port','tls','http','subdomain','full']).default('port'),
  profile: z.record(z.unknown()).default({}),
});

/**
 * Module 5 (API side) — scans are launched by enqueuing a job for the Rust
 * aegis-scanner. A scan against a known asset REQUIRES asset.is_authorized = true;
 * ad-hoc targets are recorded and still gated by the 'scan:run' permission.
 */
export default async function scanRoutes(app: FastifyInstance): Promise<void> {
  app.get('/', { preHandler: [app.requirePerms('scan:read')], schema: { tags: ['scans'] } },
    async (req) => {
      const limit = Math.min(Number((req.query as any)?.limit ?? 50), 200);
      const { rows } = await pool.query(
        `SELECT id, target, scan_type, status, progress, started_at, finished_at, created_at
           FROM aegis.scans ORDER BY created_at DESC LIMIT $1`, [limit]);
      return { data: rows };
    });

  app.get('/:id', { preHandler: [app.requirePerms('scan:read')], schema: { tags: ['scans'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query('SELECT * FROM aegis.scans WHERE id = $1', [id]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      const [{ rows: ports }, { rows: tls }, { rows: findings }] = await Promise.all([
        pool.query('SELECT * FROM aegis.scan_ports WHERE scan_id = $1 ORDER BY port', [id]),
        pool.query('SELECT * FROM aegis.scan_tls WHERE scan_id = $1', [id]),
        pool.query('SELECT * FROM aegis.findings WHERE scan_id = $1 ORDER BY severity DESC', [id]),
      ]);
      return { ...rows[0], ports, tls, findings };
    });

  /** POST /api/scans — enqueue a scan job (authorization enforced) */
  app.post('/', { preHandler: [app.requirePerms('scan:run')], schema: { tags: ['scans'] } },
    async (req, reply) => {
      const parsed = createScan.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request', details: parsed.error.flatten() });
      const b = parsed.data;

      if (b.assetId) {
        const { rows } = await pool.query(
          'SELECT is_authorized FROM aegis.assets WHERE id = $1', [b.assetId]);
        if (!rows.length) return reply.code(404).send({ error: 'asset_not_found' });
        if (!rows[0].is_authorized) {
          return reply.code(403).send({ error: 'asset_not_authorized',
            message: 'Scanning requires the asset to be explicitly marked authorized.' });
        }
      }

      const { rows: scan } = await pool.query(
        `INSERT INTO aegis.scans(asset_id, target, scan_type, profile, status, requested_by)
         VALUES ($1,$2,$3,$4,'queued',$5) RETURNING id`,
        [b.assetId ?? null, b.target, b.scanType, JSON.stringify(b.profile), req.user.sub]);
      const scanId = scan[0].id;

      await pool.query(
        `SELECT aegis.enqueue_job('scan.run', $1::jsonb, 'scanner', 3)`,
        [JSON.stringify({ scan_id: scanId, target: b.target, scan_type: b.scanType,
          asset_id: b.assetId ?? null, profile: b.profile })]);

      await audit(req, { action: 'scan.create', resource: 'scan', resourceId: scanId,
        metadata: { target: b.target, type: b.scanType } });
      return reply.code(202).send({ id: scanId, status: 'queued' });
    });
}
