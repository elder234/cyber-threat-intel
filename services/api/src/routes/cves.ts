import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { cached } from '../lib/redis.js';

const listQuery = z.object({
  kev: z.coerce.boolean().optional(),
  minCvss: z.coerce.number().min(0).max(10).optional(),
  minEpss: z.coerce.number().min(0).max(1).optional(),
  q: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export default async function cveRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/cves — filter by KEV / CVSS / EPSS / text */
  app.get('/', { preHandler: [app.requirePerms('cve:read')], schema: { tags: ['cves'] } },
    async (req, reply) => {
      const parsed = listQuery.safeParse(req.query);
      if (!parsed.success) return reply.code(400).send({ error: 'bad_request' });
      const { kev, minCvss, minEpss, q, limit, offset } = parsed.data;

      const where: string[] = [];
      const params: unknown[] = [];
      if (kev) where.push('kev = true');
      if (minCvss !== undefined) { params.push(minCvss); where.push(`cvss_v31_score >= $${params.length}`); }
      if (minEpss !== undefined) { params.push(minEpss); where.push(`epss_score >= $${params.length}`); }
      if (q) {
        params.push(`%${q}%`);
        const p = `$${params.length}`;
        where.push(`(cve_id ILIKE ${p} OR description ILIKE ${p})`);
      }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      const dataParams = [...params, limit, offset];
      const { rows } = await pool.query(
        `SELECT cve_id, left(description, 240) AS description, cvss_v31_score, cvss_v31_severity,
                epss_score, epss_percentile, kev, kev_ransomware, published_at
           FROM aegis.cves ${whereSql}
          ORDER BY COALESCE(cvss_v31_score,0) DESC, published_at DESC NULLS LAST
          LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`,
        dataParams,
      );
      const { rows: [{ count }] } = await pool.query(
        `SELECT count(*)::int AS count FROM aegis.cves ${whereSql}`, params,
      );
      return { data: rows, pagination: { total: count, limit, offset } };
    });

  /** GET /api/cves/:id */
  app.get('/:id', { preHandler: [app.requirePerms('cve:read')], schema: { tags: ['cves'] } },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { rows } = await pool.query('SELECT * FROM aegis.cves WHERE cve_id = $1', [id.toUpperCase()]);
      if (!rows.length) return reply.code(404).send({ error: 'not_found' });
      return rows[0];
    });

  /** GET /api/cves/kev/recent — cached KEV widget feed */
  app.get('/kev/recent', { preHandler: [app.requirePerms('cve:read')], schema: { tags: ['cves'] } },
    async () => cached('cve:kev:recent', 300, async () => {
      const { rows } = await pool.query(
        `SELECT cve_id, description, cvss_v31_score, cvss_v31_severity, epss_score,
                epss_percentile, kev, kev_ransomware, published_at
           FROM aegis.v_recent_kev`,
      );
      return rows;
    }));
}
