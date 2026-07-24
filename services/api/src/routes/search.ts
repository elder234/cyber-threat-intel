import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { cached } from '../lib/redis.js';

const searchQuery = z.object({
  q: z.string().min(1).max(256),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

/**
 * Module 12 — unified search across IOCs, CVEs, threat actors, malware families
 * via the aegis.unified_search() SQL function. Results are cached briefly.
 */
export default async function searchRoutes(app: FastifyInstance): Promise<void> {
  app.get('/', { preHandler: [app.requirePerms('search:read')], schema: {
    tags: ['search'],
    summary: 'Unified search across all intelligence entities',
    querystring: {
      type: 'object', required: ['q'],
      properties: { q: { type: 'string' }, limit: { type: 'integer' } },
    },
  } }, async (req, reply) => {
    const parsed = searchQuery.safeParse(req.query);
    if (!parsed.success) return reply.code(400).send({ error: 'bad_request' });
    const { q, limit } = parsed.data;

    const results = await cached(`search:${q}:${limit}`, 60, async () => {
      const { rows } = await pool.query(
        'SELECT * FROM aegis.unified_search($1, $2)', [q, limit],
      );
      return rows;
    });
    // group by entity_type for the UI
    const grouped: Record<string, unknown[]> = {};
    for (const r of results as Array<{ entity_type: string }>) {
      (grouped[r.entity_type] ??= []).push(r);
    }
    return { query: q, count: (results as unknown[]).length, results, grouped };
  });
}
