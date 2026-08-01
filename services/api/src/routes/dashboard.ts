import type { FastifyInstance } from 'fastify';
import { pool } from '../db/pool.js';
import { cached } from '../lib/redis.js';

/** Module 1 — dashboard aggregate endpoints (stats, timeline, attack matrix). */
export default async function dashboardRoutes(app: FastifyInstance): Promise<void> {
  /** GET /api/dashboard/stats — header KPI tiles */
  app.get('/stats', { preHandler: [app.requirePerms('dashboard:read')], schema: { tags: ['dashboard'] } },
    async () => cached('dash:stats', 15, async () => {
      const { rows } = await pool.query('SELECT aegis.dashboard_stats() AS stats');
      return rows[0].stats;
    }));

  /** GET /api/dashboard/timeline — recent events for the timeline widget */
  app.get('/timeline', { preHandler: [app.requirePerms('dashboard:read')], schema: { tags: ['dashboard'] } },
    async () => cached('dash:timeline', 30, async () => {
      const { rows } = await pool.query(
        'SELECT ts, kind, severity, title FROM aegis.v_threat_timeline ORDER BY ts DESC LIMIT 200',
      );
      return rows;
    }));

  /** GET /api/dashboard/attack-matrix — IOC counts by MITRE tactic */
  app.get('/attack-matrix', { preHandler: [app.requirePerms('dashboard:read')], schema: { tags: ['dashboard'] } },
    async () => cached('dash:attack', 60, async () => {
      const { rows } = await pool.query(
        'SELECT tactic, count FROM aegis.v_attack_stats',
      );
      return rows;
    }));

  /** GET /api/dashboard/top-sources */
  app.get('/top-sources', { preHandler: [app.requirePerms('dashboard:read')], schema: { tags: ['dashboard'] } },
    async () => cached('dash:sources', 60, async () => {
      const { rows } = await pool.query(
        'SELECT source, count, high_sev FROM aegis.v_top_sources LIMIT 15',
      );
      return rows;
    }));
}
