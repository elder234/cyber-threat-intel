import type { FastifyInstance } from 'fastify';
import mercurius from 'mercurius';
import { pool } from '../db/pool.js';

/**
 * Module 15 (GraphQL) — a read-focused GraphQL surface over the same data as
 * REST. Auth is enforced in the context builder; field resolvers additionally
 * check permissions. Mutations live in REST to keep audit/side-effects in one place.
 */
const schema = /* GraphQL */ `
  type Query {
    ioc(id: ID!): Ioc
    iocs(type: String, severity: String, limit: Int = 50, offset: Int = 0): [Ioc!]!
    cve(id: ID!): Cve
    cves(kev: Boolean, minCvss: Float, limit: Int = 50): [Cve!]!
    search(q: String!, limit: Int = 25): [SearchResult!]!
    dashboardStats: DashboardStats!
  }

  type Ioc {
    id: ID!
    type: String!
    value: String!
    severity: String!
    confidence: String!
    tlp: String!
    score: Int!
    isActive: Boolean!
    tags: [String!]!
    source: String!
    firstSeen: String
    lastSeen: String
  }

  type Cve {
    cveId: ID!
    description: String
    cvssV31Score: Float
    epssScore: Float
    kev: Boolean!
    kevRansomware: Boolean!
    publishedAt: String
  }

  type SearchResult {
    entityType: String!
    entityId: String!
    title: String!
    subtitle: String
    score: Float
  }

  type DashboardStats {
    iocsActive: Int!
    iocsCritical: Int!
    cvesTotal: Int!
    cvesKev: Int!
    alertsOpen: Int!
    scansRunning: Int!
    findingsOpen: Int!
    jobsPending: Int!
  }
`;

interface Ctx { user?: { sub: string; perms: string[] }; }

function requirePerm(ctx: Ctx, perm: string): void {
  if (!ctx.user) throw new mercurius.ErrorWithProps('Unauthorized', {}, 401);
  if (!ctx.user.perms.includes(perm)) throw new mercurius.ErrorWithProps('Forbidden', {}, 403);
}

const resolvers = {
  Query: {
    ioc: async (_: unknown, { id }: { id: string }, ctx: Ctx) => {
      requirePerm(ctx, 'ioc:read');
      const { rows } = await pool.query('SELECT * FROM aegis.iocs WHERE id = $1', [id]);
      return rows[0] ? mapIoc(rows[0]) : null;
    },
    iocs: async (_: unknown, args: { type?: string; severity?: string; limit: number; offset: number }, ctx: Ctx) => {
      requirePerm(ctx, 'ioc:read');
      const where: string[] = [];
      const params: unknown[] = [];
      if (args.type) { params.push(args.type); where.push(`type = $${params.length}`); }
      if (args.severity) { params.push(args.severity); where.push(`severity = $${params.length}`); }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      params.push(args.limit, args.offset);
      const { rows } = await pool.query(
        `SELECT * FROM aegis.iocs ${whereSql} ORDER BY last_seen DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params);
      return rows.map(mapIoc);
    },
    cve: async (_: unknown, { id }: { id: string }, ctx: Ctx) => {
      requirePerm(ctx, 'cve:read');
      const { rows } = await pool.query('SELECT * FROM aegis.cves WHERE cve_id = $1', [id.toUpperCase()]);
      return rows[0] ? mapCve(rows[0]) : null;
    },
    cves: async (_: unknown, args: { kev?: boolean; minCvss?: number; limit: number }, ctx: Ctx) => {
      requirePerm(ctx, 'cve:read');
      const where: string[] = [];
      const params: unknown[] = [];
      if (args.kev) where.push('kev = true');
      if (args.minCvss != null) { params.push(args.minCvss); where.push(`cvss_v31_score >= $${params.length}`); }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      params.push(args.limit);
      const { rows } = await pool.query(
        `SELECT * FROM aegis.cves ${whereSql} ORDER BY cvss_v31_score DESC NULLS LAST LIMIT $${params.length}`, params);
      return rows.map(mapCve);
    },
    search: async (_: unknown, { q, limit }: { q: string; limit: number }, ctx: Ctx) => {
      requirePerm(ctx, 'search:read');
      const { rows } = await pool.query('SELECT * FROM aegis.unified_search($1,$2)', [q, limit]);
      return rows.map((r) => ({
        entityType: r.entity_type, entityId: r.entity_id, title: r.title, subtitle: r.subtitle, score: r.score,
      }));
    },
    dashboardStats: async (_: unknown, __: unknown, ctx: Ctx) => {
      if (!ctx.user) throw new mercurius.ErrorWithProps('Unauthorized', {}, 401);
      const { rows } = await pool.query('SELECT aegis.dashboard_stats() AS s');
      const s = rows[0].s;
      return {
        iocsActive: s.iocs_active, iocsCritical: s.iocs_critical, cvesTotal: s.cves_total,
        cvesKev: s.cves_kev, alertsOpen: s.alerts_open, scansRunning: s.scans_running,
        findingsOpen: s.findings_open, jobsPending: s.jobs_pending,
      };
    },
  },
};

/* eslint-disable @typescript-eslint/no-explicit-any */
function mapIoc(r: any) {
  return {
    id: r.id, type: r.type, value: r.value, severity: r.severity, confidence: r.confidence,
    tlp: r.tlp, score: r.score, isActive: r.is_active, tags: r.tags, source: r.source,
    firstSeen: r.first_seen, lastSeen: r.last_seen,
  };
}
function mapCve(r: any) {
  return {
    cveId: r.cve_id, description: r.description, cvssV31Score: r.cvss_v31_score,
    epssScore: r.epss_score, kev: r.kev, kevRansomware: r.kev_ransomware, publishedAt: r.published_at,
  };
}

export default async function registerGraphql(app: FastifyInstance): Promise<void> {
  await app.register(mercurius, {
    schema,
    resolvers: resolvers as never,
    graphiql: !app.config?.isProd,
    path: '/api/graphql',
    context: async (req) => {
      // Reuse JWT verification; unauthenticated queries get an empty context.
      try {
        const payload = await req.jwtVerify<{ sub: string; perms: string[] }>();
        return { user: payload };
      } catch {
        return {};
      }
    },
  });
}
