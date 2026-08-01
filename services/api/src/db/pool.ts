import pg from 'pg';
import { config } from '../config.js';

/**
 * node-postgres returns `numeric`/`decimal` (OID 1700) as a *string* by default,
 * because Postgres NUMERIC is arbitrary-precision and has no lossless JS
 * counterpart. Every NUMERIC column in this schema is a bounded score —
 * cvss_v31_score numeric(3,1), epss_score/epss_percentile numeric(6,5),
 * entropy — all well inside IEEE-754 exact range, so parsing to float is safe
 * and matches what the frontend types already declare (`number`).
 *
 * Without this, `cvss_v31_score.toFixed(1)` throws "not a function" and takes
 * down the whole React tree.
 *
 * ⚠️ If a true high-precision NUMERIC column is ever added (money, large
 * counters), give it an explicit cast in its query rather than removing this —
 * removing it silently re-breaks every score field.
 */
pg.types.setTypeParser(pg.types.builtins.NUMERIC, (v) => (v === null ? null : Number.parseFloat(v)));

// int8/bigint (OID 20) has the same class of problem but the opposite tradeoff:
// it genuinely can exceed Number.MAX_SAFE_INTEGER, so it is deliberately left
// as a string. Use `::int` or `::float8` in the query when a JS number is
// wanted — as the count(*)::int in routes/cves.ts already does.

/**
 * Shared PostgreSQL connection pool. All queries run against the `aegis` schema
 * (set via search_path on each new connection).
 */
export const pool = new pg.Pool({
  connectionString: config.DATABASE_URL,
  max: config.PG_POOL_MAX,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  application_name: 'aegis-api',
});

pool.on('connect', (client) => {
  client.query('SET search_path TO aegis, public');
});

pool.on('error', (err) => {
  // Pool-level errors (e.g. backend crash) shouldn't take down the process.
  // eslint-disable-next-line no-console
  console.error('pg pool error:', err.message);
});

/** Typed query helper. */
export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params as any[]);
}

/** Run a function inside a transaction, rolling back on error. */
export async function withTransaction<T>(
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function closePool(): Promise<void> {
  await pool.end();
}
