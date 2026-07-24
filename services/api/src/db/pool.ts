import pg from 'pg';
import { config } from '../config.js';

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
