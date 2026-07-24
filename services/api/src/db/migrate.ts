import { readdir, readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import argon2 from 'argon2';
import { pool } from './pool.js';
import { config } from '../config.js';

/**
 * Migration runner. Applies db/migrations/*.sql in filename order, recording
 * each in aegis.schema_migrations so re-runs are idempotent. Mirrors db/migrate.sh
 * so the API self-migrates on container start.
 */
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Resolve the migrations directory across dev (src) and container (dist) layouts. */
async function resolveMigrationsDir(): Promise<string> {
  const candidates = [
    process.env.MIGRATIONS_DIR,
    path.resolve(__dirname, '../../../../db/migrations'), // dev: services/api/src/db + container: /db
    '/db/migrations',
    path.resolve(process.cwd(), 'db/migrations'),
  ].filter(Boolean) as string[];
  for (const dir of candidates) {
    try {
      await access(dir);
      return dir;
    } catch {
      /* try next */
    }
  }
  throw new Error(`Could not locate db/migrations (tried: ${candidates.join(', ')})`);
}

export async function runMigrations(): Promise<void> {
  await pool.query(`
    CREATE SCHEMA IF NOT EXISTS aegis;
    CREATE TABLE IF NOT EXISTS aegis.schema_migrations(
      filename text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  const migrationsDir = await resolveMigrationsDir();
  const files = (await readdir(migrationsDir))
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const { rowCount } = await pool.query(
      'SELECT 1 FROM aegis.schema_migrations WHERE filename = $1',
      [file],
    );
    if (rowCount) continue;

    const sql = await readFile(path.join(migrationsDir, file), 'utf8');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query(
        'INSERT INTO aegis.schema_migrations(filename) VALUES ($1)',
        [file],
      );
      await client.query('COMMIT');
      // eslint-disable-next-line no-console
      console.log(`  ▸ applied ${file}`);
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Migration ${file} failed: ${(err as Error).message}`);
    } finally {
      client.release();
    }
  }
}

/** Ensure a default admin user + role assignment exists (first boot only). */
export async function seedAdmin(): Promise<void> {
  const { rows } = await pool.query(
    'SELECT id FROM aegis.users WHERE email = $1',
    [config.SEED_ADMIN_EMAIL],
  );
  if (rows.length) return;

  const hash = await argon2.hash(config.SEED_ADMIN_PASSWORD, { type: argon2.argon2id });
  const {
    rows: [user],
  } = await pool.query(
    `INSERT INTO aegis.users(email, display_name, password_hash, is_active)
     VALUES ($1, 'Administrator', $2, true) RETURNING id`,
    [config.SEED_ADMIN_EMAIL, hash],
  );
  await pool.query(
    `INSERT INTO aegis.user_roles(user_id, role_id)
     SELECT $1, id FROM aegis.roles WHERE name = 'admin'
     ON CONFLICT DO NOTHING`,
    [user.id],
  );
  // eslint-disable-next-line no-console
  console.log(`  ▸ seeded admin ${config.SEED_ADMIN_EMAIL}`);
}

// Allow running standalone: `tsx src/db/migrate.ts`
if (import.meta.url === `file://${process.argv[1]}`) {
  runMigrations()
    .then(seedAdmin)
    .then(() => {
      // eslint-disable-next-line no-console
      console.log('✔ migrations complete');
      return pool.end();
    })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error('✗ migration failed:', err);
      process.exit(1);
    });
}
