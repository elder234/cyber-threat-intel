import argon2 from 'argon2';
import { createHash, randomBytes } from 'node:crypto';
import { pool } from '../db/pool.js';
import { config } from '../config.js';

/** Argon2id password hashing. */
export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2 });
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Opaque refresh token (stored hashed) with a rotation family for reuse detection. */
export function newRefreshToken(): { token: string; hash: string } {
  const token = randomBytes(48).toString('base64url');
  return { token, hash: sha256(token) };
}

export interface JwtUser {
  sub: string;
  email: string;
  roles: string[];
  perms: string[];
}

const MAX_FAILED = 5;
const LOCK_MINUTES = 15;

/** Load a user + resolved roles/permissions for token claims. */
export async function loadUserClaims(userId: string): Promise<JwtUser | null> {
  const { rows } = await pool.query(
    `SELECT u.id, u.email,
            COALESCE(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
       FROM aegis.users u
       LEFT JOIN aegis.user_roles ur ON ur.user_id = u.id
       LEFT JOIN aegis.roles r ON r.id = ur.role_id
      WHERE u.id = $1 AND u.is_active = true
      GROUP BY u.id, u.email`,
    [userId],
  );
  if (!rows.length) return null;
  const { rows: permRows } = await pool.query(
    'SELECT code FROM aegis.user_permissions($1)',
    [userId],
  );
  return {
    sub: rows[0].id,
    email: rows[0].email,
    roles: rows[0].roles,
    perms: permRows.map((r) => r.code),
  };
}

/**
 * Verify credentials with lockout. Returns the user id on success, or null.
 * Increments failed_logins and locks the account after MAX_FAILED attempts.
 */
export async function authenticate(email: string, password: string): Promise<string | null> {
  const { rows } = await pool.query(
    `SELECT id, password_hash, is_active, failed_logins, locked_until
       FROM aegis.users WHERE email = $1`,
    [email],
  );
  if (!rows.length) {
    // Constant-time-ish: still run a hash to blunt user enumeration timing.
    await argon2.hash('dummy').catch(() => undefined);
    return null;
  }
  const u = rows[0];
  if (!u.is_active) return null;
  if (u.locked_until && new Date(u.locked_until) > new Date()) return null;

  const ok = await verifyPassword(u.password_hash, password);
  if (!ok) {
    const failed = (u.failed_logins ?? 0) + 1;
    const lock = failed >= MAX_FAILED;
    await pool.query(
      `UPDATE aegis.users
          SET failed_logins = $2,
              locked_until = CASE WHEN $3 THEN now() + ($4 || ' minutes')::interval ELSE locked_until END
        WHERE id = $1`,
      [u.id, failed, lock, LOCK_MINUTES],
    );
    return null;
  }

  await pool.query(
    `UPDATE aegis.users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`,
    [u.id],
  );
  return u.id;
}

export const jwtConfig = {
  access: { secret: config.JWT_ACCESS_SECRET, ttl: config.JWT_ACCESS_TTL },
  refresh: { secret: config.JWT_REFRESH_SECRET, ttl: config.JWT_REFRESH_TTL },
};
