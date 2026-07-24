import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import {
  authenticate,
  loadUserClaims,
  newRefreshToken,
  sha256,
  jwtConfig,
} from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { randomUUID } from 'node:crypto';

const loginBody = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});
const refreshBody = z.object({ refreshToken: z.string().min(1) });

export default async function authRoutes(app: FastifyInstance): Promise<void> {
  /** POST /api/auth/login — password → access + refresh tokens */
  app.post('/login', {
    schema: {
      tags: ['auth'],
      summary: 'Authenticate with email + password',
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' },
        },
      },
    },
  }, async (req, reply) => {
    const parsed = loginBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'bad_request' });
    const { email, password } = parsed.data;

    const userId = await authenticate(email, password);
    if (!userId) {
      await audit(req, { actorEmail: email, action: 'auth.login.failed', resource: 'auth' });
      return reply.code(401).send({ error: 'invalid_credentials' });
    }

    const claims = await loadUserClaims(userId);
    if (!claims) return reply.code(401).send({ error: 'invalid_credentials' });

    const accessToken = await reply.jwtSign(claims, { expiresIn: jwtConfig.access.ttl });
    const { token, hash } = newRefreshToken();
    const familyId = randomUUID();
    await pool.query(
      `INSERT INTO aegis.refresh_tokens(user_id, token_hash, family_id, user_agent, ip, expires_at)
       VALUES ($1,$2,$3,$4,$5, now() + ($6 || ' seconds')::interval)`,
      [userId, hash, familyId, req.headers['user-agent'] ?? null, req.ip, jwtConfig.refresh.ttl],
    );

    await audit(req, { actorId: userId, actorEmail: email, action: 'auth.login', resource: 'auth' });
    return reply.send({
      accessToken,
      refreshToken: token,
      tokenType: 'Bearer',
      expiresIn: jwtConfig.access.ttl,
      user: { id: claims.sub, email: claims.email, roles: claims.roles },
    });
  });

  /** POST /api/auth/refresh — rotate refresh token; detect reuse */
  app.post('/refresh', {
    schema: { tags: ['auth'], summary: 'Rotate refresh token' },
  }, async (req, reply) => {
    const parsed = refreshBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'bad_request' });
    const hash = sha256(parsed.data.refreshToken);

    const { rows } = await pool.query(
      `SELECT id, user_id, family_id, revoked_at, expires_at
         FROM aegis.refresh_tokens WHERE token_hash = $1`,
      [hash],
    );
    if (!rows.length) return reply.code(401).send({ error: 'invalid_token' });
    const rt = rows[0];

    // Reuse detection: a revoked token being presented means the family is compromised.
    if (rt.revoked_at) {
      await pool.query(
        `UPDATE aegis.refresh_tokens SET revoked_at = now()
          WHERE family_id = $1 AND revoked_at IS NULL`,
        [rt.family_id],
      );
      await audit(req, { actorId: rt.user_id, action: 'auth.refresh.reuse_detected', resource: 'auth' });
      return reply.code(401).send({ error: 'token_reuse_detected' });
    }
    if (new Date(rt.expires_at) < new Date()) {
      return reply.code(401).send({ error: 'token_expired' });
    }

    const claims = await loadUserClaims(rt.user_id);
    if (!claims) return reply.code(401).send({ error: 'invalid_token' });

    // Rotate: revoke old, issue new in same family.
    const { token, hash: newHash } = newRefreshToken();
    await pool.query('UPDATE aegis.refresh_tokens SET revoked_at = now() WHERE id = $1', [rt.id]);
    await pool.query(
      `INSERT INTO aegis.refresh_tokens(user_id, token_hash, family_id, user_agent, ip, expires_at)
       VALUES ($1,$2,$3,$4,$5, now() + ($6 || ' seconds')::interval)`,
      [rt.user_id, newHash, rt.family_id, req.headers['user-agent'] ?? null, req.ip, jwtConfig.refresh.ttl],
    );

    const accessToken = await reply.jwtSign(claims, { expiresIn: jwtConfig.access.ttl });
    return reply.send({ accessToken, refreshToken: token, tokenType: 'Bearer', expiresIn: jwtConfig.access.ttl });
  });

  /** POST /api/auth/logout — revoke a refresh token */
  app.post('/logout', { preHandler: [app.authenticate], schema: { tags: ['auth'] } }, async (req, reply) => {
    const parsed = refreshBody.safeParse(req.body);
    if (parsed.success) {
      await pool.query(
        'UPDATE aegis.refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL',
        [sha256(parsed.data.refreshToken)],
      );
    }
    await audit(req, { action: 'auth.logout', resource: 'auth' });
    return reply.send({ ok: true });
  });

  /** GET /api/auth/me — current identity, roles, permissions */
  app.get('/me', { preHandler: [app.authenticate], schema: { tags: ['auth'] } }, async (req) => {
    return { user: req.user };
  });
}
