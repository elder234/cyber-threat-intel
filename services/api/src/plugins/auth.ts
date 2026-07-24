import fp from 'fastify-plugin';
import fastifyJwt from '@fastify/jwt';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../config.js';
import type { JwtUser } from '../lib/auth.js';

// Augment Fastify types so req.user is strongly typed everywhere.
declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requirePerms: (
      ...perms: string[]
    ) => (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    user: JwtUser;
  }
}
declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: JwtUser;
    user: JwtUser;
  }
}

/**
 * Registers JWT verification and two guards:
 *   - `authenticate`  : requires a valid access token
 *   - `requirePerms`  : requires the caller to hold ALL listed permission codes
 */
export default fp(async (app) => {
  await app.register(fastifyJwt, {
    secret: config.JWT_ACCESS_SECRET,
    sign: { expiresIn: config.JWT_ACCESS_TTL },
  });

  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      await req.jwtVerify();
    } catch {
      return reply.code(401).send({ error: 'unauthorized', message: 'Invalid or expired token' });
    }
  });

  app.decorate(
    'requirePerms',
    (...perms: string[]) =>
      async (req: FastifyRequest, reply: FastifyReply) => {
        try {
          await req.jwtVerify();
        } catch {
          return reply.code(401).send({ error: 'unauthorized' });
        }
        const held = new Set(req.user.perms ?? []);
        const missing = perms.filter((p) => !held.has(p));
        if (missing.length) {
          return reply
            .code(403)
            .send({ error: 'forbidden', message: `Missing permission(s): ${missing.join(', ')}` });
        }
      },
  );
});
