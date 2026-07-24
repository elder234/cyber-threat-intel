import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Redis from 'ioredis';

import { config } from './config.js';
import authPlugin from './plugins/auth.js';
import authRoutes from './routes/auth.js';
import iocRoutes from './routes/iocs.js';
import cveRoutes from './routes/cves.js';
import ruleRoutes from './routes/rules.js';
import searchRoutes from './routes/search.js';
import dashboardRoutes from './routes/dashboard.js';
import alertRoutes from './routes/alerts.js';
import alertRuleRoutes from './routes/alertRules.js';
import channelRoutes from './routes/channels.js';
import feedRoutes from './routes/feeds.js';
import scanRoutes from './routes/scans.js';
import containerRoutes from './routes/container.js';
import malwareRoutes from './routes/malware.js';
import healthRoutes from './routes/health.js';
import registerWs from './ws/hub.js';
import registerGraphql from './graphql/index.js';

// Expose config on the instance for plugins (e.g. GraphiQL toggle).
declare module 'fastify' {
  interface FastifyInstance {
    config: typeof config;
  }
}

export async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      transport: config.isProd ? undefined : { target: 'pino-pretty' },
      redact: ['req.headers.authorization', 'req.headers.cookie'],
    },
    trustProxy: true,
    bodyLimit: 5 * 1024 * 1024,
  });

  app.decorate('config', config);

  // ── Security & platform plugins ────────────────────────────────────────────
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: config.corsOrigins, credentials: true });
  await app.register(multipart, { limits: { fileSize: 32 * 1024 * 1024 } });
  await app.register(rateLimit, {
    max: config.RATE_LIMIT_MAX,
    timeWindow: config.RATE_LIMIT_WINDOW * 1000,
    redis: new Redis(config.REDIS_URL, { connectionName: 'ratelimit', maxRetriesPerRequest: 1 }),
    keyGenerator: (req) => req.user?.sub ?? req.ip,
  });

  // ── OpenAPI / Swagger ──────────────────────────────────────────────────────
  await app.register(swagger, {
    openapi: {
      info: { title: 'Aegis CTI API', version: '0.1.0', description: 'Cyber Threat Intelligence Platform API' },
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        },
      },
      security: [{ bearerAuth: [] }],
      tags: [
        { name: 'auth' }, { name: 'iocs' }, { name: 'cves' }, { name: 'rules' }, { name: 'search' },
        { name: 'dashboard' }, { name: 'alerts' }, { name: 'feeds' }, { name: 'scans' },
        { name: 'container' },
        { name: 'malware' },
        { name: 'system' },
      ],
    },
  });
  await app.register(swaggerUi, { routePrefix: '/api/docs' });

  await app.register(authPlugin);

  // ── Routes ─────────────────────────────────────────────────────────────────
  await app.register(healthRoutes, { prefix: '/api' });
  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(iocRoutes, { prefix: '/api/iocs' });
  await app.register(cveRoutes, { prefix: '/api/cves' });
  await app.register(ruleRoutes, { prefix: '/api/rules' });
  await app.register(searchRoutes, { prefix: '/api/search' });
  await app.register(dashboardRoutes, { prefix: '/api/dashboard' });
  await app.register(alertRoutes, { prefix: '/api/alerts' });
  await app.register(alertRuleRoutes, { prefix: '/api/alert-rules' });
  await app.register(channelRoutes, { prefix: '/api/channels' });
  await app.register(feedRoutes, { prefix: '/api/feeds' });
  await app.register(scanRoutes, { prefix: '/api/scans' });
  await app.register(containerRoutes, { prefix: '/api/container' });
  await app.register(malwareRoutes, { prefix: '/api/malware' });

  // ── GraphQL + WebSockets ───────────────────────────────────────────────────
  await registerGraphql(app);
  await registerWs(app);

  // Uniform error shape.
  app.setErrorHandler((err, _req, reply) => {
    const status = err.statusCode ?? 500;
    if (status >= 500) app.log.error(err);
    reply.code(status).send({
      error: err.name ?? 'error',
      message: status >= 500 ? 'internal_server_error' : err.message,
    });
  });

  return app;
}
