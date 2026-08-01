import { z } from 'zod';
import dotenv from 'dotenv';

// Load .env when present (docker-compose passes env directly; local dev uses file).
dotenv.config();

/**
 * Central, validated configuration. Fails fast at boot if required secrets are
 * missing or malformed — no service should start in a half-configured state.
 */
const PLACEHOLDER_SECRET = /^change_me|^ChangeMe123!$/i;

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.string().default('info'),

  API_HOST: z.string().default('0.0.0.0'),
  API_PORT: z.coerce.number().int().positive().default(8080),
  API_PUBLIC_URL: z.string().url().default('http://localhost:8080'),
  CORS_ORIGINS: z.string().default('http://localhost:8080'),

  DATABASE_URL: z.string().min(1),
  PG_POOL_MAX: z.coerce.number().int().positive().default(20),

  REDIS_URL: z.string().min(1),

  JWT_ACCESS_SECRET: z.string().min(16),
  JWT_REFRESH_SECRET: z.string().min(16),
  JWT_ACCESS_TTL: z.coerce.number().int().positive().default(900),
  JWT_REFRESH_TTL: z.coerce.number().int().positive().default(1_209_600),

  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(300),
  RATE_LIMIT_WINDOW: z.coerce.number().int().positive().default(60),

  SEED_ADMIN_EMAIL: z.string().email().default('admin@aegis.local'),
  // No default: a published admin password must never be used silently.
  SEED_ADMIN_PASSWORD: z.string().min(8),

  // ── Notifications (Module 11) — all optional; a channel is disabled if unset ──
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().positive().default(587),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().default('Aegis CTI <aegis@localhost>'),
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  ALERTS_ENABLED: z.coerce.boolean().default(true),
})
  // Hard-fail on repo-published placeholder secrets in production. These pass
  // shape validation (min length) but are publicly known signing/admin keys.
  .superRefine((val, ctx) => {
    if (val.NODE_ENV !== 'production') return;
    for (const key of ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'SEED_ADMIN_PASSWORD'] as const) {
      if (PLACEHOLDER_SECRET.test(val[key])) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `${key} must not be a placeholder value in production`,
        });
      }
    }
  });

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('✗ Invalid configuration:\n', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = {
  ...parsed.data,
  isProd: parsed.data.NODE_ENV === 'production',
  corsOrigins: parsed.data.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
};

export type Config = typeof config;
