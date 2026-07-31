import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    env: {
      // Hermetic unit tests import src/config.ts, which requires these. Real
      // values pass through so RUN_INTEGRATION=1 still uses live services.
      DATABASE_URL: process.env.DATABASE_URL ?? 'postgres://aegis:aegis@localhost:5432/aegis',
      REDIS_URL: process.env.REDIS_URL ?? 'redis://localhost:6379/0',
      JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET ?? 'test_access_secret_0123456789abcdef',
      JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET ?? 'test_refresh_secret_0123456789abcdef',
    },
  },
});
