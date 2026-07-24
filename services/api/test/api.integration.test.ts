import { describe, it, expect, beforeAll, afterAll } from 'vitest';

/**
 * Integration tests — REQUIRE RUNTIME VERIFICATION.
 * These need a live Postgres + Redis (set DATABASE_URL / REDIS_URL). They are
 * skipped automatically when RUN_INTEGRATION!=1 so unit CI stays hermetic.
 *
 * To run:  RUN_INTEGRATION=1 DATABASE_URL=... REDIS_URL=... npm test
 */
const RUN = process.env.RUN_INTEGRATION === '1';
const d = RUN ? describe : describe.skip;

d('API integration (auth + RBAC + IOC lifecycle)', () => {
  let app: Awaited<ReturnType<typeof import('../src/app.js')['buildApp']>>;
  let accessToken = '';

  beforeAll(async () => {
    const { runMigrations, seedAdmin } = await import('../src/db/migrate.js');
    await runMigrations();
    await seedAdmin();
    const { buildApp } = await import('../src/app.js');
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app?.close();
  });

  it('rejects unauthenticated access to protected routes', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/iocs' });
    expect(res.statusCode).toBe(401);
  });

  it('logs in the seeded admin and returns tokens', async () => {
    const res = await app.inject({
      method: 'POST', url: '/api/auth/login',
      payload: {
        email: process.env.SEED_ADMIN_EMAIL ?? 'admin@aegis.local',
        password: process.env.SEED_ADMIN_PASSWORD ?? 'ChangeMe123!',
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accessToken).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    accessToken = body.accessToken;
  });

  it('creates and reads back an IOC (admin has ioc:write)', async () => {
    const create = await app.inject({
      method: 'POST', url: '/api/iocs',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { type: 'ipv4', value: '198.51.100.7', severity: 'high', confidence: 'high' },
    });
    expect(create.statusCode).toBe(201);
    const ioc = create.json();
    expect(ioc.value).toBe('198.51.100.7');
    expect(ioc.score).toBeGreaterThan(0);

    const list = await app.inject({
      method: 'GET', url: '/api/iocs?type=ipv4',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(list.statusCode).toBe(200);
    expect(list.json().data.length).toBeGreaterThanOrEqual(1);
  });

  it('unified search finds the created IOC', async () => {
    const res = await app.inject({
      method: 'GET', url: '/api/search?q=198.51.100.7',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().count).toBeGreaterThanOrEqual(1);
  });

  it('health readiness reports dependencies', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health/ready' });
    expect([200, 503]).toContain(res.statusCode);
    expect(res.json().checks.postgres).toBeDefined();
  });
});
