import { buildApp } from './app.js';
import { config } from './config.js';
import { runMigrations, seedAdmin } from './db/migrate.js';
import { closePool } from './db/pool.js';
import { startAlertEngine, type AlertEngine } from './alerts/engine.js';

/** Server entrypoint: migrate, seed admin, then listen. */
async function main(): Promise<void> {
  // Self-migrate on boot so containers converge to the latest schema.
  await runMigrations();
  await seedAdmin();

  const app = await buildApp();

  // Module 11 — start the alert engine (Redis event → rule match → notify).
  let engine: AlertEngine | undefined;
  if (config.ALERTS_ENABLED) {
    engine = await startAlertEngine(app.log).catch((err) => {
      app.log.error({ err }, 'alert engine failed to start — continuing without it');
      return undefined;
    });
  }

  const shutdown = async (signal: string) => {
    app.log.info(`received ${signal}, shutting down`);
    if (engine) await engine.stop();
    await app.close();
    await closePool();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ host: config.API_HOST, port: config.API_PORT });
  app.log.info(`Aegis API listening on http://${config.API_HOST}:${config.API_PORT} (docs: /api/docs)`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('fatal startup error:', err);
  process.exit(1);
});
