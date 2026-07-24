import type { FastifyRequest } from 'fastify';
import { pool } from '../db/pool.js';

export interface AuditEntry {
  actorId?: string | null;
  actorEmail?: string | null;
  action: string;
  resource?: string | null;
  resourceId?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Append an audit-log record via the aegis.write_audit() stored procedure.
 * Never throws into the request path — audit failures are logged, not fatal.
 */
export async function audit(req: FastifyRequest | null, entry: AuditEntry): Promise<void> {
  try {
    const ip = req?.ip ?? null;
    const ua = (req?.headers['user-agent'] as string) ?? null;
    await pool.query(
      `SELECT aegis.write_audit($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        entry.actorId ?? req?.user?.sub ?? null,
        entry.actorEmail ?? req?.user?.email ?? null,
        entry.action,
        entry.resource ?? null,
        entry.resourceId ?? null,
        ip,
        ua,
        JSON.stringify(entry.metadata ?? {}),
      ],
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('audit write failed:', (err as Error).message);
  }
}
