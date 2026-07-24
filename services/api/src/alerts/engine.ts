/**
 * Alert engine runtime (Module 11).
 *
 * Subscribes to the Redis `events` channel, matches each event against enabled
 * alert rules, raises alerts (dedupe-aware via aegis.raise_alert), applies a
 * per-rule throttle, publishes an `alert.new` event for the WS hub, and hands
 * the alert to the notification dispatcher.
 *
 * Rules are cached in-process and refreshed periodically so the hot path avoids
 * a DB round-trip per event.
 *
 * ⚠️ RUNTIME VERIFICATION REQUIRED — Redis + DB + delivery paths unverified (VM offline).
 */

import Redis from 'ioredis';
import type { FastifyBaseLogger } from 'fastify';
import { pool } from '../db/pool.js';
import { config } from '../config.js';
import { publish } from '../lib/redis.js';
import {
  type DomainEvent, type RuleSpec, alertTitle, dedupeKey, matchRule,
} from './match.js';
import { alertUrl, dispatchToChannels } from '../lib/notify/dispatch.js';
import type { AlertMessage, Severity } from '../lib/notify/format.js';

interface RuleRow extends RuleSpec {
  channels: string[];
  throttle_secs: number;
}

const RULE_REFRESH_MS = 30_000;

export class AlertEngine {
  private sub: Redis;
  private rules: RuleRow[] = [];
  private refreshTimer?: NodeJS.Timeout;
  // rule.id → last fire epoch ms, for throttling.
  private lastFired = new Map<string, number>();

  constructor(private log: FastifyBaseLogger) {
    this.sub = new Redis(config.REDIS_URL, { connectionName: 'alert-engine', lazyConnect: true });
  }

  async start(): Promise<void> {
    await this.refreshRules();
    this.refreshTimer = setInterval(() => {
      void this.refreshRules().catch((e) => this.log.error({ err: e }, 'alert rule refresh failed'));
    }, RULE_REFRESH_MS);

    await this.sub.connect();
    await this.sub.subscribe('events');
    this.sub.on('message', (_ch, raw) => {
      void this.onEvent(raw).catch((e) => this.log.error({ err: e }, 'alert engine event error'));
    });
    this.log.info('alert engine started');
  }

  async stop(): Promise<void> {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    await this.sub.quit().catch(() => undefined);
  }

  private async refreshRules(): Promise<void> {
    const { rows } = await pool.query<RuleRow>(
      `SELECT id, event_type, conditions, severity, channels, throttle_secs
         FROM aegis.alert_rules WHERE enabled = true`,
    );
    this.rules = rows;
  }

  private throttled(rule: RuleRow): boolean {
    if (!rule.throttle_secs) return false;
    const last = this.lastFired.get(rule.id);
    return last !== undefined && Date.now() - last < rule.throttle_secs * 1000;
  }

  private async onEvent(raw: string): Promise<void> {
    let event: DomainEvent;
    try {
      event = JSON.parse(raw) as DomainEvent;
    } catch {
      return; // ignore malformed events
    }
    // The engine only reacts to domain events, not to its own alert.* emissions.
    if (!event.type || event.type.startsWith('alert.')) return;

    for (const rule of this.rules) {
      if (!matchRule(event, rule)) continue;
      if (this.throttled(rule)) continue;
      this.lastFired.set(rule.id, Date.now());
      await this.raiseAndDispatch(event, rule);
    }
  }

  private async raiseAndDispatch(event: DomainEvent, rule: RuleRow): Promise<void> {
    const severity: Severity = rule.severity ?? event.severity ?? 'medium';
    const title = alertTitle(event);
    const body = typeof event.description === 'string' ? event.description : '';

    const { rows } = await pool.query<{ id: string; is_new: boolean }>(
      `SELECT * FROM aegis.raise_alert($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        rule.id, title, body, severity,
        event.source ?? null,
        entityType(event.type), event.id ?? event.value ?? null,
        dedupeKey(rule, event),
        JSON.stringify(event),
      ],
    );
    const { id: alertId, is_new: isNew } = rows[0];

    // Only notify on the first occurrence; deduped repeats stay quiet.
    if (!isNew) return;

    await publish('events', { type: 'alert.new', id: alertId, severity, title });

    const msg: AlertMessage = {
      id: alertId,
      title,
      body,
      severity,
      source: event.source ?? null,
      entityType: entityType(event.type),
      entityId: event.id ?? event.value ?? null,
      url: alertUrl(alertId),
      metadata: event,
      createdAt: new Date().toISOString(),
    };

    const outcomes = await dispatchToChannels(pool, alertId, msg, rule.channels ?? []);
    const failed = outcomes.filter((o) => !o.ok);
    if (failed.length) {
      this.log.warn({ alertId, failed }, 'some alert channels failed');
    }
  }
}

/** Map an event type to the alert entity_type column. */
function entityType(eventType: string): string {
  return eventType.split('.')[0] ?? 'event';
}

/** Construct + start the engine; returns a stop handle. */
export async function startAlertEngine(log: FastifyBaseLogger): Promise<AlertEngine> {
  const engine = new AlertEngine(log);
  await engine.start();
  return engine;
}
