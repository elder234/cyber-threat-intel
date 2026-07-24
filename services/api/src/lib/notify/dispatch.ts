/**
 * Dispatch a raised alert to all channels named on its rule.
 *
 * Resolves each channel name to a `notification_channels` row, applies the
 * channel's `min_severity` gate, sends via the matching transport, and records
 * a `notifications` row per attempt. Channel failures are isolated — one broken
 * webhook never blocks the others.
 */

import type { Pool } from 'pg';
import {
  type AlertMessage, type ChannelType, type Severity, severityAtLeast,
} from './format.js';
import {
  type DeliveryResult,
  sendDiscord, sendEmail, sendSlack, sendTelegram, sendWebhook,
} from './send.js';
import { config } from '../../config.js';

interface ChannelRow {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: Record<string, unknown>;
  min_severity: Severity;
}

const SENDERS: Record<ChannelType, (cfg: Record<string, unknown>, m: AlertMessage) => Promise<DeliveryResult>> = {
  slack: sendSlack,
  discord: sendDiscord,
  telegram: sendTelegram,
  webhook: sendWebhook,
  email: sendEmail,
};

/** Build the deep link to an alert in the web console. */
export function alertUrl(alertId: string): string {
  const base = config.API_PUBLIC_URL.replace(/\/$/, '');
  return `${base}/alerts?focus=${alertId}`;
}

/**
 * Deliver `msg` to the given channel names. Returns per-channel outcomes.
 * `channelNames` typically comes from alert_rules.channels. Pass `alertId: null`
 * for ad-hoc test sends that should not be tied to a persisted alert row.
 */
export async function dispatchToChannels(
  pool: Pool,
  alertId: string | null,
  msg: AlertMessage,
  channelNames: string[],
): Promise<Array<{ channel: string; ok: boolean; error?: string }>> {
  if (!channelNames.length) return [];

  const { rows } = await pool.query<ChannelRow>(
    `SELECT id, name, type, enabled, config, min_severity
       FROM aegis.notification_channels
      WHERE name = ANY($1) AND enabled = true`,
    [channelNames],
  );

  const results = await Promise.all(rows.map(async (ch) => {
    // Severity gate per channel.
    if (!severityAtLeast(msg.severity, ch.min_severity)) {
      return { channel: ch.name, ok: true, skipped: true as const };
    }
    const send = SENDERS[ch.type];
    const res = send
      ? await send(ch.config ?? {}, msg)
      : { ok: false, error: `no sender for channel type ${ch.type}` };

    // Record the attempt (skipped for ad-hoc test sends with no alert row).
    if (alertId) {
      await pool.query(
        `INSERT INTO aegis.notifications(alert_id, channel, status, attempts, error, sent_at)
         VALUES ($1, $2, $3, 1, $4, $5)`,
        [alertId, ch.name, res.ok ? 'sent' : 'failed', res.error ?? null, res.ok ? new Date() : null],
      );
    }

    // Track channel health.
    if (res.ok) {
      await pool.query('UPDATE aegis.notification_channels SET last_ok_at = now(), last_error = NULL WHERE id = $1', [ch.id]);
    } else {
      await pool.query('UPDATE aegis.notification_channels SET last_error = $2 WHERE id = $1', [ch.id, res.error ?? 'unknown']);
    }
    return { channel: ch.name, ok: res.ok, error: res.error };
  }));

  return results.map((r) => ({ channel: r.channel, ok: r.ok, error: 'error' in r ? r.error : undefined }));
}
