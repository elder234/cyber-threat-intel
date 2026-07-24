/**
 * Channel senders. Each takes a channel `config` (from
 * aegis.notification_channels.config) plus the formatted [`AlertMessage`] and
 * performs the delivery, returning a [`DeliveryResult`].
 *
 * Chat/webhook channels use the global `fetch` (Node ≥ 20 — zero deps). Email
 * uses nodemailer with SMTP settings from the environment.
 *
 * ⚠️ RUNTIME VERIFICATION REQUIRED — network + SMTP paths are unverified (VM offline).
 */

import { config } from '../../config.js';
import {
  type AlertMessage,
  formatDiscord, formatEmail, formatSlack, formatTelegram, formatWebhook,
} from './format.js';

export interface DeliveryResult {
  ok: boolean;
  error?: string;
}

const TIMEOUT_MS = 10_000;

/** POST JSON with a hard timeout; returns a normalized result. */
async function postJson(url: string, payload: unknown, headers?: Record<string, string>): Promise<DeliveryResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 300);
      return { ok: false, error: `HTTP ${res.status}${detail ? `: ${detail}` : ''}` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

type ChannelConfig = Record<string, unknown>;
const str = (c: ChannelConfig, k: string): string | undefined =>
  typeof c[k] === 'string' && (c[k] as string).length ? (c[k] as string) : undefined;

export async function sendSlack(cfg: ChannelConfig, m: AlertMessage): Promise<DeliveryResult> {
  const url = str(cfg, 'url');
  if (!url) return { ok: false, error: 'slack channel missing config.url' };
  return postJson(url, formatSlack(m));
}

export async function sendDiscord(cfg: ChannelConfig, m: AlertMessage): Promise<DeliveryResult> {
  const url = str(cfg, 'url');
  if (!url) return { ok: false, error: 'discord channel missing config.url' };
  return postJson(url, formatDiscord(m));
}

export async function sendWebhook(cfg: ChannelConfig, m: AlertMessage): Promise<DeliveryResult> {
  const url = str(cfg, 'url');
  if (!url) return { ok: false, error: 'webhook channel missing config.url' };
  // Optional shared-secret header for the receiver to verify authenticity.
  const secret = str(cfg, 'secret');
  return postJson(url, formatWebhook(m), secret ? { 'x-aegis-signature': secret } : undefined);
}

export async function sendTelegram(cfg: ChannelConfig, m: AlertMessage): Promise<DeliveryResult> {
  const token = str(cfg, 'bot_token') ?? config.TELEGRAM_BOT_TOKEN;
  const chatId = str(cfg, 'chat_id');
  if (!token) return { ok: false, error: 'telegram missing bot_token (config or TELEGRAM_BOT_TOKEN)' };
  if (!chatId) return { ok: false, error: 'telegram channel missing config.chat_id' };
  const body = { chat_id: chatId, ...formatTelegram(m) };
  return postJson(`https://api.telegram.org/bot${token}/sendMessage`, body);
}

export async function sendEmail(cfg: ChannelConfig, m: AlertMessage): Promise<DeliveryResult> {
  if (!config.SMTP_HOST) return { ok: false, error: 'email disabled: SMTP_HOST not configured' };
  const to = Array.isArray(cfg.to) ? (cfg.to as string[]) : str(cfg, 'to') ? [str(cfg, 'to')!] : [];
  if (!to.length) return { ok: false, error: 'email channel missing config.to' };

  let nodemailer: typeof import('nodemailer');
  try {
    nodemailer = await import('nodemailer');
  } catch {
    return { ok: false, error: 'email disabled: nodemailer not installed' };
  }

  const { subject, text, html } = formatEmail(m);
  try {
    const transport = nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_PORT === 465,
      auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined,
    });
    await transport.sendMail({
      from: str(cfg, 'from') ?? config.SMTP_FROM,
      to,
      subject,
      text,
      html,
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
