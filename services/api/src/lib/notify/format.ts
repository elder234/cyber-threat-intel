/**
 * Channel-agnostic alert message + per-channel payload formatting.
 *
 * Formatters are pure (no I/O) so they can be unit-tested without network or
 * SMTP. The senders in ./send.ts consume these payloads.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type ChannelType = 'email' | 'slack' | 'discord' | 'telegram' | 'webhook';

/** Normalized alert passed to every channel. */
export interface AlertMessage {
  id: string;
  title: string;
  body: string;
  severity: Severity;
  source?: string | null;
  entityType?: string | null;
  entityId?: string | null;
  url?: string | null; // deep link into the console
  metadata?: Record<string, unknown>;
  createdAt?: string;
}

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/** True when `sev` is at or above `floor`. */
export function severityAtLeast(sev: Severity, floor: Severity): boolean {
  return SEVERITY_RANK[sev] >= SEVERITY_RANK[floor];
}

// Severity → emoji/hex accent, reused across chat channels.
const SEVERITY_EMOJI: Record<Severity, string> = {
  info: '⚪', low: '🔵', medium: '🟡', high: '🟠', critical: '🔴',
};
const SEVERITY_HEX: Record<Severity, number> = {
  info: 0x7d8fa1, low: 0x4cc9f0, medium: 0xf5c518, high: 0xff8c42, critical: 0xff4d6d,
};

function line(label: string, value?: string | null): string {
  return value ? `${label}: ${value}` : '';
}

/** Compact one-line summary used in webhook/telegram/subject contexts. */
export function summaryLine(m: AlertMessage): string {
  return `[${m.severity.toUpperCase()}] ${m.title}`;
}

/** Slack Incoming-Webhook payload (Block Kit). */
export function formatSlack(m: AlertMessage): unknown {
  const fields = [
    line('*Severity*', `${SEVERITY_EMOJI[m.severity]} ${m.severity}`),
    line('*Source*', m.source),
    line('*Entity*', m.entityType && m.entityId ? `${m.entityType} \`${m.entityId}\`` : null),
  ].filter(Boolean);

  const blocks: unknown[] = [
    { type: 'header', text: { type: 'plain_text', text: `${SEVERITY_EMOJI[m.severity]} ${m.title}`.slice(0, 150) } },
  ];
  if (m.body) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: m.body.slice(0, 2900) } });
  if (fields.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: fields.join('\n') } });
  if (m.url) {
    blocks.push({
      type: 'actions',
      elements: [{ type: 'button', text: { type: 'plain_text', text: 'Open in Aegis' }, url: m.url }],
    });
  }
  return { text: summaryLine(m), blocks };
}

/** Discord webhook payload (embeds). */
export function formatDiscord(m: AlertMessage): unknown {
  const embedFields = [
    { name: 'Severity', value: `${SEVERITY_EMOJI[m.severity]} ${m.severity}`, inline: true },
    m.source ? { name: 'Source', value: m.source, inline: true } : null,
    m.entityType && m.entityId ? { name: 'Entity', value: `${m.entityType} \`${m.entityId}\``, inline: false } : null,
  ].filter(Boolean);

  return {
    username: 'Aegis CTI',
    embeds: [{
      title: m.title.slice(0, 250),
      description: (m.body || '').slice(0, 4000),
      url: m.url ?? undefined,
      color: SEVERITY_HEX[m.severity],
      fields: embedFields,
      timestamp: m.createdAt ?? new Date().toISOString(),
      footer: { text: m.source ? `source: ${m.source}` : 'Aegis CTI' },
    }],
  };
}

/** Telegram sendMessage body (HTML parse mode). Chat id filled by the sender. */
export function formatTelegram(m: AlertMessage): { text: string; parse_mode: 'HTML'; disable_web_page_preview: boolean } {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const parts = [
    `${SEVERITY_EMOJI[m.severity]} <b>${esc(m.title)}</b>`,
    m.body ? esc(m.body) : '',
    line('Severity', m.severity),
    line('Source', m.source ? esc(m.source) : null),
    m.entityType && m.entityId ? `Entity: ${esc(m.entityType)} <code>${esc(m.entityId)}</code>` : '',
    m.url ? `<a href="${m.url}">Open in Aegis</a>` : '',
  ].filter(Boolean);
  return { text: parts.join('\n'), parse_mode: 'HTML', disable_web_page_preview: true };
}

/** Generic webhook payload — stable, machine-readable envelope. */
export function formatWebhook(m: AlertMessage): unknown {
  return {
    type: 'aegis.alert',
    id: m.id,
    title: m.title,
    body: m.body,
    severity: m.severity,
    source: m.source ?? null,
    entity: m.entityType && m.entityId ? { type: m.entityType, id: m.entityId } : null,
    url: m.url ?? null,
    metadata: m.metadata ?? {},
    created_at: m.createdAt ?? new Date().toISOString(),
  };
}

/** Email subject + plaintext/HTML bodies. */
export function formatEmail(m: AlertMessage): { subject: string; text: string; html: string } {
  const subject = `[Aegis][${m.severity.toUpperCase()}] ${m.title}`;
  const rows = [
    line('Severity', m.severity),
    line('Source', m.source),
    line('Entity', m.entityType && m.entityId ? `${m.entityType} ${m.entityId}` : null),
    line('Alert ID', m.id),
  ].filter(Boolean);

  const text = [m.title, '', m.body, '', ...rows, m.url ? `\nOpen: ${m.url}` : ''].join('\n');

  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:600px">
      <h2 style="margin:0 0 4px">${SEVERITY_EMOJI[m.severity]} ${esc(m.title)}</h2>
      <p style="color:#444;white-space:pre-wrap">${esc(m.body || '')}</p>
      <table style="border-collapse:collapse;font-size:14px">
        ${rows.map((r) => `<tr><td style="padding:2px 8px">${esc(r)}</td></tr>`).join('')}
      </table>
      ${m.url ? `<p><a href="${m.url}">Open in Aegis</a></p>` : ''}
    </div>`.trim();

  return { subject, text, html };
}
