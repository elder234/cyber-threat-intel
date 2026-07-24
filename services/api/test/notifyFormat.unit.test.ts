import { describe, it, expect } from 'vitest';
import {
  summaryLine, formatSlack, formatDiscord, formatTelegram, formatWebhook, formatEmail,
  severityAtLeast, type AlertMessage,
} from '../src/lib/notify/format.js';

function msg(over: Partial<AlertMessage> = {}): AlertMessage {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    title: 'Malicious IP observed',
    body: 'Host 1.2.3.4 flagged by 3 sources.',
    severity: 'high',
    source: 'otx',
    entityType: 'ioc',
    entityId: '1.2.3.4',
    url: 'http://localhost:8080/alerts?focus=11111111-1111-1111-1111-111111111111',
    createdAt: '2026-07-22T00:00:00.000Z',
    ...over,
  };
}

describe('severityAtLeast', () => {
  it('orders severities', () => {
    expect(severityAtLeast('critical', 'high')).toBe(true);
    expect(severityAtLeast('low', 'high')).toBe(false);
    expect(severityAtLeast('medium', 'medium')).toBe(true);
  });
});

describe('summaryLine', () => {
  it('prefixes an uppercased severity tag', () => {
    expect(summaryLine(msg())).toBe('[HIGH] Malicious IP observed');
  });
});

describe('formatSlack', () => {
  it('produces fallback text plus blocks', () => {
    const p = formatSlack(msg()) as { text: string; blocks: unknown[] };
    expect(p.text).toBe('[HIGH] Malicious IP observed');
    expect(Array.isArray(p.blocks)).toBe(true);
    // header + body section + fields section + actions (url present)
    expect(p.blocks.length).toBe(4);
  });
  it('omits the actions block when there is no url', () => {
    const p = formatSlack(msg({ url: null })) as { blocks: Array<{ type: string }> };
    expect(p.blocks.some((b) => b.type === 'actions')).toBe(false);
  });
});

describe('formatDiscord', () => {
  it('emits a single embed with severity color', () => {
    const p = formatDiscord(msg()) as { embeds: Array<{ title: string; color: number; fields: unknown[] }> };
    expect(p.embeds).toHaveLength(1);
    expect(p.embeds[0].title).toBe('Malicious IP observed');
    expect(typeof p.embeds[0].color).toBe('number');
    expect(p.embeds[0].fields.length).toBeGreaterThanOrEqual(1);
  });
});

describe('formatTelegram', () => {
  it('uses HTML parse mode and escapes markup', () => {
    const p = formatTelegram(msg({ title: 'a<b>&c' }));
    expect(p.parse_mode).toBe('HTML');
    expect(p.disable_web_page_preview).toBe(true);
    expect(p.text).toContain('a&lt;b&gt;&amp;c');
    expect(p.text).toContain('<b>');
  });
});

describe('formatWebhook', () => {
  it('emits a stable machine-readable envelope', () => {
    const p = formatWebhook(msg()) as Record<string, unknown>;
    expect(p.type).toBe('aegis.alert');
    expect(p.id).toBe('11111111-1111-1111-1111-111111111111');
    expect(p.severity).toBe('high');
    expect(p.entity).toEqual({ type: 'ioc', id: '1.2.3.4' });
    expect(p.created_at).toBe('2026-07-22T00:00:00.000Z');
  });
  it('nulls entity when incomplete', () => {
    const p = formatWebhook(msg({ entityId: null })) as Record<string, unknown>;
    expect(p.entity).toBeNull();
  });
});

describe('formatEmail', () => {
  it('builds subject, text and html', () => {
    const p = formatEmail(msg());
    expect(p.subject).toBe('[Aegis][HIGH] Malicious IP observed');
    expect(p.text).toContain('Malicious IP observed');
    expect(p.text).toContain('Open: http://localhost:8080/alerts');
    expect(p.html).toContain('<h2');
    expect(p.html).toContain('Open in Aegis');
  });
  it('escapes HTML in the body', () => {
    const p = formatEmail(msg({ body: '<script>alert(1)</script>' }));
    expect(p.html).not.toContain('<script>');
    expect(p.html).toContain('&lt;script&gt;');
  });
});
