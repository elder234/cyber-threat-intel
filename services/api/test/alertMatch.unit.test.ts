import { describe, it, expect } from 'vitest';
import {
  matchRule, dedupeKey, alertTitle,
  type DomainEvent, type RuleSpec,
} from '../src/alerts/match.js';
import { severityAtLeast } from '../src/lib/notify/format.js';

/** Build a rule with sensible defaults, overriding as needed. */
function rule(over: Partial<RuleSpec> = {}): RuleSpec {
  return {
    id: 'r1',
    event_type: 'ioc.new',
    conditions: {},
    severity: 'medium',
    ...over,
  };
}

describe('severityAtLeast', () => {
  it('is inclusive at the floor', () => {
    expect(severityAtLeast('high', 'high')).toBe(true);
  });
  it('ranks correctly', () => {
    expect(severityAtLeast('critical', 'low')).toBe(true);
    expect(severityAtLeast('info', 'medium')).toBe(false);
  });
});

describe('matchRule — event type gate', () => {
  it('rejects a mismatched event type', () => {
    const ev: DomainEvent = { type: 'cve.new' };
    expect(matchRule(ev, rule({ event_type: 'ioc.new' }))).toBe(false);
  });
  it('matches when type agrees and no conditions', () => {
    const ev: DomainEvent = { type: 'ioc.new' };
    expect(matchRule(ev, rule())).toBe(true);
  });
});

describe('matchRule — min_severity', () => {
  it('passes at or above the floor', () => {
    const ev: DomainEvent = { type: 'ioc.new', severity: 'high' };
    expect(matchRule(ev, rule({ conditions: { min_severity: 'medium' } }))).toBe(true);
  });
  it('fails below the floor', () => {
    const ev: DomainEvent = { type: 'ioc.new', severity: 'low' };
    expect(matchRule(ev, rule({ conditions: { min_severity: 'high' } }))).toBe(false);
  });
  it('fails when the event carries no severity', () => {
    const ev: DomainEvent = { type: 'ioc.new' };
    expect(matchRule(ev, rule({ conditions: { min_severity: 'low' } }))).toBe(false);
  });
});

describe('matchRule — sources', () => {
  it('passes when source is in the allow-list', () => {
    const ev: DomainEvent = { type: 'ioc.new', source: 'otx' };
    expect(matchRule(ev, rule({ conditions: { sources: ['otx', 'abuseipdb'] } }))).toBe(true);
  });
  it('fails when source is absent or not listed', () => {
    expect(matchRule({ type: 'ioc.new', source: 'misp' }, rule({ conditions: { sources: ['otx'] } }))).toBe(false);
    expect(matchRule({ type: 'ioc.new' }, rule({ conditions: { sources: ['otx'] } }))).toBe(false);
  });
});

describe('matchRule — tags_any / tags_all', () => {
  it('tags_any requires an intersection', () => {
    const r = rule({ conditions: { tags_any: ['c2', 'phishing'] } });
    expect(matchRule({ type: 'ioc.new', tags: ['phishing'] }, r)).toBe(true);
    expect(matchRule({ type: 'ioc.new', tags: ['benign'] }, r)).toBe(false);
    expect(matchRule({ type: 'ioc.new' }, r)).toBe(false);
  });
  it('tags_all requires a superset', () => {
    const r = rule({ conditions: { tags_all: ['c2', 'malware'] } });
    expect(matchRule({ type: 'ioc.new', tags: ['c2', 'malware', 'x'] }, r)).toBe(true);
    expect(matchRule({ type: 'ioc.new', tags: ['c2'] }, r)).toBe(false);
  });
});

describe('matchRule — value_regex', () => {
  it('matches case-insensitively', () => {
    const r = rule({ conditions: { value_regex: '\\.ru$' } });
    expect(matchRule({ type: 'ioc.new', value: 'evil.RU' }, r)).toBe(true);
    expect(matchRule({ type: 'ioc.new', value: 'good.com' }, r)).toBe(false);
  });
  it('a malformed regex never matches and never throws', () => {
    const r = rule({ conditions: { value_regex: '(' } });
    expect(() => matchRule({ type: 'ioc.new', value: 'x' }, r)).not.toThrow();
    expect(matchRule({ type: 'ioc.new', value: 'x' }, r)).toBe(false);
  });
  it('fails when the event has no value', () => {
    const r = rule({ conditions: { value_regex: 'x' } });
    expect(matchRule({ type: 'ioc.new' }, r)).toBe(false);
  });
});

describe('matchRule — combined clauses are ANDed', () => {
  it('all clauses must pass', () => {
    const r = rule({ conditions: { min_severity: 'high', tags_any: ['c2'], sources: ['otx'] } });
    const good: DomainEvent = { type: 'ioc.new', severity: 'critical', tags: ['c2'], source: 'otx' };
    expect(matchRule(good, r)).toBe(true);
    // one clause off → no match
    expect(matchRule({ ...good, source: 'misp' }, r)).toBe(false);
    expect(matchRule({ ...good, severity: 'low' }, r)).toBe(false);
  });
});

describe('dedupeKey', () => {
  it('prefers event id, falls back to value, then na', () => {
    expect(dedupeKey(rule(), { type: 'ioc.new', id: 'abc' })).toBe('r1:ioc.new:abc');
    expect(dedupeKey(rule(), { type: 'ioc.new', value: 'evil.ru' })).toBe('r1:ioc.new:evil.ru');
    expect(dedupeKey(rule(), { type: 'ioc.new' })).toBe('r1:ioc.new:na');
  });
});

describe('alertTitle', () => {
  it('formats known event types', () => {
    expect(alertTitle({ type: 'ioc.new', severity: 'high', value: '1.2.3.4' }))
      .toBe('New high indicator: 1.2.3.4');
    expect(alertTitle({ type: 'cve.kev', value: 'CVE-2024-1' }))
      .toBe('KEV-listed vulnerability: CVE-2024-1');
    expect(alertTitle({ type: 'scan.finding', value: 'open:22' }))
      .toBe('Scan finding: open:22');
  });
  it('falls back for unknown types', () => {
    expect(alertTitle({ type: 'feed.error', value: 'nvd' })).toBe('feed.error: nvd');
  });
});
