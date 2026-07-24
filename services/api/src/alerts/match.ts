/**
 * Alert rule matching (pure, unit-tested).
 *
 * The engine receives domain events on the Redis `events` channel and tests them
 * against enabled `alert_rules`. Matching is intentionally simple and declarative
 * so rules can be authored as JSON without code changes.
 */

import { type Severity, severityAtLeast } from '../lib/notify/format.js';

/** A domain event as published to Redis by the API/worker. */
export interface DomainEvent {
  type: string;                 // 'ioc.new', 'cve.kev', 'scan.finding', ...
  id?: string;
  severity?: Severity;
  value?: string;
  source?: string;
  tags?: string[];
  [k: string]: unknown;
}

/** The subset of an alert_rules row the matcher needs. */
export interface RuleSpec {
  id: string;
  event_type: string;
  conditions: RuleConditions;
  severity: Severity;           // severity stamped on raised alerts
}

/** Declarative condition block (all present clauses must pass — logical AND). */
export interface RuleConditions {
  min_severity?: Severity;
  tags_any?: string[];          // event.tags intersects this set
  tags_all?: string[];          // event.tags is a superset of this set
  sources?: string[];           // event.source ∈ this set
  value_regex?: string;         // event.value matches
}

/** True when the event satisfies every clause present in the rule. */
export function matchRule(event: DomainEvent, rule: RuleSpec): boolean {
  if (rule.event_type !== event.type) return false;
  const c = rule.conditions ?? {};

  if (c.min_severity) {
    if (!event.severity || !severityAtLeast(event.severity, c.min_severity)) return false;
  }
  if (c.sources && c.sources.length) {
    if (!event.source || !c.sources.includes(event.source)) return false;
  }
  if (c.tags_any && c.tags_any.length) {
    const tags = event.tags ?? [];
    if (!c.tags_any.some((t) => tags.includes(t))) return false;
  }
  if (c.tags_all && c.tags_all.length) {
    const tags = new Set(event.tags ?? []);
    if (!c.tags_all.every((t) => tags.has(t))) return false;
  }
  if (c.value_regex) {
    try {
      if (!event.value || !new RegExp(c.value_regex, 'i').test(event.value)) return false;
    } catch {
      // A malformed regex condition never matches (and shouldn't throw).
      return false;
    }
  }
  return true;
}

/** Stable dedupe key so repeated events collapse onto one open alert. */
export function dedupeKey(rule: RuleSpec, event: DomainEvent): string {
  return `${rule.id}:${event.type}:${event.id ?? event.value ?? 'na'}`;
}

/** Human title for a raised alert. */
export function alertTitle(event: DomainEvent): string {
  switch (event.type) {
    case 'ioc.new': return `New ${event.severity ?? ''} indicator: ${event.value ?? event.id}`.trim();
    case 'cve.kev': return `KEV-listed vulnerability: ${event.value ?? event.id}`;
    case 'scan.finding': return `Scan finding: ${event.value ?? event.id}`;
    default: return `${event.type}: ${event.value ?? event.id ?? ''}`.trim();
  }
}
