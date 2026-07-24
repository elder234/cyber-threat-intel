import clsx from 'clsx';
import type { Severity } from './types';

// Fixed severity → Tailwind class maps. Severity color is deliberate and never
// reused for decoration elsewhere in the UI, so an operator can trust color.

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_TEXT: Record<Severity, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
};

const SEV_DOT: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

// Chips use a translucent tint of the severity color on a dark chip.
const SEV_CHIP: Record<Severity, string> = {
  critical: 'bg-sev-critical/15 text-sev-critical ring-1 ring-inset ring-sev-critical/30',
  high: 'bg-sev-high/15 text-sev-high ring-1 ring-inset ring-sev-high/30',
  medium: 'bg-sev-medium/15 text-sev-medium ring-1 ring-inset ring-sev-medium/30',
  low: 'bg-sev-low/15 text-sev-low ring-1 ring-inset ring-sev-low/30',
  info: 'bg-sev-info/15 text-sev-info ring-1 ring-inset ring-sev-info/30',
};

export function sevText(sev: Severity): string {
  return SEV_TEXT[sev] ?? SEV_TEXT.info;
}
export function sevDot(sev: Severity): string {
  return SEV_DOT[sev] ?? SEV_DOT.info;
}
export function sevChip(sev: Severity): string {
  return SEV_CHIP[sev] ?? SEV_CHIP.info;
}

/** Hex values for non-Tailwind consumers (map fills, chart series, SVG). */
export const SEV_HEX: Record<Severity, string> = {
  critical: '#ff4d6d',
  high: '#ff8c42',
  medium: '#f5c518',
  low: '#4cc9f0',
  info: '#7d8fa1',
};

/** Map a 0–100 risk score to a severity band + label. */
export function riskBand(score: number): { sev: Severity; label: string } {
  if (score >= 80) return { sev: 'critical', label: 'Critical' };
  if (score >= 60) return { sev: 'high', label: 'Elevated' };
  if (score >= 40) return { sev: 'medium', label: 'Guarded' };
  if (score >= 20) return { sev: 'low', label: 'Low' };
  return { sev: 'info', label: 'Nominal' };
}

/** Compact relative time ("3m", "2h", "5d") for dense tables/timelines. */
export function relTime(iso: string | number | Date): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo`;
  return `${Math.floor(months / 12)}y`;
}

export function fmtNum(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  return new Intl.NumberFormat('en-US').format(n);
}

export { clsx };
