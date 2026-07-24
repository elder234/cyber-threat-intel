import type { ReactNode } from 'react';
import { clsx, sevChip, sevDot } from '../lib/ui';
import type { Severity } from '../lib/types';

/** Panel — the base container for every widget on the console. */
export function Panel({
  title, action, className, bodyClassName, children,
}: {
  title?: ReactNode;
  action?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}): JSX.Element {
  return (
    <section className={clsx('panel flex flex-col', className)}>
      {(title || action) && (
        <header className="panel-header">
          <h2 className="panel-title">{title}</h2>
          {action}
        </header>
      )}
      <div className={clsx('min-h-0 flex-1', bodyClassName ?? 'p-4')}>{children}</div>
    </section>
  );
}

export function SeverityChip({ severity, className }: { severity: Severity; className?: string }): JSX.Element {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
        sevChip(severity), className,
      )}
    >
      <span className={clsx('h-1.5 w-1.5 rounded-full', sevDot(severity))} />
      {severity}
    </span>
  );
}

export function StatusPill({ status }: { status: string }): JSX.Element {
  const tone = ({
    open: 'bg-sev-high/15 text-sev-high ring-sev-high/30',
    running: 'bg-signal/15 text-signal ring-signal/30',
    queued: 'bg-base-700 text-ink-dim ring-base-500',
    acknowledged: 'bg-sev-low/15 text-sev-low ring-sev-low/30',
    completed: 'bg-good/15 text-good ring-good/30',
    resolved: 'bg-good/15 text-good ring-good/30',
    failed: 'bg-sev-critical/15 text-sev-critical ring-sev-critical/30',
    suppressed: 'bg-base-700 text-ink-faint ring-base-500',
  } as Record<string, string>)[status] ?? 'bg-base-700 text-ink-dim ring-base-500';
  return (
    <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ring-1 ring-inset', tone)}>
      {status}
    </span>
  );
}

export function Spinner({ label }: { label?: string }): JSX.Element {
  return (
    <div className="flex items-center justify-center gap-3 py-10 text-ink-faint">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-base-500 border-t-signal" />
      {label && <span className="font-mono text-xs uppercase tracking-widest">{label}</span>}
    </div>
  );
}

export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: string }): JSX.Element {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      {icon && <div className="text-ink-faint">{icon}</div>}
      <p className="font-display text-sm text-ink-dim">{title}</p>
      {hint && <p className="max-w-xs text-xs text-ink-faint">{hint}</p>}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }): JSX.Element {
  const msg = error instanceof Error ? error.message : 'Request failed';
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-10 text-center">
      <p className="font-mono text-xs uppercase tracking-widest text-sev-critical">{msg}</p>
      {retry && (
        <button
          onClick={retry}
          className="rounded border border-base-500 px-3 py-1 text-xs text-ink-dim transition hover:border-signal hover:text-signal"
        >
          Retry
        </button>
      )}
    </div>
  );
}

/** A single KPI tile for the dashboard header row. */
export function StatTile({
  label, value, sub, accent, live,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: string;
  live?: boolean;
}): JSX.Element {
  return (
    <div className="panel relative overflow-hidden px-4 py-3">
      {live && (
        <span className="absolute right-3 top-3 h-2 w-2 animate-pulse-ring rounded-full bg-signal" />
      )}
      <p className="eyebrow">{label}</p>
      <p className={clsx('data mt-1 text-2xl font-bold leading-none', accent ?? 'text-ink')}>{value}</p>
      {sub && <p className="mt-1 text-xs text-ink-faint">{sub}</p>}
    </div>
  );
}
