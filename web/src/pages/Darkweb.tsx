import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../lib/api';
import { useHasPerm } from '../lib/auth';
import { clsx, relTime } from '../lib/ui';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner } from '../components/primitives';
import { PageHeader } from './Iocs';
import type {
  DarkwebHit, DarkwebHitStatus, DarkwebSource, Severity, WatchEntry, WatchKind,
} from '../lib/types';

const WATCH_KINDS: { value: WatchKind; label: string }[] = [
  { value: 'domain', label: 'Domain' },
  { value: 'email', label: 'Email' },
  { value: 'keyword', label: 'Keyword' },
  { value: 'brand', label: 'Brand' },
  { value: 'bin', label: 'Card BIN' },
];
const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const HIT_STATUS: { value: DarkwebHitStatus; label: string }[] = [
  { value: 'new', label: 'New' },
  { value: 'reviewed', label: 'Reviewed' },
  { value: 'actioned', label: 'Actioned' },
  { value: 'false_positive', label: 'False positive' },
];

export default function DarkwebPage(): JSX.Element {
  const canWrite = useHasPerm('watchlist:write');
  return (
    <div className="space-y-4">
      <PageHeader
        title="Dark-web Monitor"
        subtitle="Module 12 · read-only · Tor-routed · snippets redacted before storage"
      />
      <HitsPanel />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <WatchlistPanel canWrite={canWrite} />
        <SourcesPanel />
      </div>
    </div>
  );
}

// PLACEHOLDER_REST

// ── Hits ──────────────────────────────────────────────────────────────────────
function HitsPanel(): JSX.Element {
  const qc = useQueryClient();
  const canWrite = useHasPerm('watchlist:write');
  const query = useQuery({ queryKey: ['darkweb-hits'], queryFn: () => api.darkweb.hits(100) });
  const hits = query.data?.data ?? [];

  const triage = useMutation({
    mutationFn: ({ id, status }: { id: string; status: DarkwebHitStatus }) => api.darkweb.triageHit(id, status),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['darkweb-hits'] }),
  });

  return (
    <Panel title="Exposure hits" bodyClassName="p-0">
      {query.isLoading ? <Spinner label="Loading hits" />
        : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
        : hits.length === 0
          ? <EmptyState title="No exposure detected" hint="Watchlisted values have not been seen on any monitored source." />
          : (
            <ul className="divide-y divide-base-700">
              {hits.map((h) => (
                <HitRow key={h.id} h={h} canWrite={canWrite}
                  onTriage={(status) => triage.mutate({ id: h.id, status })} />
              ))}
            </ul>
          )}
    </Panel>
  );
}

function HitRow({ h, canWrite, onTriage }: {
  h: DarkwebHit; canWrite: boolean; onTriage: (s: DarkwebHitStatus) => void;
}): JSX.Element {
  return (
    <li className="px-4 py-3">
      <div className="flex items-start gap-3">
        <SeverityChip severity={h.severity} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-mono text-sm text-ink">{h.matched_value}</span>
            <span className="font-mono text-[10px] uppercase tracking-wide text-ink-faint">{h.source_name}</span>
            <span className="font-mono text-[10px] text-ink-faint">{relTime(h.observed_at)}</span>
          </div>
          {h.snippet && (
            <p className="mt-1 break-words rounded border border-base-700 bg-base-900/50 px-2 py-1 font-mono text-[11px] leading-relaxed text-ink-dim">
              {h.snippet}
            </p>
          )}
          <p className="mt-1 break-all font-mono text-[10px] text-ink-faint">{h.url}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <HitStatusBadge status={h.status} />
          {canWrite && (
            <select
              value={h.status}
              onChange={(e) => onTriage(e.target.value as DarkwebHitStatus)}
              className="rounded border border-base-600 bg-base-800 px-1.5 py-0.5 font-mono text-[10px] text-ink-dim"
            >
              {HIT_STATUS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          )}
        </div>
      </div>
    </li>
  );
}

function HitStatusBadge({ status }: { status: DarkwebHitStatus }): JSX.Element {
  const tone = status === 'new' ? 'bg-signal/15 text-signal'
    : status === 'actioned' ? 'bg-good/15 text-good'
    : status === 'false_positive' ? 'bg-base-700 text-ink-faint'
    : 'bg-base-700 text-ink-dim';
  const label = HIT_STATUS.find((s) => s.value === status)?.label ?? status;
  return <span className={clsx('rounded px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide', tone)}>{label}</span>;
}

// ── Watchlist ────────────────────────────────────────────────────────────────
function WatchlistPanel({ canWrite }: { canWrite: boolean }): JSX.Element {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ['darkweb-watchlist'], queryFn: () => api.darkweb.watchlist() });
  const entries = query.data?.data ?? [];
  const invalidate = () => qc.invalidateQueries({ queryKey: ['darkweb-watchlist'] });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.darkweb.updateWatch(id, { enabled }),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.darkweb.removeWatch(id),
    onSuccess: invalidate,
  });

  return (
    <Panel title="Watchlist" bodyClassName="p-0">
      {canWrite && <WatchForm onCreated={invalidate} />}
      {query.isLoading ? <Spinner label="Loading watchlist" />
        : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
        : entries.length === 0
          ? <EmptyState title="Nothing watched" hint={canWrite ? 'Add a domain, email, brand or BIN above.' : 'No watchlist entries.'} />
          : (
            <ul className="divide-y divide-base-700">
              {entries.map((w) => (
                <WatchRow key={w.id} w={w} canWrite={canWrite}
                  onToggle={() => toggle.mutate({ id: w.id, enabled: !w.enabled })}
                  onRemove={() => remove.mutate(w.id)} />
              ))}
            </ul>
          )}
    </Panel>
  );
}

function WatchRow({ w, canWrite, onToggle, onRemove }: {
  w: WatchEntry; canWrite: boolean; onToggle: () => void; onRemove: () => void;
}): JSX.Element {
  return (
    <li className="flex items-center gap-3 px-4 py-2">
      <SeverityChip severity={w.severity} />
      <span className="min-w-0 flex-1">
        <span className="block truncate font-mono text-sm text-ink">{w.value}</span>
        <span className="font-mono text-[10px] uppercase tracking-wide text-ink-faint">
          {WATCH_KINDS.find((k) => k.value === w.kind)?.label ?? w.kind}
          {w.label ? ` · ${w.label}` : ''}
        </span>
      </span>
      {canWrite ? (
        <>
          <button onClick={onToggle}
            className={clsx('rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide transition',
              w.enabled ? 'bg-good/15 text-good hover:bg-good/25' : 'bg-base-700 text-ink-faint hover:bg-base-600')}>
            {w.enabled ? 'On' : 'Off'}
          </button>
          <button onClick={onRemove}
            className="rounded border border-base-600 px-2 py-0.5 text-[10px] text-ink-dim transition hover:border-sev-critical/50 hover:text-sev-critical">
            Remove
          </button>
        </>
      ) : (
        <span className={clsx('rounded px-2 py-0.5 font-mono text-[10px] uppercase',
          w.enabled ? 'text-good' : 'text-ink-faint')}>{w.enabled ? 'On' : 'Off'}</span>
      )}
    </li>
  );
}

function WatchForm({ onCreated }: { onCreated: () => void }): JSX.Element {
  const [kind, setKind] = useState<WatchKind>('domain');
  const [value, setValue] = useState('');
  const [severity, setSeverity] = useState<Severity>('high');
  const [err, setErr] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: () => api.darkweb.addWatch({ kind, value: value.trim(), severity }),
    onSuccess: () => { setValue(''); setErr(null); onCreated(); },
    onError: (e) => setErr(
      e instanceof ApiError && e.status === 409 ? 'That value is already watched.'
        : e instanceof ApiError && e.status === 400 ? 'Invalid entry — check the value.'
        : 'Could not add entry.',
    ),
  });

  function onSubmit(e: FormEvent): void {
    e.preventDefault();
    if (value.trim()) add.mutate();
  }

  return (
    <form onSubmit={onSubmit} className="border-b border-base-700 p-3 space-y-2">
      <div className="flex flex-wrap items-end gap-2">
        <label>
          <span className="eyebrow">Kind</span>
          <select value={kind} onChange={(e) => setKind(e.target.value as WatchKind)}
            className="input mt-1 py-1.5">
            {WATCH_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
        </label>
        <label className="min-w-[180px] flex-1">
          <span className="eyebrow">Value</span>
          <input value={value} onChange={(e) => setValue(e.target.value)}
            placeholder="acme.com / user@acme.com / Acme"
            className="input mt-1 font-mono py-1.5" />
        </label>
        <label>
          <span className="eyebrow">Severity</span>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}
            className="input mt-1 py-1.5 capitalize">
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <button type="submit" disabled={add.isPending || !value.trim()}
          className="rounded-md bg-signal px-3 py-1.5 font-display text-sm font-semibold text-base-900 transition hover:bg-signal-soft disabled:opacity-50">
          {add.isPending ? 'Adding…' : 'Add'}
        </button>
      </div>
      {err && <p className="rounded border border-sev-critical/30 bg-sev-critical/10 px-2 py-1 text-xs text-sev-critical">{err}</p>}
    </form>
  );
}

// ── Sources ──────────────────────────────────────────────────────────────────
function SourcesPanel(): JSX.Element {
  const query = useQuery({ queryKey: ['darkweb-sources'], queryFn: () => api.darkweb.sources() });
  const sources = query.data?.data ?? [];

  return (
    <Panel title="Monitored sources" bodyClassName="p-0">
      {query.isLoading ? <Spinner label="Loading sources" />
        : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
        : sources.length === 0
          ? <EmptyState title="No sources configured" hint="Sources are provisioned by the operator." />
          : (
            <ul className="divide-y divide-base-700">
              {sources.map((s) => <SourceRow key={s.id} s={s} />)}
            </ul>
          )}
      <p className="border-t border-base-700 px-4 py-2 font-mono text-[10px] leading-relaxed text-ink-faint">
        Sources ship disabled with placeholder addresses. Enable and set current onion addresses
        out-of-band; polling is Tor-only and fails closed with no clearnet fallback.
      </p>
    </Panel>
  );
}

function SourceRow({ s }: { s: DarkwebSource }): JSX.Element {
  const health = (s.health ?? 'unknown').toLowerCase();
  const tone = health === 'ok' ? 'text-good'
    : health === 'error' || health === 'unreachable' ? 'text-sev-critical'
    : 'text-ink-faint';
  return (
    <li className="flex items-center gap-3 px-4 py-2">
      <span className={clsx('h-2 w-2 shrink-0 rounded-full',
        s.enabled ? 'bg-good' : 'bg-base-500')} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm text-ink">{s.name}</span>
        <span className="font-mono text-[10px] uppercase tracking-wide text-ink-faint">
          {s.kind} · every {Math.round(s.poll_interval_secs / 60)}m
          {s.last_polled_at ? ` · polled ${relTime(s.last_polled_at)}` : ' · never polled'}
        </span>
      </span>
      <span className={clsx('font-mono text-[10px] uppercase', tone)}>{health}</span>
    </li>
  );
}

