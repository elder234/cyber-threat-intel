import { useState } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { clsx, relTime, SEVERITY_ORDER } from '../lib/ui';
import { useHasRole } from '../lib/auth';
import { DataTable, type Column } from '../components/DataTable';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner } from '../components/primitives';
import type { Ioc, IocType, Severity } from '../lib/types';

const IOC_TYPES: IocType[] = [
  'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'sha512',
  'email', 'cidr', 'asn', 'file_path', 'registry_key', 'mutex', 'user_agent', 'ja3',
];
const PAGE = 50;

export default function IocsPage(): JSX.Element {
  const [type, setType] = useState<IocType | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);
  const canWrite = useHasRole('admin', 'analyst');
  const qc = useQueryClient();

  const query = useQuery({
    queryKey: ['iocs', { type, severity, q, offset }],
    queryFn: () => api.iocs.list({
      type: type || undefined,
      severity: severity || undefined,
      q: q || undefined,
      limit: PAGE,
      offset,
    }),
    placeholderData: keepPreviousData,
  });

  // Enqueue an OSINT enrichment job; the row's score updates on the next poll.
  const enrichM = useMutation({
    mutationFn: (id: string) => api.iocs.enrich(id),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['iocs'] }); },
  });

  const total = query.data?.pagination.total ?? 0;
  const rows = query.data?.data ?? [];

  const columns: Column<Ioc>[] = [
    { key: 'sev', header: 'Sev', width: '92px', cell: (r) => <SeverityChip severity={r.severity} /> },
    { key: 'type', header: 'Type', width: '90px',
      cell: (r) => <span className="font-mono text-[11px] uppercase tracking-wide text-ink-faint">{r.type}</span> },
    { key: 'value', header: 'Indicator',
      cell: (r) => <span className="data break-all text-ink">{r.value}</span> },
    { key: 'conf', header: 'Confidence', width: '110px',
      cell: (r) => <span className="text-xs capitalize text-ink-dim">{r.confidence}</span> },
    { key: 'source', header: 'Source', width: '130px',
      cell: (r) => <span className="font-mono text-[11px] text-ink-dim">{r.source}</span> },
    { key: 'score', header: 'Rep', width: '70px',
      cell: (r) => <ScoreBadge score={r.score} /> },
    { key: 'tags', header: 'Tags',
      cell: (r) => (
        <div className="flex flex-wrap gap-1">
          {r.tags.slice(0, 3).map((t) => (
            <span key={t} className="rounded bg-base-700 px-1.5 py-0.5 text-[10px] text-ink-dim">{t}</span>
          ))}
          {r.tags.length > 3 && <span className="text-[10px] text-ink-faint">+{r.tags.length - 3}</span>}
        </div>
      ) },
    { key: 'seen', header: 'Last seen', width: '80px',
      cell: (r) => <span className="data text-xs text-ink-faint">{relTime(r.last_seen)}</span> },
  ];

  if (canWrite) {
    columns.push({
      key: 'enrich', header: '', width: '84px',
      cell: (r) => (
        <button
          onClick={() => enrichM.mutate(r.id)}
          disabled={enrichM.isPending}
          title="Enqueue OSINT reputation lookup"
          className="rounded border border-base-600 px-2 py-0.5 text-[10px] uppercase tracking-widest text-ink-dim disabled:opacity-40 enabled:hover:border-signal enabled:hover:text-signal"
        >Enrich</button>
      ),
    });
  }

  function resetAnd<T>(setter: (v: T) => void) {
    return (v: T) => { setOffset(0); setter(v); };
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Indicators of Compromise"
        subtitle={`${total.toLocaleString()} indicators`}
      />

      <Panel bodyClassName="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => resetAnd(setQ)(e.target.value)}
            placeholder="Filter by value…"
            className="min-w-[220px] flex-1 rounded-md border border-base-600 bg-base-900 px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
          />
          <Select value={type} onChange={resetAnd(setType)} label="Type"
            options={['', ...IOC_TYPES]} />
          <Select value={severity} onChange={resetAnd(setSeverity)} label="Severity"
            options={['', ...SEVERITY_ORDER]} />
        </div>
      </Panel>

      <Panel bodyClassName="p-0">
        {query.isLoading ? <Spinner label="Loading indicators" />
          : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
          : (
            <>
              <DataTable
                columns={columns}
                rows={rows}
                keyFn={(r) => r.id}
                empty={<EmptyState title="No matching indicators" hint="Adjust filters or ingest a feed." />}
              />
              <Pager offset={offset} pageSize={PAGE} total={total} onChange={setOffset}
                fetching={query.isFetching} />
            </>
          )}
      </Panel>
    </div>
  );
}

/** Aggregated OSINT reputation score (0–100). Null = not yet enriched. */
function ScoreBadge({ score }: { score: number | null }): JSX.Element {
  if (score == null) return <span className="text-[10px] text-ink-faint">—</span>;
  const tone = score >= 65 ? 'text-sev-critical' : score >= 25 ? 'text-signal' : 'text-good';
  return <span className={clsx('data text-xs font-semibold', tone)}>{score}</span>;
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: JSX.Element }): JSX.Element {
  return (
    <div className="flex items-end justify-between">
      <div>
        <h1 className="font-display text-xl font-bold tracking-wide text-ink">{title}</h1>
        {subtitle && <p className="eyebrow mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function Select<T extends string>({
  value, onChange, options, label,
}: { value: T; onChange: (v: T) => void; options: T[]; label: string }): JSX.Element {
  return (
    <label className="flex items-center gap-2">
      <span className="eyebrow">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as T)}
        className="rounded-md border border-base-600 bg-base-900 px-2 py-1.5 text-sm text-ink focus:border-signal"
      >
        {options.map((o) => (
          <option key={o} value={o}>{o === '' ? 'any' : o}</option>
        ))}
      </select>
    </label>
  );
}

export function Pager({
  offset, pageSize, total, onChange, fetching,
}: { offset: number; pageSize: number; total: number; onChange: (o: number) => void; fetching?: boolean }): JSX.Element {
  const page = Math.floor(offset / pageSize) + 1;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="flex items-center justify-between border-t border-base-600 px-3 py-2">
      <span className={clsx('font-mono text-[10px] uppercase tracking-widest',
        fetching ? 'text-signal' : 'text-ink-faint')}>
        {fetching ? 'loading…' : `page ${page} / ${pages}`}
      </span>
      <div className="flex gap-2">
        <button
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - pageSize))}
          className="rounded border border-base-600 px-2 py-1 text-xs text-ink-dim disabled:opacity-40 enabled:hover:border-signal enabled:hover:text-signal"
        >Prev</button>
        <button
          disabled={page >= pages}
          onClick={() => onChange(offset + pageSize)}
          className="rounded border border-base-600 px-2 py-1 text-xs text-ink-dim disabled:opacity-40 enabled:hover:border-signal enabled:hover:text-signal"
        >Next</button>
      </div>
    </div>
  );
}
