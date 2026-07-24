import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { clsx } from '../lib/ui';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner } from '../components/primitives';
import { PageHeader } from './Iocs';
import type { SearchResult, Severity } from '../lib/types';

// Human labels + accent for each entity bucket the unified search returns.
const ENTITY_META: Record<string, { label: string; glyph: string }> = {
  ioc: { label: 'Indicators', glyph: '◈' },
  cve: { label: 'Vulnerabilities', glyph: '⚠' },
  actor: { label: 'Threat actors', glyph: '☰' },
  malware: { label: 'Malware families', glyph: '⌬' },
  scan: { label: 'Scans', glyph: '◎' },
  alert: { label: 'Alerts', glyph: '◆' },
};

export default function SearchPage(): JSX.Element {
  const [params, setParams] = useSearchParams();
  const initial = params.get('q') ?? '';
  const [term, setTerm] = useState(initial);

  // Keep the input synced when navigation changes ?q= (e.g. header search).
  useEffect(() => { setTerm(params.get('q') ?? ''); }, [params]);

  const q = params.get('q') ?? '';
  const query = useQuery({
    queryKey: ['search', q],
    queryFn: () => api.search.query(q, 50),
    enabled: q.trim().length > 0,
  });

  return (
    <div className="space-y-4">
      <PageHeader title="Unified Search" subtitle="IOCs · CVEs · actors · malware · indicators" />

      <Panel bodyClassName="p-3">
        <form
          onSubmit={(e) => { e.preventDefault(); setParams(term.trim() ? { q: term.trim() } : {}); }}
          className="flex gap-2"
        >
          <input
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            autoFocus
            placeholder="Search across all intelligence entities…"
            className="flex-1 rounded-md border border-base-600 bg-base-900 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
          />
          <button
            type="submit"
            className="rounded-md bg-signal px-5 font-display text-sm font-semibold text-base-900 transition hover:bg-signal-soft"
          >Search</button>
        </form>
      </Panel>

      {!q.trim() ? (
        <Panel><EmptyState title="Enter a query" hint="Search IPs, domains, hashes, CVE ids, actors, and malware families." /></Panel>
      ) : query.isLoading ? <Spinner label="Searching" />
        : query.error ? <Panel><ErrorState error={query.error} retry={() => query.refetch()} /></Panel>
        : <Results grouped={query.data?.grouped ?? {}} count={query.data?.count ?? 0} q={q} />}
    </div>
  );
}

function Results({
  grouped, count, q,
}: { grouped: Record<string, SearchResult[]>; count: number; q: string }): JSX.Element {
  const buckets = Object.entries(grouped);
  if (count === 0) {
    return <Panel><EmptyState title={`No results for “${q}”`} hint="Try a different indicator or a broader term." /></Panel>;
  }
  return (
    <div className="space-y-4">
      <p className="font-mono text-xs text-ink-faint">
        {count} result{count === 1 ? '' : 's'} across {buckets.length} categor{buckets.length === 1 ? 'y' : 'ies'}
      </p>
      {buckets.map(([type, items]) => {
        const meta = ENTITY_META[type] ?? { label: type, glyph: '•' };
        return (
          <Panel key={type} title={<span className="flex items-center gap-2">
            <span className="text-signal">{meta.glyph}</span>{meta.label}
            <span className="text-ink-faint">({items.length})</span>
          </span>}>
            <ul className="divide-y divide-base-700/60">
              {items.map((r) => (
                <li key={`${r.entity_type}:${r.entity_id}`} className="flex items-center gap-3 py-2">
                  {r.severity && <SeverityChip severity={r.severity as Severity} />}
                  <span className="data min-w-0 flex-1 truncate text-sm text-ink">{r.label}</span>
                  {r.sub_label && <span className="truncate text-xs text-ink-faint">{r.sub_label}</span>}
                  <span className={clsx('font-mono text-[10px] uppercase tracking-wider text-ink-faint')}>{type}</span>
                </li>
              ))}
            </ul>
          </Panel>
        );
      })}
    </div>
  );
}
