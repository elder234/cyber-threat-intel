import { useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { clsx, relTime } from '../lib/ui';
import { DataTable, type Column } from '../components/DataTable';
import { EmptyState, ErrorState, Panel, Spinner } from '../components/primitives';
import { PageHeader, Pager } from './Iocs';
import type { Cve } from '../lib/types';

const PAGE = 50;

/** CVSS score → color band (mirrors the severity scale). */
function cvssColor(score: number | null): string {
  if (score === null) return 'text-ink-faint';
  if (score >= 9) return 'text-sev-critical';
  if (score >= 7) return 'text-sev-high';
  if (score >= 4) return 'text-sev-medium';
  return 'text-sev-low';
}

export default function CvesPage(): JSX.Element {
  const [kevOnly, setKevOnly] = useState(false);
  const [minCvss, setMinCvss] = useState(0);
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);

  const query = useQuery({
    queryKey: ['cves', { kevOnly, minCvss, q, offset }],
    queryFn: () => api.cves.list({
      kev: kevOnly || undefined,
      minCvss: minCvss || undefined,
      q: q || undefined,
      limit: PAGE,
      offset,
    }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.pagination.total ?? 0;
  const rows = query.data?.data ?? [];

  const columns: Column<Cve>[] = [
    { key: 'id', header: 'CVE', width: '150px',
      cell: (r) => (
        <div className="flex items-center gap-2">
          <span className="data font-semibold text-ink">{r.cve_id}</span>
          {r.kev && (
            <span className={clsx('rounded px-1 py-0.5 text-[9px] font-bold uppercase',
              r.kev_ransomware ? 'bg-sev-critical/20 text-sev-critical' : 'bg-sev-high/20 text-sev-high')}>
              {r.kev_ransomware ? 'KEV·RANSOM' : 'KEV'}
            </span>
          )}
        </div>
      ) },
    { key: 'cvss', header: 'CVSS', width: '70px',
      cell: (r) => <span className={clsx('data font-bold', cvssColor(r.cvss_v31_score))}>
        {r.cvss_v31_score?.toFixed(1) ?? '—'}</span> },
    { key: 'epss', header: 'EPSS', width: '90px',
      cell: (r) => r.epss_score !== null
        ? <span className="data text-xs text-ink-dim">{(r.epss_score * 100).toFixed(1)}%</span>
        : <span className="text-ink-faint">—</span> },
    { key: 'desc', header: 'Description',
      cell: (r) => <span className="line-clamp-2 text-xs text-ink-dim">{r.description}</span> },
    { key: 'pub', header: 'Published', width: '90px',
      cell: (r) => <span className="data text-xs text-ink-faint">{r.published_at ? relTime(r.published_at) : '—'}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Vulnerabilities" subtitle={`${total.toLocaleString()} CVEs · CVSS · EPSS · CISA KEV`} />

      <Panel bodyClassName="p-3">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={q}
            onChange={(e) => { setOffset(0); setQ(e.target.value); }}
            placeholder="Search CVE id or description…"
            className="min-w-[220px] flex-1 rounded-md border border-base-600 bg-base-900 px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
          />
          <label className="flex items-center gap-2">
            <span className="eyebrow">Min CVSS</span>
            <input
              type="range" min={0} max={10} step={0.5} value={minCvss}
              onChange={(e) => { setOffset(0); setMinCvss(Number(e.target.value)); }}
              className="accent-signal"
            />
            <span className="data w-8 text-xs text-ink-dim">{minCvss.toFixed(1)}</span>
          </label>
          <label className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox" checked={kevOnly}
              onChange={(e) => { setOffset(0); setKevOnly(e.target.checked); }}
              className="accent-signal"
            />
            <span className="eyebrow">KEV only</span>
          </label>
        </div>
      </Panel>

      <Panel bodyClassName="p-0">
        {query.isLoading ? <Spinner label="Loading CVEs" />
          : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
          : (
            <>
              <DataTable
                columns={columns} rows={rows} keyFn={(r) => r.cve_id}
                empty={<EmptyState title="No matching CVEs" hint="Loosen the CVSS filter or sync the NVD feed." />}
              />
              <Pager offset={offset} pageSize={PAGE} total={total} onChange={setOffset} fetching={query.isFetching} />
            </>
          )}
      </Panel>
    </div>
  );
}
