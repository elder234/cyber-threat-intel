import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../lib/api';
import { useLiveEvent } from '../lib/live';
import { clsx, relTime } from '../lib/ui';
import { DataTable, type Column } from '../components/DataTable';
import { EmptyState, ErrorState, Panel, Spinner, StatusPill } from '../components/primitives';
import { PageHeader } from './Iocs';
import type { Scan } from '../lib/types';

const SCAN_TYPES = ['port', 'tls', 'http', 'subdomain', 'full'] as const;

export default function ScansPage(): JSX.Element {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ['scans'], queryFn: () => api.scans.list(100) });

  useLiveEvent('scan.update', () => qc.invalidateQueries({ queryKey: ['scans'] }));

  const columns: Column<Scan>[] = [
    { key: 'target', header: 'Target',
      cell: (r) => <span className="data text-ink">{r.target}</span> },
    { key: 'type', header: 'Type', width: '90px',
      cell: (r) => <span className="font-mono text-[11px] uppercase text-ink-faint">{r.scan_type}</span> },
    { key: 'status', header: 'Status', width: '120px', cell: (r) => <StatusPill status={r.status} /> },
    { key: 'progress', header: 'Progress', width: '140px',
      cell: (r) => (
        <div className="flex items-center gap-2">
          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-base-700">
            <div className={clsx('h-full rounded-full',
              r.status === 'failed' ? 'bg-sev-critical' : 'bg-signal')}
              style={{ width: `${Math.round((r.progress ?? 0) * 100)}%` }} />
          </div>
          <span className="data text-[10px] text-ink-faint">{Math.round((r.progress ?? 0) * 100)}%</span>
        </div>
      ) },
    { key: 'created', header: 'Created', width: '90px',
      cell: (r) => <span className="data text-xs text-ink-faint">{relTime(r.created_at)}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Vulnerability Scans" subtitle="Port · TLS · HTTP headers · authorized targets only" />

      <NewScanForm onCreated={() => qc.invalidateQueries({ queryKey: ['scans'] })} />

      <Panel title="Scan history" bodyClassName="p-0">
        {query.isLoading ? <Spinner label="Loading scans" />
          : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
          : (
            <DataTable columns={columns} rows={query.data?.data ?? []} keyFn={(r) => r.id}
              empty={<EmptyState title="No scans yet" hint="Launch a scan against an authorized target above." />} />
          )}
      </Panel>
    </div>
  );
}

function NewScanForm({ onCreated }: { onCreated: () => void }): JSX.Element {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState<typeof SCAN_TYPES[number]>('port');
  const [assetId, setAssetId] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.scans.create({
      target,
      scanType,
      assetId: assetId.trim() || undefined,
    }),
    onSuccess: () => { setTarget(''); setAssetId(''); setErr(null); onCreated(); },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 403) {
        setErr('Target asset is not marked authorized. Scanning is gated on explicit authorization.');
      } else if (e instanceof ApiError && e.status === 404) {
        setErr('Asset not found.');
      } else {
        setErr('Failed to queue scan.');
      }
    },
  });

  function submit(e: FormEvent): void {
    e.preventDefault();
    if (target.trim()) create.mutate();
  }

  return (
    <Panel title="Launch scan">
      <form onSubmit={submit} className="space-y-3">
        <div className="flex flex-wrap items-end gap-3">
          <label className="min-w-[240px] flex-1">
            <span className="eyebrow">Target (host / IP / CIDR)</span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="scanme.example.com"
              className="mt-1 w-full rounded-md border border-base-600 bg-base-900 px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
            />
          </label>
          <label>
            <span className="eyebrow">Type</span>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value as typeof SCAN_TYPES[number])}
              className="mt-1 block rounded-md border border-base-600 bg-base-900 px-2 py-1.5 text-sm text-ink focus:border-signal"
            >
              {SCAN_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="min-w-[200px]">
            <span className="eyebrow">Asset ID (optional)</span>
            <input
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              placeholder="uuid of authorized asset"
              className="mt-1 w-full rounded-md border border-base-600 bg-base-900 px-3 py-1.5 font-mono text-xs text-ink placeholder:text-ink-faint focus:border-signal"
            />
          </label>
          <button
            type="submit"
            disabled={create.isPending || !target.trim()}
            className="rounded-md bg-signal px-4 py-2 font-display text-sm font-semibold text-base-900 transition hover:bg-signal-soft disabled:opacity-50"
          >
            {create.isPending ? 'Queuing…' : 'Scan'}
          </button>
        </div>

        {err && (
          <p className="rounded border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">{err}</p>
        )}
        <p className="font-mono text-[10px] leading-relaxed text-ink-faint">
          Authorized use only. Scanning a registered asset requires that asset to be explicitly marked
          <span className="text-ink-dim"> authorized</span>. All scans are audit-logged.
        </p>
      </form>
    </Panel>
  );
}
