import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../lib/api';
import { useLiveEvent } from '../lib/live';
import { useHasPerm } from '../lib/auth';
import { clsx, relTime } from '../lib/ui';
import { DataTable, type Column } from '../components/DataTable';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner, StatusPill } from '../components/primitives';
import { PageHeader } from './Iocs';
import type { Scan, ScanFinding, Severity } from '../lib/types';

const SCAN_TYPES = ['port', 'tls', 'http', 'subdomain', 'full', 'web'] as const;
type ScanType = typeof SCAN_TYPES[number];

const PROBE_CLASSES = [
  { id: 'xss', label: 'Reflected XSS' },
  { id: 'sqli', label: 'Error-based SQLi' },
  { id: 'path_traversal', label: 'Path traversal' },
  { id: 'open_redirect', label: 'Open redirect' },
] as const;

const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<Severity, number>;

export default function ScansPage(): JSX.Element {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ['scans'], queryFn: () => api.scans.list(100) });
  const [openScan, setOpenScan] = useState<Scan | null>(null);

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
      <PageHeader title="Vulnerability Scans" subtitle="Port · TLS · HTTP headers · web (DAST) · authorized targets only" />

      <NewScanForm onCreated={() => qc.invalidateQueries({ queryKey: ['scans'] })} />

      <Panel title="Scan history" bodyClassName="p-0">
        {query.isLoading ? <Spinner label="Loading scans" />
          : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
          : (
            <DataTable columns={columns} rows={query.data?.data ?? []} keyFn={(r) => r.id}
              onRowClick={(r) => setOpenScan(r)}
              empty={<EmptyState title="No scans yet" hint="Launch a scan against an authorized target above." />} />
          )}
      </Panel>

      {openScan && <FindingsDrawer scan={openScan} onClose={() => setOpenScan(null)} />}
    </div>
  );
}

function NewScanForm({ onCreated }: { onCreated: () => void }): JSX.Element {
  const canWebScan = useHasPerm('web:scan');
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState<ScanType>('port');
  const [assetId, setAssetId] = useState('');
  const [err, setErr] = useState<string | null>(null);

  // Web (DAST) options.
  const [activeEnabled, setActiveEnabled] = useState(false);
  const [probeClasses, setProbeClasses] = useState<string[]>([]);
  const [maxPayloads, setMaxPayloads] = useState(4);

  const isWeb = scanType === 'web';

  function buildProfile(): Record<string, unknown> | undefined {
    if (!isWeb) return undefined;
    return {
      probeClasses: activeEnabled ? probeClasses : [],
      activeEnabled,
      maxPayloadsPerParam: maxPayloads,
    };
  }

  const create = useMutation({
    mutationFn: () => api.scans.create({
      target,
      scanType,
      assetId: assetId.trim() || undefined,
      profile: buildProfile(),
    }),
    onSuccess: () => {
      setTarget(''); setAssetId(''); setErr(null);
      setActiveEnabled(false); setProbeClasses([]);
      onCreated();
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 403) {
        setErr(isWeb
          ? 'Web (DAST) inspection requires the web:scan permission and an authorized asset.'
          : 'Target asset is not marked authorized. Scanning is gated on explicit authorization.');
      } else if (e instanceof ApiError && e.status === 404) {
        setErr('Asset not found.');
      } else if (e instanceof ApiError && e.status === 400) {
        const msg = (e.body as { message?: string } | null)?.message;
        setErr(msg || 'Invalid request. Active probing requires a registered authorized asset.');
      } else {
        setErr('Failed to queue scan.');
      }
    },
  });

  function toggleProbe(id: string): void {
    setProbeClasses((cur) => cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]);
  }

  function submit(e: FormEvent): void {
    e.preventDefault();
    if (target.trim()) create.mutate();
  }

  return (
    <Panel title="Launch scan">
      <form onSubmit={submit} className="space-y-3">
        <div className="flex flex-wrap items-end gap-3">
          <label className="min-w-[240px] flex-1">
            <span className="eyebrow">{isWeb ? 'Target URL / host' : 'Target (host / IP / CIDR)'}</span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={isWeb ? 'https://app.example.com/search?q=1' : 'scanme.example.com'}
              className="mt-1 w-full rounded-md border border-base-600 bg-base-900 px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
            />
          </label>
          <label>
            <span className="eyebrow">Type</span>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value as ScanType)}
              className="mt-1 block rounded-md border border-base-600 bg-base-900 px-2 py-1.5 text-sm text-ink focus:border-signal"
            >
              {SCAN_TYPES.map((t) => (
                <option key={t} value={t} disabled={t === 'web' && !canWebScan}>
                  {t}{t === 'web' && !canWebScan ? ' (no permission)' : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="min-w-[200px]">
            <span className="eyebrow">Asset ID {isWeb ? '(required for active probes)' : '(optional)'}</span>
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

        {isWeb && (
          <div className="rounded-md border border-base-600 bg-base-900/60 p-3">
            <div className="flex items-center justify-between">
              <span className="eyebrow">Web inspection</span>
              <label className="flex items-center gap-2 text-xs text-ink-dim">
                <input
                  type="checkbox"
                  checked={activeEnabled}
                  onChange={(e) => setActiveEnabled(e.target.checked)}
                  className="accent-signal"
                />
                Enable active DAST probes
              </label>
            </div>
            <p className="mt-1 font-mono text-[10px] leading-relaxed text-ink-faint">
              Passive fingerprinting, header analysis and version→CVE correlation always run.
              Active probes send benign, non-destructive detection markers and require the target
              to be a registered <span className="text-ink-dim">authorized</span> asset.
            </p>
            {activeEnabled && (
              <div className="mt-2 space-y-2">
                <div className="flex flex-wrap gap-3">
                  {PROBE_CLASSES.map((pc) => (
                    <label key={pc.id} className="flex items-center gap-1.5 text-xs text-ink-dim">
                      <input
                        type="checkbox"
                        checked={probeClasses.includes(pc.id)}
                        onChange={() => toggleProbe(pc.id)}
                        className="accent-signal"
                      />
                      {pc.label}
                    </label>
                  ))}
                </div>
                <label className="flex items-center gap-2 text-xs text-ink-dim">
                  Max payloads / parameter
                  <input
                    type="number" min={1} max={64} value={maxPayloads}
                    onChange={(e) => setMaxPayloads(Math.max(1, Math.min(64, Number(e.target.value) || 1)))}
                    className="w-16 rounded border border-base-600 bg-base-900 px-2 py-1 font-mono text-xs text-ink focus:border-signal"
                  />
                </label>
              </div>
            )}
          </div>
        )}

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

/** Slide-over showing a scan's findings, grouped by category and sorted by severity. */
function FindingsDrawer({ scan, onClose }: { scan: Scan; onClose: () => void }): JSX.Element {
  const detail = useQuery({
    queryKey: ['scan', scan.id],
    queryFn: () => api.scans.get(scan.id),
    refetchInterval: scan.status === 'running' || scan.status === 'queued' ? 3000 : false,
  });

  const findings: ScanFinding[] = detail.data?.findings ?? [];
  const groups = groupByCategory(findings);

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-2xl flex-col border-l border-base-600 bg-base-800 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-base-600 px-5 py-3">
          <div>
            <h2 className="font-display text-base font-bold text-ink">Findings</h2>
            <p className="data text-xs text-ink-faint">{scan.target} · <span className="uppercase">{scan.scan_type}</span></p>
          </div>
          <button onClick={onClose} className="text-ink-faint hover:text-ink">✕</button>
        </header>

        <div className="min-h-0 flex-1 overflow-auto p-5">
          {detail.isLoading ? <Spinner label="Loading findings" />
            : detail.error ? <ErrorState error={detail.error} retry={() => detail.refetch()} />
            : findings.length === 0 ? (
              <EmptyState
                title="No findings"
                hint={scan.status === 'completed'
                  ? 'This scan completed without recording any findings.'
                  : 'Findings appear as the scan progresses.'} />
            ) : (
              <div className="space-y-5">
                {groups.map(([category, rows]) => (
                  <section key={category}>
                    <h3 className="eyebrow mb-2">{prettyCategory(category)} · {rows.length}</h3>
                    <div className="space-y-2">
                      {rows.map((f) => <FindingCard key={f.id} f={f} />)}
                    </div>
                  </section>
                ))}
              </div>
            )}
        </div>
      </div>
    </div>
  );
}

function FindingCard({ f }: { f: ScanFinding }): JSX.Element {
  const conf = num(f.evidence?.confidence);
  return (
    <div className="rounded-md border border-base-600 bg-base-900/60 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium text-ink">{f.title}</p>
          {f.description && <p className="mt-0.5 text-xs text-ink-dim">{f.description}</p>}
        </div>
        <SeverityChip severity={f.severity} />
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-ink-faint">
        {f.cve_id && <span className="text-signal">{f.cve_id}</span>}
        {typeof f.evidence?.param === 'string' && <span>param: {f.evidence.param as string}</span>}
        {conf !== null && <span>confidence: {(conf * 100).toFixed(0)}%</span>}
        {typeof f.evidence?.payload === 'string' && (
          <span className="truncate">payload: {f.evidence.payload as string}</span>
        )}
      </div>
      {f.remediation && (
        <p className="mt-2 border-t border-base-700 pt-2 text-[11px] leading-relaxed text-ink-dim">
          <span className="text-ink-faint">Remediation: </span>{f.remediation}
        </p>
      )}
    </div>
  );
}

function groupByCategory(findings: ScanFinding[]): Array<[string, ScanFinding[]]> {
  const map = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const arr = map.get(f.category) ?? [];
    arr.push(f);
    map.set(f.category, arr);
  }
  for (const arr of map.values()) {
    arr.sort((a, b) => (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0));
  }
  // Order groups by their worst severity.
  return [...map.entries()].sort((a, b) => worst(b[1]) - worst(a[1]));
}

function worst(rows: ScanFinding[]): number {
  return rows.reduce((m, r) => Math.max(m, SEV_ORDER[r.severity] ?? 0), 0);
}

function prettyCategory(c: string): string {
  const labels: Record<string, string> = {
    fingerprint: 'Technology fingerprint',
    cve: 'Version → CVE',
    version_cve: 'Version → CVE',
    http_header: 'HTTP headers',
    cookie: 'Cookies',
    tls: 'TLS',
    xss: 'Reflected XSS',
    sqli: 'SQL injection',
    path_traversal: 'Path traversal',
    open_redirect: 'Open redirect',
  };
  return labels[c] ?? c;
}

/** Coerce a possibly-string NUMERIC (node-postgres) or JSON number to a number. */
function num(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = typeof v === 'number' ? v : Number.parseFloat(String(v));
  return Number.isFinite(n) ? n : null;
}
