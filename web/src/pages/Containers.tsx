import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../lib/api';
import { useLiveEvent } from '../lib/live';
import { useHasRole } from '../lib/auth';
import { clsx, relTime } from '../lib/ui';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner, StatusPill } from '../components/primitives';
import { PageHeader } from './Iocs';
import type { ContainerAudit, ContainerAuditKind, ContainerFinding } from '../lib/types';

/**
 * Module 6 — Container Security. Submit a Dockerfile, an image `config` JSON,
 * or a Trivy report; the worker analyzes it offline and returns hardening
 * findings + a 0–100 risk score.
 *
 * ⚠️ RUNTIME VERIFICATION REQUIRED — depends on the worker + API being live (VM offline).
 */
const KINDS: { value: ContainerAuditKind; label: string; hint: string; placeholder: string }[] = [
  { value: 'dockerfile', label: 'Dockerfile', hint: 'Paste Dockerfile contents',
    placeholder: 'FROM node:20-alpine\nRUN adduser -D app\nUSER app\n...' },
  { value: 'image_config', label: 'Image config', hint: 'OCI/`docker inspect` Config JSON',
    placeholder: '{"User":"","Env":["API_KEY=..."],"ExposedPorts":{"22/tcp":{}}}' },
  { value: 'trivy', label: 'Trivy report', hint: 'Output of `trivy image --format json`',
    placeholder: '{"Results":[{"Target":"app:latest","Vulnerabilities":[...]}]}' },
];

export default function ContainersPage(): JSX.Element {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const canRun = useHasRole('admin', 'analyst');
  const query = useQuery({ queryKey: ['container-audits'], queryFn: () => api.container.list(100) });

  useLiveEvent('container.audit', () => qc.invalidateQueries({ queryKey: ['container-audits'] }));

  const audits = query.data?.data ?? [];

  return (
    <div className="space-y-4">
      <PageHeader title="Container Security" subtitle="Module 6 · Dockerfile lint · image config · Trivy — offline analysis" />

      {canRun && <NewAuditForm onCreated={() => qc.invalidateQueries({ queryKey: ['container-audits'] })} />}

      <Panel title="Audits" bodyClassName="p-0">
        {query.isLoading ? <Spinner label="Loading audits" />
          : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
          : audits.length === 0
            ? <EmptyState title="No audits yet" hint={canRun ? 'Submit a Dockerfile or scanner report above.' : 'Nothing has been analyzed yet.'} />
            : (
              <ul className="divide-y divide-base-700">
                {audits.map((a) => (
                  <li key={a.id}>
                    <button
                      onClick={() => setSelected(selected === a.id ? null : a.id)}
                      className="flex w-full items-center gap-3 px-4 py-2.5 text-left transition hover:bg-base-800/60"
                    >
                      <ScorePill score={a.score} status={a.status} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-ink">{a.name}</span>
                        <span className="data text-[11px] text-ink-faint">{kindLabel(a.kind)} · {relTime(a.created_at)}</span>
                      </span>
                      <SummaryCounts audit={a} />
                      <StatusPill status={a.status} />
                    </button>
                    {selected === a.id && <AuditDetail id={a.id} />}
                  </li>
                ))}
              </ul>
            )}
      </Panel>
    </div>
  );
}

function kindLabel(kind: ContainerAuditKind): string {
  return KINDS.find((k) => k.value === kind)?.label ?? kind;
}

function ScorePill({ score, status }: { score: number | null; status: string }): JSX.Element {
  if (status !== 'completed' || score == null) {
    return <span className="grid h-9 w-9 place-items-center rounded-md bg-base-700 font-mono text-xs text-ink-faint">—</span>;
  }
  const tone = score >= 75 ? 'bg-sev-critical/15 text-sev-critical'
    : score >= 50 ? 'bg-sev-high/15 text-sev-high'
    : score >= 25 ? 'bg-sev-medium/15 text-sev-medium'
    : 'bg-good/15 text-good';
  return <span className={clsx('grid h-9 w-9 place-items-center rounded-md font-mono text-sm font-semibold', tone)}>{score}</span>;
}

function SummaryCounts({ audit }: { audit: ContainerAudit }): JSX.Element | null {
  const s = audit.summary ?? {};
  const items: [string, number | undefined, string][] = [
    ['C', s.critical, 'text-sev-critical'],
    ['H', s.high, 'text-sev-high'],
    ['M', s.medium, 'text-sev-medium'],
    ['L', s.low, 'text-sev-low'],
  ];
  if (audit.status !== 'completed') return null;
  return (
    <span className="hidden items-center gap-2 sm:flex">
      {items.map(([label, n, tone]) => (
        <span key={label} className={clsx('data text-[11px]', (n ?? 0) > 0 ? tone : 'text-ink-faint')}>
          {n ?? 0}{label}
        </span>
      ))}
    </span>
  );
}

function AuditDetail({ id }: { id: string }): JSX.Element {
  const qc = useQueryClient();
  const canRun = useHasRole('admin', 'analyst');
  const detail = useQuery({ queryKey: ['container-audit', id], queryFn: () => api.container.get(id) });
  const remove = useMutation({
    mutationFn: () => api.container.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['container-audits'] }),
  });

  if (detail.isLoading) return <div className="px-4 py-3"><Spinner label="Loading findings" /></div>;
  if (detail.error) return <div className="px-4 py-3"><ErrorState error={detail.error} retry={() => detail.refetch()} /></div>;
  const d = detail.data!;

  return (
    <div className="border-t border-base-700 bg-base-900/40 px-4 py-3">
      {d.status === 'failed' && d.error && (
        <p className="mb-3 rounded border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
          Analysis failed: {d.error}
        </p>
      )}
      {d.findings.length === 0 ? (
        <p className="text-sm text-ink-dim">
          {d.status === 'completed' ? 'No findings — clean.' : 'No findings yet.'}
        </p>
      ) : (
        <ul className="space-y-2">
          {d.findings.map((f) => <FindingRow key={f.id} f={f} />)}
        </ul>
      )}
      {canRun && (
        <div className="mt-3 flex justify-end">
          <button
            onClick={() => remove.mutate()}
            disabled={remove.isPending}
            className="rounded border border-base-600 px-2.5 py-1 text-xs text-ink-dim transition hover:border-sev-critical/50 hover:text-sev-critical disabled:opacity-50"
          >
            {remove.isPending ? 'Deleting…' : 'Delete audit'}
          </button>
        </div>
      )}
    </div>
  );
}

function FindingRow({ f }: { f: ContainerFinding }): JSX.Element {
  return (
    <li className="rounded-md border border-base-700 bg-base-800/40 p-2.5">
      <div className="flex items-start gap-2.5">
        <SeverityChip severity={f.severity} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-sm text-ink">{f.title}</span>
            <span className="data text-[10px] uppercase text-ink-faint">{f.rule_id}</span>
            {f.location && <span className="data text-[10px] text-ink-faint">· {f.location}</span>}
          </div>
          {f.remediation && <p className="mt-0.5 text-xs leading-relaxed text-ink-dim">{f.remediation}</p>}
        </div>
      </div>
    </li>
  );
}

function NewAuditForm({ onCreated }: { onCreated: () => void }): JSX.Element {
  const [kind, setKind] = useState<ContainerAuditKind>('dockerfile');
  const [name, setName] = useState('');
  const [input, setInput] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const active = KINDS.find((k) => k.value === kind)!;

  const create = useMutation({
    mutationFn: () => api.container.create({ name: name.trim(), kind, input }),
    onSuccess: () => { setName(''); setInput(''); setErr(null); onCreated(); },
    onError: (e) => setErr(e instanceof ApiError && e.status === 400
      ? 'Check the input — it must be non-empty and within size limits.'
      : 'Failed to queue audit.'),
  });

  function submit(e: FormEvent): void {
    e.preventDefault();
    if (name.trim() && input.trim()) create.mutate();
  }

  return (
    <Panel title="New audit">
      <form onSubmit={submit} className="space-y-3">
        <div className="flex flex-wrap items-end gap-3">
          <label className="min-w-[220px] flex-1">
            <span className="eyebrow">Name (image ref or filename)</span>
            <input value={name} onChange={(e) => setName(e.target.value)}
              placeholder="app:latest" className="input mt-1 font-mono" />
          </label>
          <label>
            <span className="eyebrow">Kind</span>
            <select value={kind} onChange={(e) => setKind(e.target.value as ContainerAuditKind)}
              className="input mt-1 block">
              {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </select>
          </label>
          <button type="submit" disabled={create.isPending || !name.trim() || !input.trim()}
            className="rounded-md bg-signal px-4 py-2 font-display text-sm font-semibold text-base-900 transition hover:bg-signal-soft disabled:opacity-50">
            {create.isPending ? 'Queuing…' : 'Analyze'}
          </button>
        </div>
        <label className="block">
          <span className="eyebrow">{active.hint}</span>
          <textarea value={input} onChange={(e) => setInput(e.target.value)} rows={8}
            placeholder={active.placeholder}
            className="input mt-1 resize-y font-mono text-xs leading-relaxed" spellCheck={false} />
        </label>
        {err && <p className="rounded border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">{err}</p>}
        <p className="font-mono text-[10px] leading-relaxed text-ink-faint">
          Analysis is fully offline — no image is built, pulled, or contacted. Findings are heuristic and audit-logged.
        </p>
      </form>
    </Panel>
  );
}
