import { useMemo, useState } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../lib/api';
import { clsx, relTime, SEVERITY_ORDER } from '../lib/ui';
import { useHasRole } from '../lib/auth';
import { DataTable, type Column } from '../components/DataTable';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner, StatusPill } from '../components/primitives';
import { PageHeader, Select, Pager } from './Iocs';
import type {
  DetectionRule, RuleFormat, RuleStatus, RuleValidation, Severity,
} from '../lib/types';

const FORMATS: RuleFormat[] = ['yara', 'sigma'];
const STATUSES: RuleStatus[] = ['stable', 'test', 'experimental', 'deprecated'];
const PAGE = 50;

export default function RulesPage(): JSX.Element {
  const canWrite = useHasRole('admin', 'analyst');
  const [format, setFormat] = useState<RuleFormat | ''>('');
  const [status, setStatus] = useState<RuleStatus | ''>('');
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);
  const [editor, setEditor] = useState<EditorTarget | null>(null);

  const query = useQuery({
    queryKey: ['rules', { format, status, q, offset }],
    queryFn: () => api.rules.list({
      format: format || undefined,
      status: status || undefined,
      q: q || undefined,
      limit: PAGE,
      offset,
    }),
    placeholderData: keepPreviousData,
  });

  const total = query.data?.pagination.total ?? 0;
  const rows = query.data?.data ?? [];

  const columns: Column<DetectionRule>[] = [
    { key: 'format', header: 'Fmt', width: '64px',
      cell: (r) => (
        <span className={clsx('font-mono text-[10px] font-semibold uppercase tracking-wider',
          r.format === 'yara' ? 'text-sev-medium' : 'text-sev-low')}>{r.format}</span>
      ) },
    { key: 'name', header: 'Rule',
      cell: (r) => (
        <button onClick={() => setEditor({ mode: 'view', id: r.id })}
          className="text-left text-ink hover:text-signal">
          <span className="block truncate">{r.name}</span>
          {r.rule_id_ext && <span className="font-mono text-[10px] text-ink-faint">{r.rule_id_ext}</span>}
        </button>
      ) },
    { key: 'sev', header: 'Sev', width: '92px', cell: (r) => <SeverityChip severity={r.severity} /> },
    { key: 'status', header: 'Status', width: '112px', cell: (r) => <StatusPill status={r.status} /> },
    { key: 'valid', header: 'Valid', width: '84px',
      cell: (r) => <ValidBadge valid={r.is_valid} error={r.validation_error} /> },
    { key: 'enabled', header: 'On', width: '54px',
      cell: (r) => (
        <span className={clsx('font-mono text-[10px] uppercase',
          r.is_enabled ? 'text-good' : 'text-ink-faint')}>{r.is_enabled ? 'yes' : 'off'}</span>
      ) },
    { key: 'attack', header: 'ATT&CK',
      cell: (r) => (
        <div className="flex flex-wrap gap-1">
          {r.technique_ids.slice(0, 3).map((t) => (
            <span key={t} className="rounded bg-base-700 px-1.5 py-0.5 font-mono text-[10px] text-ink-dim">{t}</span>
          ))}
          {r.technique_ids.length > 3 && <span className="text-[10px] text-ink-faint">+{r.technique_ids.length - 3}</span>}
        </div>
      ) },
    { key: 'updated', header: 'Updated', width: '82px',
      cell: (r) => <span className="data text-xs text-ink-faint">{relTime(r.updated_at)}</span> },
  ];

  function resetAnd<T>(setter: (v: T) => void) {
    return (v: T) => { setOffset(0); setter(v); };
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Detection Rules"
        subtitle={`${total.toLocaleString()} YARA / Sigma rules`}
        action={canWrite ? (
          <button
            onClick={() => setEditor({ mode: 'create' })}
            className="rounded-md border border-signal/50 bg-signal/10 px-3 py-1.5 text-sm font-semibold text-signal transition hover:bg-signal/20"
          >
            + New rule
          </button>
        ) : undefined}
      />

      <Panel bodyClassName="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => resetAnd(setQ)(e.target.value)}
            placeholder="Filter by name…"
            className="min-w-[220px] flex-1 rounded-md border border-base-600 bg-base-900 px-3 py-1.5 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
          />
          <Select value={format} onChange={resetAnd(setFormat)} label="Format" options={['', ...FORMATS]} />
          <Select value={status} onChange={resetAnd(setStatus)} label="Status" options={['', ...STATUSES]} />
        </div>
      </Panel>

      <Panel bodyClassName="p-0">
        {query.isLoading ? <Spinner label="Loading rules" />
          : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
          : (
            <>
              <DataTable
                columns={columns}
                rows={rows}
                keyFn={(r) => r.id}
                empty={<EmptyState title="No detection rules"
                  hint={canWrite ? 'Create a YARA or Sigma rule to get started.' : 'No rules match the current filters.'} />}
              />
              <Pager offset={offset} pageSize={PAGE} total={total} onChange={setOffset} fetching={query.isFetching} />
            </>
          )}
      </Panel>

      {editor && (
        <RuleDrawer
          target={editor}
          canWrite={canWrite}
          onClose={() => setEditor(null)}
        />
      )}
    </div>
  );
}

function ValidBadge({ valid, error }: { valid: boolean | null; error: string | null }): JSX.Element {
  if (valid === null) return <span className="font-mono text-[10px] text-ink-faint">—</span>;
  return (
    <span
      title={error ?? undefined}
      className={clsx('font-mono text-[10px] font-semibold uppercase',
        valid ? 'text-good' : 'text-sev-critical')}
    >
      {valid ? 'valid' : 'invalid'}
    </span>
  );
}

// ── Drawer: view / create / edit ────────────────────────────────────────────

type EditorTarget = { mode: 'create' } | { mode: 'view'; id: string };

function RuleDrawer({
  target, canWrite, onClose,
}: { target: EditorTarget; canWrite: boolean; onClose: () => void }): JSX.Element {
  const qc = useQueryClient();
  const isCreate = target.mode === 'create';

  const detail = useQuery({
    queryKey: ['rule', target.mode === 'view' ? target.id : null],
    queryFn: () => api.rules.get((target as { id: string }).id),
    enabled: target.mode === 'view',
  });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['rules'] });
    if (target.mode === 'view') void qc.invalidateQueries({ queryKey: ['rule', target.id] });
  };

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-2xl flex-col border-l border-base-600 bg-base-800 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-base-600 px-5 py-3">
          <h2 className="font-display text-base font-bold text-ink">
            {isCreate ? 'New detection rule' : detail.data?.name ?? 'Rule'}
          </h2>
          <button onClick={onClose} className="text-ink-faint hover:text-ink">✕</button>
        </header>

        <div className="min-h-0 flex-1 overflow-auto p-5">
          {target.mode === 'view' && detail.isLoading ? <Spinner label="Loading rule" />
            : target.mode === 'view' && detail.error ? <ErrorState error={detail.error} retry={() => detail.refetch()} />
            : (
              <RuleForm
                initial={target.mode === 'view' ? detail.data : undefined}
                canWrite={canWrite}
                onSaved={() => { invalidate(); onClose(); }}
              />
            )}
        </div>
      </div>
    </div>
  );
}

function RuleForm({
  initial, canWrite, onSaved,
}: { initial?: DetectionRule; canWrite: boolean; onSaved: () => void }): JSX.Element {
  const editing = Boolean(initial);
  const [format, setFormat] = useState<RuleFormat>(initial?.format ?? 'sigma');
  const [name, setName] = useState(initial?.name ?? '');
  const [content, setContent] = useState(initial?.content ?? '');
  const [severity, setSeverity] = useState<Severity>(initial?.severity ?? 'medium');
  const [ruleStatus, setRuleStatus] = useState<RuleStatus>(initial?.status ?? 'experimental');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [isEnabled, setIsEnabled] = useState(initial?.is_enabled ?? true);
  const [check, setCheck] = useState<RuleValidation | null>(null);

  const validateM = useMutation({
    mutationFn: () => api.rules.validate(format, content),
    onSuccess: (v) => setCheck(v),
  });

  const saveM = useMutation({
    mutationFn: async () => {
      if (editing && initial) {
        return api.rules.update(initial.id, {
          content, name: name || undefined, severity, status: ruleStatus,
          description, is_enabled: isEnabled,
        });
      }
      return api.rules.create({
        format, content, name: name || undefined, severity, status: ruleStatus,
        description, is_enabled: isEnabled,
      });
    },
    onSuccess: onSaved,
  });

  const saveErr = saveM.error;
  const saveErrMsg = useMemo(() => {
    if (!saveErr) return null;
    if (saveErr instanceof ApiError) {
      const body = saveErr.body as { message?: string; error?: string } | null;
      return body?.message ?? body?.error ?? saveErr.message;
    }
    return (saveErr as Error).message;
  }, [saveErr]);

  const readOnly = !canWrite;

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => { e.preventDefault(); if (!readOnly) saveM.mutate(); }}
    >
      <div className="grid grid-cols-2 gap-3">
        <Field label="Format">
          <select
            value={format}
            disabled={editing || readOnly}
            onChange={(e) => setFormat(e.target.value as RuleFormat)}
            className={selectCls}
          >
            {FORMATS.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
        </Field>
        <Field label="Name (blank = parse from rule)">
          <input value={name} readOnly={readOnly} onChange={(e) => setName(e.target.value)}
            placeholder="auto" className={inputCls} />
        </Field>
        <Field label="Severity">
          <select value={severity} disabled={readOnly} onChange={(e) => setSeverity(e.target.value as Severity)} className={selectCls}>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Status">
          <select value={ruleStatus} disabled={readOnly} onChange={(e) => setRuleStatus(e.target.value as RuleStatus)} className={selectCls}>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
      </div>

      <Field label="Description">
        <input value={description} readOnly={readOnly} onChange={(e) => setDescription(e.target.value)}
          placeholder="What this rule detects" className={inputCls} />
      </Field>

      <Field label={`${format.toUpperCase()} source`}>
        <textarea
          value={content}
          readOnly={readOnly}
          onChange={(e) => { setContent(e.target.value); setCheck(null); }}
          spellCheck={false}
          rows={14}
          placeholder={format === 'yara' ? 'rule Example {\n  condition:\n    true\n}' : 'title: Example\ndetection:\n  condition: selection'}
          className="w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 font-mono text-xs leading-relaxed text-ink placeholder:text-ink-faint focus:border-signal"
        />
      </Field>

      <label className="flex items-center gap-2 text-sm text-ink-dim">
        <input type="checkbox" checked={isEnabled} disabled={readOnly}
          onChange={(e) => setIsEnabled(e.target.checked)} className="accent-signal" />
        Enabled (evaluated against incoming data)
      </label>

      {check && (
        <div className={clsx('rounded-md border px-3 py-2 text-xs',
          check.valid ? 'border-good/40 bg-good/10 text-good' : 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical')}>
          <p className="font-mono font-semibold uppercase tracking-wider">
            {check.valid ? 'valid' : 'invalid'}
          </p>
          {check.error && <p className="mt-1 text-ink-dim">{check.error}</p>}
          {check.techniqueIds.length > 0 && (
            <p className="mt-1 text-ink-faint">ATT&CK: {check.techniqueIds.join(', ')}</p>
          )}
        </div>
      )}

      {saveErrMsg && (
        <p className="font-mono text-xs text-sev-critical">{saveErrMsg}</p>
      )}

      <div className="flex items-center gap-2 pt-1">
        <button
          type="button"
          onClick={() => validateM.mutate()}
          disabled={!content.trim() || validateM.isPending}
          className="rounded-md border border-base-500 px-3 py-1.5 text-sm text-ink-dim transition hover:border-signal hover:text-signal disabled:opacity-40"
        >
          {validateM.isPending ? 'Checking…' : 'Validate'}
        </button>
        {!readOnly && (
          <button
            type="submit"
            disabled={!content.trim() || saveM.isPending}
            className="rounded-md border border-signal/50 bg-signal/10 px-4 py-1.5 text-sm font-semibold text-signal transition hover:bg-signal/20 disabled:opacity-40"
          >
            {saveM.isPending ? 'Saving…' : editing ? 'Save changes' : 'Create rule'}
          </button>
        )}
      </div>
    </form>
  );
}

const inputCls = 'w-full rounded-md border border-base-600 bg-base-900 px-3 py-1.5 text-sm text-ink placeholder:text-ink-faint focus:border-signal read-only:opacity-70';
const selectCls = 'w-full rounded-md border border-base-600 bg-base-900 px-2 py-1.5 text-sm text-ink focus:border-signal disabled:opacity-70';

function Field({ label, children }: { label: string; children: JSX.Element }): JSX.Element {
  return (
    <label className="block space-y-1">
      <span className="eyebrow">{label}</span>
      {children}
    </label>
  );
}
