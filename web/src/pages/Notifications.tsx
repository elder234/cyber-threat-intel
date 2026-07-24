import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useHasRole } from '../lib/auth';
import { clsx, relTime } from '../lib/ui';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner } from '../components/primitives';
import { PageHeader } from './Iocs';
import type {
  AlertRule, AlertRuleEventType, ChannelType, NotificationChannel, Severity,
} from '../lib/types';

// ⚠️ RUNTIME VERIFICATION REQUIRED — depends on the live API, DB and the
// in-process alert engine (services/api/src/alerts/engine.ts).

const CHANNEL_TYPES: ChannelType[] = ['slack', 'discord', 'telegram', 'webhook', 'email'];
const EVENT_TYPES: AlertRuleEventType[] = ['ioc.new', 'cve.kev', 'cve.new', 'scan.finding', 'feed.error'];
const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

// The config keys each channel type expects, so the form can prompt for them.
const CONFIG_HINTS: Record<ChannelType, string[]> = {
  slack: ['url'],
  discord: ['url'],
  webhook: ['url', 'secret'],
  telegram: ['bot_token', 'chat_id'],
  email: ['to', 'SMTP_HOST'],
};

export default function NotificationsPage(): JSX.Element {
  const canManage = useHasRole('admin', 'analyst');

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alerting"
        subtitle="Module 11 · notification channels + alert rules"
      />
      <ChannelsSection canManage={canManage} />
      <RulesSection canManage={canManage} />
    </div>
  );
}

// ---------------------------------------------------------------- //
// Channels
// ---------------------------------------------------------------- //
function ChannelsSection({ canManage }: { canManage: boolean }): JSX.Element {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ['channels'], queryFn: api.channels.list });
  const [showForm, setShowForm] = useState(false);

  const remove = useMutation({
    mutationFn: (id: string) => api.channels.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['channels'] }),
  });
  const toggle = useMutation({
    mutationFn: (c: NotificationChannel) => api.channels.update(c.id, { enabled: !c.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['channels'] }),
  });
  const test = useMutation({ mutationFn: (id: string) => api.channels.test(id) });

  const rows = query.data?.data ?? [];

  return (
    <Panel
      title="Notification channels"
      action={canManage ? (
        <button
          onClick={() => setShowForm((v) => !v)}
          className="rounded border border-base-500 px-2.5 py-1 text-xs font-semibold text-ink-dim transition hover:border-signal hover:text-signal"
        >
          {showForm ? 'Cancel' : 'New channel'}
        </button>
      ) : undefined}
      bodyClassName="p-4 space-y-4"
    >
      {showForm && <ChannelForm onDone={() => { setShowForm(false); qc.invalidateQueries({ queryKey: ['channels'] }); }} />}

      {query.isLoading ? <Spinner label="Loading channels" />
        : query.error ? <ErrorState error={query.error} retry={() => query.refetch()} />
        : rows.length === 0 ? <EmptyState title="No channels configured" hint="Add a Slack, Discord, Telegram, webhook or email destination." />
        : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-base-600 text-left">
                <Th>Name</Th><Th>Type</Th><Th>Min sev</Th><Th>Health</Th>
                {canManage && <Th className="text-right">Actions</Th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} className="border-b border-base-700/60">
                  <td className="py-2">
                    <span className="font-mono text-ink">{c.name}</span>
                    {!c.enabled && <span className="ml-2 text-[10px] uppercase text-ink-faint">disabled</span>}
                  </td>
                  <td className="py-2 font-mono text-xs uppercase text-ink-dim">{c.type}</td>
                  <td className="py-2"><SeverityChip severity={c.min_severity} /></td>
                  <td className="py-2 text-xs">
                    {c.last_error
                      ? <span className="text-sev-critical" title={c.last_error}>error · {relTime(c.updated_at)}</span>
                      : c.last_ok_at
                        ? <span className="text-good">ok · {relTime(c.last_ok_at)} ago</span>
                        : <span className="text-ink-faint">untested</span>}
                  </td>
                  {canManage && (
                    <td className="py-2">
                      <div className="flex justify-end gap-2">
                        <RowButton onClick={() => test.mutate(c.id)} busy={test.isPending && test.variables === c.id}>Test</RowButton>
                        <RowButton onClick={() => toggle.mutate(c)}>{c.enabled ? 'Disable' : 'Enable'}</RowButton>
                        <RowButton danger onClick={() => { if (confirm(`Delete channel "${c.name}"?`)) remove.mutate(c.id); }}>Delete</RowButton>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}

      {test.data && (
        <p className={clsx('font-mono text-xs', test.data.ok ? 'text-good' : 'text-sev-critical')}>
          {test.data.channel}: {test.data.ok ? 'delivered' : `failed — ${test.data.error ?? 'unknown'}`}
        </p>
      )}
    </Panel>
  );
}

function ChannelForm({ onDone }: { onDone: () => void }): JSX.Element {
  const [name, setName] = useState('');
  const [type, setType] = useState<ChannelType>('slack');
  const [minSeverity, setMinSeverity] = useState<Severity>('low');
  const [config, setConfig] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.channels.create({ name, type, min_severity: minSeverity, config }),
    onSuccess: onDone,
    onError: (e) => setErr(e instanceof Error ? e.message : 'failed'),
  });

  const hints = CONFIG_HINTS[type];

  return (
    <form
      onSubmit={(e) => { e.preventDefault(); setErr(null); create.mutate(); }}
      className="grid grid-cols-1 gap-3 rounded-md border border-base-600 bg-base-800/50 p-4 md:grid-cols-2"
    >
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} required
          className="input" placeholder="soc-slack" />
      </Field>
      <Field label="Type">
        <select value={type} onChange={(e) => { setType(e.target.value as ChannelType); setConfig({}); }} className="input">
          {CHANNEL_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </Field>
      <Field label="Minimum severity">
        <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as Severity)} className="input">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </Field>
      <div className="md:col-span-2 grid grid-cols-1 gap-3 md:grid-cols-2">
        {hints.map((key) => (
          <Field key={key} label={key}>
            <input
              value={config[key] ?? ''}
              onChange={(e) => setConfig((c) => ({ ...c, [key]: e.target.value }))}
              className="input"
              placeholder={key === 'url' ? 'https://…' : ''}
            />
          </Field>
        ))}
      </div>
      {err && <p className="md:col-span-2 font-mono text-xs text-sev-critical">{err}</p>}
      <div className="md:col-span-2 flex justify-end gap-2">
        <button type="submit" disabled={create.isPending}
          className="rounded border border-signal px-3 py-1.5 text-xs font-semibold text-signal transition hover:bg-signal/10 disabled:opacity-50">
          {create.isPending ? 'Saving…' : 'Create channel'}
        </button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------- //
// Rules
// ---------------------------------------------------------------- //
function RulesSection({ canManage }: { canManage: boolean }): JSX.Element {
  const qc = useQueryClient();
  const rulesQ = useQuery({ queryKey: ['alert-rules'], queryFn: api.alertRules.list });
  const channelsQ = useQuery({ queryKey: ['channels'], queryFn: api.channels.list });
  const [showForm, setShowForm] = useState(false);

  const remove = useMutation({
    mutationFn: (id: string) => api.alertRules.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-rules'] }),
  });
  const toggle = useMutation({
    mutationFn: (r: AlertRule) => api.alertRules.update(r.id, { enabled: !r.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-rules'] }),
  });

  const rows = rulesQ.data?.data ?? [];
  const channelNames = useMemo(() => (channelsQ.data?.data ?? []).map((c) => c.name), [channelsQ.data]);

  return (
    <Panel
      title="Alert rules"
      action={canManage ? (
        <button
          onClick={() => setShowForm((v) => !v)}
          className="rounded border border-base-500 px-2.5 py-1 text-xs font-semibold text-ink-dim transition hover:border-signal hover:text-signal"
        >
          {showForm ? 'Cancel' : 'New rule'}
        </button>
      ) : undefined}
      bodyClassName="p-4 space-y-4"
    >
      {showForm && (
        <RuleForm
          channels={channelNames}
          onDone={() => { setShowForm(false); qc.invalidateQueries({ queryKey: ['alert-rules'] }); }}
        />
      )}

      {rulesQ.isLoading ? <Spinner label="Loading rules" />
        : rulesQ.error ? <ErrorState error={rulesQ.error} retry={() => rulesQ.refetch()} />
        : rows.length === 0 ? <EmptyState title="No alert rules" hint="Rules bind an event type + conditions to a severity and channels." />
        : (
          <div className="space-y-2">
            {rows.map((r) => (
              <div key={r.id} className="flex items-start justify-between gap-4 rounded-md border border-base-700/60 bg-base-800/40 p-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-display text-sm font-semibold text-ink">{r.name}</span>
                    <SeverityChip severity={r.severity} />
                    {!r.enabled && <span className="text-[10px] uppercase text-ink-faint">disabled</span>}
                  </div>
                  <p className="mt-0.5 font-mono text-[11px] text-ink-faint">
                    on <span className="text-ink-dim">{r.event_type}</span>
                    {' · '}{summarizeConditions(r)}
                    {r.throttle_secs > 0 && ` · throttle ${r.throttle_secs}s`}
                  </p>
                  {r.channels.length > 0 && (
                    <p className="mt-0.5 text-[11px] text-ink-dim">→ {r.channels.join(', ')}</p>
                  )}
                </div>
                {canManage && (
                  <div className="flex shrink-0 gap-2">
                    <RowButton onClick={() => toggle.mutate(r)}>{r.enabled ? 'Disable' : 'Enable'}</RowButton>
                    <RowButton danger onClick={() => { if (confirm(`Delete rule "${r.name}"?`)) remove.mutate(r.id); }}>Delete</RowButton>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
    </Panel>
  );
}

function RuleForm({ channels, onDone }: { channels: string[]; onDone: () => void }): JSX.Element {
  const [name, setName] = useState('');
  const [eventType, setEventType] = useState<AlertRuleEventType>('ioc.new');
  const [severity, setSeverity] = useState<Severity>('medium');
  const [minSeverity, setMinSeverity] = useState<Severity | ''>('');
  const [tagsAny, setTagsAny] = useState('');
  const [sources, setSources] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [throttle, setThrottle] = useState(0);
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.alertRules.create({
      name,
      event_type: eventType,
      severity,
      conditions: {
        ...(minSeverity ? { min_severity: minSeverity } : {}),
        ...(csv(tagsAny).length ? { tags_any: csv(tagsAny) } : {}),
        ...(csv(sources).length ? { sources: csv(sources) } : {}),
      },
      channels: selected,
      throttle_secs: throttle,
    }),
    onSuccess: onDone,
    onError: (e) => setErr(e instanceof Error ? e.message : 'failed'),
  });

  return (
    <form
      onSubmit={(e) => { e.preventDefault(); setErr(null); create.mutate(); }}
      className="grid grid-cols-1 gap-3 rounded-md border border-base-600 bg-base-800/50 p-4 md:grid-cols-2"
    >
      <Field label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} required className="input" placeholder="KEV on critical CVEs" />
      </Field>
      <Field label="Event type">
        <select value={eventType} onChange={(e) => setEventType(e.target.value as AlertRuleEventType)} className="input">
          {EVENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </Field>
      <Field label="Alert severity">
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className="input">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </Field>
      <Field label="Match min severity (optional)">
        <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as Severity | '')} className="input">
          <option value="">any</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </Field>
      <Field label="Match tags (any, comma-sep)">
        <input value={tagsAny} onChange={(e) => setTagsAny(e.target.value)} className="input" placeholder="c2, ransomware" />
      </Field>
      <Field label="Match sources (comma-sep)">
        <input value={sources} onChange={(e) => setSources(e.target.value)} className="input" placeholder="otx, abuse.ch" />
      </Field>
      <Field label="Throttle (seconds)">
        <input type="number" min={0} value={throttle} onChange={(e) => setThrottle(Number(e.target.value) || 0)} className="input" />
      </Field>
      <Field label="Channels">
        {channels.length === 0
          ? <p className="text-xs text-ink-faint">No channels yet — create one above.</p>
          : (
            <div className="flex flex-wrap gap-2">
              {channels.map((c) => (
                <label key={c} className="flex items-center gap-1.5 rounded border border-base-600 px-2 py-1 text-xs text-ink-dim">
                  <input
                    type="checkbox"
                    checked={selected.includes(c)}
                    onChange={(e) => setSelected((s) => e.target.checked ? [...s, c] : s.filter((x) => x !== c))}
                  />
                  {c}
                </label>
              ))}
            </div>
          )}
      </Field>
      {err && <p className="md:col-span-2 font-mono text-xs text-sev-critical">{err}</p>}
      <div className="md:col-span-2 flex justify-end">
        <button type="submit" disabled={create.isPending}
          className="rounded border border-signal px-3 py-1.5 text-xs font-semibold text-signal transition hover:bg-signal/10 disabled:opacity-50">
          {create.isPending ? 'Saving…' : 'Create rule'}
        </button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------- //
// Small helpers
// ---------------------------------------------------------------- //
function csv(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

function summarizeConditions(r: AlertRule): string {
  const c = r.conditions ?? {};
  const parts: string[] = [];
  if (c.min_severity) parts.push(`sev≥${c.min_severity}`);
  if (c.tags_any?.length) parts.push(`tags∈{${c.tags_any.join(',')}}`);
  if (c.tags_all?.length) parts.push(`tags⊇{${c.tags_all.join(',')}}`);
  if (c.sources?.length) parts.push(`src∈{${c.sources.join(',')}}`);
  if (c.value_regex) parts.push(`value~/${c.value_regex}/`);
  return parts.length ? parts.join(' ∧ ') : 'any';
}

function Th({ children, className }: { children: React.ReactNode; className?: string }): JSX.Element {
  return <th className={clsx('pb-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-ink-faint', className)}>{children}</th>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }): JSX.Element {
  return (
    <label className="flex flex-col gap-1">
      <span className="eyebrow">{label}</span>
      {children}
    </label>
  );
}

function RowButton({
  children, onClick, busy, danger,
}: { children: React.ReactNode; onClick: () => void; busy?: boolean; danger?: boolean }): JSX.Element {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className={clsx(
        'rounded border px-2 py-1 text-[11px] font-semibold transition disabled:opacity-50',
        danger
          ? 'border-base-500 text-ink-dim hover:border-sev-critical hover:text-sev-critical'
          : 'border-base-500 text-ink-dim hover:border-signal hover:text-signal',
      )}
    >
      {busy ? '…' : children}
    </button>
  );
}
