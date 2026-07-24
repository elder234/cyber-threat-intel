import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useLiveEvent } from '../lib/live';
import { relTime } from '../lib/ui';
import { EmptyState, ErrorState, Panel, SeverityChip, Spinner, StatusPill } from '../components/primitives';
import { PageHeader, Select } from './Iocs';
import type { Alert, AlertStatus, Severity } from '../lib/types';

const STATUSES: (AlertStatus | '')[] = ['', 'open', 'acknowledged', 'resolved', 'suppressed'];
const SEVS: (Severity | '')[] = ['', 'critical', 'high', 'medium', 'low', 'info'];

export default function AlertsPage(): JSX.Element {
  const qc = useQueryClient();
  const [status, setStatus] = useState<AlertStatus | ''>('open');
  const [severity, setSeverity] = useState<Severity | ''>('');

  const query = useQuery({
    queryKey: ['alerts', { status, severity }],
    queryFn: () => api.alerts.list({ status: status || undefined, severity: severity || undefined, limit: 100 }),
  });

  // New alerts pushed over the socket refresh the list immediately.
  useLiveEvent('alert.new', () => qc.invalidateQueries({ queryKey: ['alerts'] }));

  const ack = useMutation({
    mutationFn: (id: string) => api.alerts.ack(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  });
  const resolve = useMutation({
    mutationFn: (id: string) => api.alerts.resolve(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  });

  const rows = query.data?.data ?? [];

  return (
    <div className="space-y-4">
      <PageHeader title="Alerts" subtitle="Triage queue · acknowledge and resolve" />

      <Panel bodyClassName="p-3">
        <div className="flex flex-wrap items-center gap-3">
          <Select label="Status" value={status} onChange={setStatus} options={STATUSES} />
          <Select label="Severity" value={severity} onChange={setSeverity} options={SEVS} />
        </div>
      </Panel>

      {query.isLoading ? <Spinner label="Loading alerts" />
        : query.error ? <Panel><ErrorState error={query.error} retry={() => query.refetch()} /></Panel>
        : rows.length === 0 ? <Panel><EmptyState title="Queue clear" hint="No alerts match the current filters." /></Panel>
        : (
          <div className="space-y-2">
            {rows.map((a) => (
              <AlertCard
                key={a.id} alert={a}
                onAck={() => ack.mutate(a.id)}
                onResolve={() => resolve.mutate(a.id)}
                busy={ack.isPending || resolve.isPending}
              />
            ))}
          </div>
        )}
    </div>
  );
}

function AlertCard({
  alert, onAck, onResolve, busy,
}: { alert: Alert; onAck: () => void; onResolve: () => void; busy: boolean }): JSX.Element {
  return (
    <div className="panel flex items-start gap-4 p-4">
      <div className="pt-0.5"><SeverityChip severity={alert.severity} /></div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <h3 className="truncate font-display text-sm font-semibold text-ink">{alert.title}</h3>
          <StatusPill status={alert.status} />
        </div>
        {alert.summary && <p className="mt-1 line-clamp-2 text-xs text-ink-dim">{alert.summary}</p>}
        <p className="mt-1.5 font-mono text-[10px] uppercase tracking-wider text-ink-faint">
          {alert.source ?? 'system'} · {relTime(alert.created_at)} ago
        </p>
      </div>
      <div className="flex shrink-0 gap-2">
        {alert.status === 'open' && (
          <button
            disabled={busy} onClick={onAck}
            className="rounded border border-base-500 px-2.5 py-1 text-xs text-ink-dim transition hover:border-sev-low hover:text-sev-low disabled:opacity-50"
          >Ack</button>
        )}
        {alert.status !== 'resolved' && (
          <button
            disabled={busy} onClick={onResolve}
            className="rounded border border-base-500 px-2.5 py-1 text-xs text-ink-dim transition hover:border-good hover:text-good disabled:opacity-50"
          >Resolve</button>
        )}
      </div>
    </div>
  );
}
