import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useLiveEvent } from '../lib/live';
import { clsx, relTime } from '../lib/ui';
import { EmptyState, ErrorState, Panel, Spinner } from '../components/primitives';
import { PageHeader } from './Iocs';
import type { Feed } from '../lib/types';

export default function FeedsPage(): JSX.Element {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ['feeds'], queryFn: api.feeds.list });

  useLiveEvent('feed.run', () => qc.invalidateQueries({ queryKey: ['feeds'] }));

  const sync = useMutation({
    mutationFn: (id: string) => api.feeds.sync(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['feeds'] }),
  });

  const rows = query.data?.data ?? [];

  return (
    <div className="space-y-4">
      <PageHeader title="Threat Feeds" subtitle="Aggregation sources · CISA · abuse.ch · EPSS · URLhaus" />

      {query.isLoading ? <Spinner label="Loading feeds" />
        : query.error ? <Panel><ErrorState error={query.error} retry={() => query.refetch()} /></Panel>
        : rows.length === 0 ? <Panel><EmptyState title="No feeds configured" /></Panel>
        : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {rows.map((f) => (
              <FeedCard key={f.id} feed={f} onSync={() => sync.mutate(f.id)}
                syncing={sync.isPending && sync.variables === f.id} />
            ))}
          </div>
        )}
    </div>
  );
}

function statusColor(status: string | null): string {
  switch (status) {
    case 'ok':
    case 'success': return 'text-good';
    case 'running': return 'text-signal';
    case 'error':
    case 'failed': return 'text-sev-critical';
    default: return 'text-ink-faint';
  }
}

function FeedCard({ feed, onSync, syncing }: { feed: Feed; onSync: () => void; syncing: boolean }): JSX.Element {
  return (
    <div className="panel flex flex-col p-4">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <h3 className="truncate font-display text-sm font-semibold text-ink">{feed.name}</h3>
          <p className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">
            {feed.provider} · {feed.format}
          </p>
        </div>
        <span className={clsx('h-2 w-2 rounded-full',
          feed.enabled ? 'bg-good' : 'bg-base-500')} title={feed.enabled ? 'enabled' : 'disabled'} />
      </div>

      <dl className="mt-3 grid grid-cols-2 gap-y-1.5 text-xs">
        <dt className="text-ink-faint">Last run</dt>
        <dd className="data text-right text-ink-dim">{feed.last_run_at ? `${relTime(feed.last_run_at)} ago` : 'never'}</dd>
        <dt className="text-ink-faint">Status</dt>
        <dd className={clsx('text-right font-mono uppercase', statusColor(feed.last_status))}>{feed.last_status ?? '—'}</dd>
        <dt className="text-ink-faint">Items</dt>
        <dd className="data text-right text-ink-dim">{feed.last_item_count ?? '—'}</dd>
        <dt className="text-ink-faint">Interval</dt>
        <dd className="data text-right text-ink-dim">{Math.round(feed.interval_secs / 60)}m</dd>
      </dl>

      <button
        onClick={onSync}
        disabled={syncing}
        className="mt-4 rounded border border-base-500 py-1.5 text-xs font-semibold text-ink-dim transition hover:border-signal hover:text-signal disabled:opacity-50"
      >
        {syncing ? 'Queuing…' : 'Sync now'}
      </button>
    </div>
  );
}
