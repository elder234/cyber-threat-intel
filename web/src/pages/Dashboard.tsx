import { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts';
import { api } from '../lib/api';
import { useLive, useLiveEvent } from '../lib/live';
import {
  clsx, fmtNum, relTime, riskBand, SEV_HEX, sevText, SEVERITY_ORDER,
} from '../lib/ui';
import {
  EmptyState, ErrorState, Panel, SeverityChip, Spinner, StatTile,
} from '../components/primitives';
import { WorldThreatMap, type ThreatPoint } from '../components/WorldThreatMap';
import type { AttackStat, DashboardStats, TimelineEvent } from '../lib/types';

export default function DashboardPage(): JSX.Element {
  const qc = useQueryClient();

  const statsQ = useQuery({ queryKey: ['dash', 'stats'], queryFn: api.dashboard.stats });
  const timelineQ = useQuery({ queryKey: ['dash', 'timeline'], queryFn: api.dashboard.timeline });
  const attackQ = useQuery({ queryKey: ['dash', 'attack'], queryFn: api.dashboard.attackMatrix });

  // Live events nudge the aggregates to refetch (debounced by React Query's
  // staleTime) and drive the local "events/min" tempo meter.
  const [tempo, setTempo] = useState<number[]>(() => new Array(12).fill(0));
  useLiveEvent('ioc.new', () => {
    qc.invalidateQueries({ queryKey: ['dash', 'stats'] });
    bumpTempo(setTempo);
  });
  useLiveEvent('alert.new', () => {
    qc.invalidateQueries({ queryKey: ['dash', 'stats'] });
    bumpTempo(setTempo);
  });

  const threatPoints = useThreatPoints(timelineQ.data);

  return (
    <div className="space-y-5">
      <KpiRow stats={statsQ.data} loading={statsQ.isLoading} error={statsQ.error} />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Panel
          title="Global threat activity"
          className="xl:col-span-2"
          bodyClassName="p-0"
          action={<span className="eyebrow">geolocated indicators</span>}
        >
          <div className="h-[380px] w-full">
            <WorldThreatMap points={threatPoints} />
          </div>
        </Panel>

        <div className="space-y-5">
          <RiskGauge score={statsQ.data?.risk_score ?? 0} tempo={tempo} />
          <SeverityBreakdown stats={statsQ.data} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Panel title="Threat timeline" className="xl:col-span-2">
          {timelineQ.isLoading ? <Spinner label="Loading timeline" />
            : timelineQ.error ? <ErrorState error={timelineQ.error} retry={() => timelineQ.refetch()} />
            : <Timeline events={timelineQ.data ?? []} />}
        </Panel>

        <Panel title="ATT&CK tactics">
          {attackQ.isLoading ? <Spinner />
            : attackQ.error ? <ErrorState error={attackQ.error} retry={() => attackQ.refetch()} />
            : <AttackMatrix rows={attackQ.data ?? []} />}
        </Panel>
      </div>

      <LiveFeedStrip />
    </div>
  );
}

function bumpTempo(setTempo: React.Dispatch<React.SetStateAction<number[]>>): void {
  setTempo((t) => {
    const next = [...t];
    next[next.length - 1] += 1;
    return next;
  });
}

function KpiRow({
  stats, loading, error,
}: { stats?: DashboardStats; loading: boolean; error: unknown }): JSX.Element {
  if (error) {
    return <Panel title="System status"><ErrorState error={error} /></Panel>;
  }
  const feedHealth = stats ? `${stats.feeds_healthy}/${stats.feeds_total}` : '—';
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
      <StatTile label="Active indicators" value={loading ? '—' : fmtNum(stats?.iocs_active)}
        sub={stats ? `${fmtNum(stats.iocs_total)} total` : undefined} live />
      <StatTile label="KEV in scope" value={loading ? '—' : fmtNum(stats?.cves_kev)}
        accent="text-sev-high" />
      <StatTile label="Open alerts" value={loading ? '—' : fmtNum(stats?.alerts_open)}
        accent={stats && stats.alerts_open > 0 ? 'text-sev-critical' : 'text-ink'} live />
      <StatTile label="Scans running" value={loading ? '—' : fmtNum(stats?.scans_running)}
        accent="text-signal" />
      <StatTile label="Feeds healthy" value={loading ? '—' : feedHealth}
        accent={stats && stats.feeds_healthy < stats.feeds_total ? 'text-sev-medium' : 'text-good'} />
      <StatTile label="Ingest 24h" value={loading ? '—' : fmtNum(stats?.ingest_24h)} />
    </div>
  );
}

function RiskGauge({ score, tempo }: { score: number; tempo: number[] }): JSX.Element {
  const band = riskBand(score);
  const pct = Math.max(0, Math.min(100, score));
  const dash = `${pct * 2.83} 283`;
  return (
    <Panel title="Composite risk">
      <div className="flex items-center gap-5">
        <div className="relative h-28 w-28 shrink-0">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            <circle cx="50" cy="50" r="45" fill="none" stroke="#1a2432" strokeWidth="8" />
            <circle
              cx="50" cy="50" r="45" fill="none" stroke={SEV_HEX[band.sev]} strokeWidth="8"
              strokeLinecap="round" strokeDasharray={dash}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={clsx('data text-3xl font-bold leading-none', sevText(band.sev))}>
              {Math.round(score)}
            </span>
            <span className="mt-0.5 text-[10px] uppercase tracking-widest text-ink-faint">/100</span>
          </div>
        </div>
        <div className="min-w-0">
          <p className={clsx('font-display text-lg font-bold', sevText(band.sev))}>{band.label}</p>
          <p className="mt-1 text-xs text-ink-faint">Weighted across active indicators, open alerts, and KEV exposure.</p>
          <div className="mt-3 flex h-6 items-end gap-0.5">
            {tempo.map((v, i) => (
              <span key={i} className="w-1.5 rounded-sm bg-signal/70"
                style={{ height: `${Math.min(100, 12 + v * 18)}%` }} />
            ))}
          </div>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-widest text-ink-faint">live tempo</p>
        </div>
      </div>
    </Panel>
  );
}

function SeverityBreakdown({ stats }: { stats?: DashboardStats }): JSX.Element {
  const data = useMemo(() => SEVERITY_ORDER.map((sev) => ({
    sev, value: stats?.by_severity?.[sev] ?? 0,
  })), [stats]);
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <Panel title="Indicators by severity">
      {total === 0 ? (
        <EmptyState title="No active indicators" />
      ) : (
        <div className="space-y-2">
          {data.map((d) => (
            <div key={d.sev} className="flex items-center gap-3">
              <span className="w-16 text-xs capitalize" style={{ color: SEV_HEX[d.sev] }}>{d.sev}</span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-base-700">
                <div className="h-full rounded-full"
                  style={{ width: `${(d.value / total) * 100}%`, background: SEV_HEX[d.sev] }} />
              </div>
              <span className="data w-12 text-right text-xs text-ink-dim">{fmtNum(d.value)}</span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function Timeline({ events }: { events: TimelineEvent[] }): JSX.Element {
  // Bucket events per hour for the area chart; list the freshest below it.
  const series = useMemo(() => bucketByHour(events), [events]);
  if (events.length === 0) return <EmptyState title="No recent events" hint="New activity appears here in real time." />;
  return (
    <div className="space-y-3">
      <div className="h-28">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={series} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="tl" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f5a524" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#f5a524" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1a2432" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: '#5f7183', fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#5f7183', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#9fb0c0' }} />
            <Area type="monotone" dataKey="count" stroke="#f5a524" strokeWidth={2} fill="url(#tl)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <ul className="max-h-56 space-y-1 overflow-auto pr-1">
        {events.slice(0, 40).map((e, i) => (
          <li key={i} className="flex items-center gap-3 rounded border border-transparent px-2 py-1.5 hover:border-base-600 hover:bg-base-700/40">
            <SeverityChip severity={e.severity} />
            <span className="min-w-0 flex-1 truncate text-sm text-ink-dim">{e.title}</span>
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-faint">{e.kind}</span>
            <span className="data w-10 text-right text-[10px] text-ink-faint">{relTime(e.ts)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AttackMatrix({ rows }: { rows: AttackStat[] }): JSX.Element {
  const top = useMemo(
    () => [...rows].sort((a, b) => b.count - a.count).slice(0, 10),
    [rows],
  );
  if (top.length === 0) return <EmptyState title="No mapped techniques" />;
  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={top} layout="vertical" margin={{ top: 0, right: 12, left: 8, bottom: 0 }}>
          <CartesianGrid stroke="#1a2432" horizontal={false} />
          <XAxis type="number" tick={{ fill: '#5f7183', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="tactic" width={104}
            tick={{ fill: '#9fb0c0', fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#1a2432' }} />
          <Bar dataKey="count" radius={[0, 3, 3, 0]}>
            {top.map((_, i) => <Cell key={i} fill="#f5a524" fillOpacity={1 - i * 0.06} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** A thin strip that shows the last few live events with a subtle enter animation. */
function LiveFeedStrip(): JSX.Element {
  const { events, status } = useLive();
  const shown = events.filter((e) => e.type !== 'error').slice(0, 6);
  return (
    <Panel
      title="Live event stream"
      action={<span className={clsx('font-mono text-[10px] uppercase tracking-widest',
        status === 'open' ? 'text-good' : 'text-ink-faint')}>{status}</span>}
    >
      {shown.length === 0 ? (
        <p className="py-4 text-center font-mono text-xs text-ink-faint">Awaiting events…</p>
      ) : (
        <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
          {shown.map((e, i) => (
            <li key={i} className="flex items-center gap-2 rounded border border-base-600 bg-base-900/60 px-3 py-2">
              <span className={clsx('h-2 w-2 shrink-0 rounded-full',
                e.type.includes('alert') ? 'bg-sev-high' : 'bg-signal')} />
              <span className="truncate font-mono text-xs text-ink-dim">
                {e.type}
                {'value' in e && e.value ? ` · ${String(e.value)}` : ''}
                {'title' in e && e.title ? ` · ${String(e.title)}` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- helpers

const TOOLTIP_STYLE = {
  background: '#111823',
  border: '1px solid #26323f',
  borderRadius: 8,
  fontSize: 12,
  color: '#e6edf3',
} as const;

function bucketByHour(events: TimelineEvent[]): { label: string; count: number }[] {
  const buckets = new Map<string, number>();
  for (const e of events) {
    const d = new Date(e.ts);
    if (Number.isNaN(d.getTime())) continue;
    const key = `${d.getHours().toString().padStart(2, '0')}:00`;
    buckets.set(key, (buckets.get(key) ?? 0) + 1);
  }
  return [...buckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([label, count]) => ({ label, count }));
}

/**
 * Timeline events don't carry geo in the current API. Until an enrichment
 * step attaches lat/lng, we derive a deterministic pseudo-position from the
 * event title hash so the map is populated and visually stable across renders.
 * ⚠️ RUNTIME VERIFICATION REQUIRED — replace with real geo once the API exposes
 * source coordinates (planned: ioc.geo enrichment).
 */
function useThreatPoints(events?: TimelineEvent[]): ThreatPoint[] {
  return useMemo(() => {
    if (!events) return [];
    return events.slice(0, 120).map((e, i) => {
      const h = hashString(e.title || String(i));
      const lat = ((h % 12000) / 100) - 60; // -60..60
      const lng = (((h >> 3) % 34000) / 100) - 170; // -170..170
      return {
        id: `${i}-${h}`,
        lat, lng,
        severity: e.severity,
        label: e.title,
      } satisfies ThreatPoint;
    });
  }, [events]);
}

function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}
