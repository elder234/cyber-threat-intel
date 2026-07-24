import { type ReactNode, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { useLive } from '../lib/live';
import { clsx, relTime, sevDot } from '../lib/ui';
import type { LiveEvent, Severity } from '../lib/types';

// ---------------------------------------------------------------- //
// Navigation model. Icons are inline strokes (no icon dependency) so
// the bundle stays lean and the glyphs match the console's hairline
// aesthetic.
// ---------------------------------------------------------------- //
const NAV: { to: string; label: string; glyph: JSX.Element }[] = [
  { to: '/', label: 'Overview', glyph: <Glyph d="M3 12h6l2-7 4 14 2-5h4" /> },
  { to: '/iocs', label: 'Indicators', glyph: <Glyph d="M12 3l8 4v6c0 4-3.5 7-8 8-4.5-1-8-4-8-8V7z" /> },
  { to: '/cves', label: 'Vulnerabilities', glyph: <Glyph d="M12 3v6m0 4v.01M4 20h16L12 4z" /> },
  { to: '/rules', label: 'Detections', glyph: <Glyph d="M4 5h16M4 12h16M4 19h10" /> },
  { to: '/alerts', label: 'Alerts', glyph: <Glyph d="M6 9a6 6 0 0112 0c0 5 2 6 2 6H4s2-1 2-6M10 21h4" /> },
  { to: '/notifications', label: 'Alerting', glyph: <Glyph d="M4 6h16M4 12h16M4 18h16M8 3v3m8 12v3" /> },
  { to: '/scans', label: 'Scans', glyph: <Glyph d="M3 12a9 9 0 1018 0 9 9 0 00-18 0zm9-9v4m0 10v4m9-9h-4M7 12H3" /> },
  { to: '/containers', label: 'Containers', glyph: <Glyph d="M3 8l9-5 9 5v8l-9 5-9-5zM3 8l9 5m0 0l9-5m-9 5v9" /> },
  { to: '/malware', label: 'Malware', glyph: <Glyph d="M12 3l1 5h5l-4 3 1.5 5L12 13l-3.5 3L10 11 6 8h5z" /> },
  { to: '/feeds', label: 'Feeds', glyph: <Glyph d="M4 4a16 16 0 0116 16M4 11a9 9 0 019 9M5 19a1 1 0 100-2 1 1 0 000 2z" /> },
];

function Glyph({ d }: { d: string }): JSX.Element {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"
      strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4">
      <path d={d} />
    </svg>
  );
}

/**
 * The signature element: a live threat-pulse rail running down the left edge of
 * the shell. Each incoming live event drops a colored tick that rises and fades,
 * giving an ambient read of tempo + severity without stealing focus. Respects
 * prefers-reduced-motion via the global CSS override.
 */
function ThreatPulseRail(): JSX.Element {
  const { events, status } = useLive();
  const recent = events.slice(0, 14);
  return (
    <div className="relative flex w-1.5 flex-col items-center overflow-hidden bg-base-800">
      <span
        className={clsx(
          'absolute inset-0',
          status === 'open' ? 'opacity-100' : 'opacity-30',
        )}
        style={{
          background:
            'linear-gradient(to bottom, rgba(245,165,36,0.10), rgba(245,165,36,0) 60%)',
        }}
      />
      <div className="mt-2 flex flex-col gap-1.5">
        {recent.map((e, i) => (
          <span
            key={i}
            className={clsx('h-1.5 w-1.5 rounded-full transition', sevDot(eventSeverity(e)))}
            style={{ opacity: 1 - i * 0.06 }}
          />
        ))}
      </div>
    </div>
  );
}

function eventSeverity(e: LiveEvent): Severity {
  return (e as { severity?: Severity }).severity ?? 'info';
}

export function Shell({ children }: { children: ReactNode }): JSX.Element {
  const { user, logout } = useAuth();
  const { status, events } = useLive();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  const lastEvent = events[0];

  return (
    <div className="flex h-full">
      <ThreatPulseRail />

      {/* Sidebar */}
      <aside className="flex w-52 flex-col border-r border-base-600 bg-base-800">
        <div className="flex items-center gap-2 px-4 py-4">
          <img src="/aegis.svg" alt="" className="h-6 w-6" />
          <div className="leading-tight">
            <p className="font-display text-sm font-bold tracking-wide text-ink">AEGIS</p>
            <p className="font-mono text-[9px] uppercase tracking-[0.24em] text-ink-faint">CTI Console</p>
          </div>
        </div>

        <nav className="mt-2 flex-1 space-y-0.5 px-2">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => clsx(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition',
                isActive
                  ? 'bg-base-700 text-ink'
                  : 'text-ink-dim hover:bg-base-700/50 hover:text-ink',
              )}
            >
              {item.glyph}
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-base-600 p-3">
          <p className="truncate font-mono text-xs text-ink-dim" title={user?.email}>{user?.email}</p>
          <p className="mt-0.5 truncate text-[10px] uppercase tracking-wider text-ink-faint">
            {user?.roles?.join(' · ') || 'no roles'}
          </p>
          <button
            onClick={() => logout()}
            className="mt-2 w-full rounded border border-base-500 px-2 py-1 text-xs text-ink-dim transition hover:border-sev-critical hover:text-sev-critical"
          >
            Sign out
          </button>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="flex items-center gap-4 border-b border-base-600 bg-base-800/60 px-5 py-3 backdrop-blur">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (query.trim()) navigate(`/search?q=${encodeURIComponent(query.trim())}`);
            }}
            className="flex-1"
          >
            <div className="relative max-w-lg">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint">
                <circle cx="11" cy="11" r="7" /><path d="m20 20-3-3" strokeLinecap="round" />
              </svg>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search indicators, CVEs, hashes, domains…"
                className="w-full rounded-md border border-base-600 bg-base-900 py-2 pl-9 pr-3 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-signal"
              />
            </div>
          </form>

          <ConnectionIndicator status={status} last={lastEvent} />
        </header>

        <main className="min-h-0 flex-1 overflow-auto bg-base-900 p-5">{children}</main>
      </div>
    </div>
  );
}

function ConnectionIndicator({
  status, last,
}: { status: ReturnType<typeof useLive>['status']; last?: LiveEvent }): JSX.Element {
  const dot = status === 'open' ? 'bg-good' : status === 'connecting' ? 'bg-signal' : 'bg-sev-critical';
  const label = status === 'open' ? 'LIVE' : status === 'connecting' ? 'SYNC' : 'DOWN';
  return (
    <div className="flex items-center gap-3">
      {last && last.type !== 'error' && (
        <span className="hidden font-mono text-[10px] text-ink-faint md:inline">
          last event {relTime(Date.now())} · {last.type}
        </span>
      )}
      <span className="flex items-center gap-1.5 rounded-full border border-base-600 px-2.5 py-1">
        <span className={clsx('h-2 w-2 rounded-full', dot, status === 'open' && 'animate-pulse-ring')} />
        <span className="font-mono text-[10px] font-semibold tracking-widest text-ink-dim">{label}</span>
      </span>
    </div>
  );
}
