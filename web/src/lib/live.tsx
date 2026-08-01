import {
  createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode,
} from 'react';
import { getRefreshToken } from './api';
import type { LiveEvent } from './types';

// ⚠️ RUNTIME VERIFICATION REQUIRED — depends on the /ws hub + Redis fan-out.
//
// The live-events layer connects to /ws with the access token, then fans domain
// events (ioc.new, alert.new, scan.update, feed.run) out to subscribers. It
// reconnects with capped exponential backoff and exposes a rolling buffer of the
// most recent events plus a connection status for the header indicator.

export type WsStatus = 'connecting' | 'open' | 'closed';

interface LiveState {
  status: WsStatus;
  events: LiveEvent[];
  subscribe: (fn: (e: LiveEvent) => void) => () => void;
}

const LiveContext = createContext<LiveState | null>(null);

const MAX_BUFFER = 100;
const MAX_BACKOFF = 15_000;

// The socket authenticates with the *access* token. We don't have direct access
// to it here (kept in the API module's closure), so the hub is handed a getter
// that returns the freshest token. Simplest reliable approach: read it from a
// small accessor the API module exposes via a global the client sets.
function currentToken(): string | null {
  // The API client stashes the live access token on window for the WS layer,
  // which cannot import it without a cycle. Falls back to refresh token so a
  // brand-new tab still attempts a connection (the hub will 401 and we retry
  // after the API's resume populates the access token).
  return (window as unknown as { __aegisAccessToken?: string }).__aegisAccessToken
    ?? getRefreshToken();
}

export function LiveProvider({ children }: { children: ReactNode }): JSX.Element {
  const [status, setStatus] = useState<WsStatus>('connecting');
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const subscribers = useRef<Set<(e: LiveEvent) => void>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  const attemptRef = useRef(0);
  const closedByUs = useRef(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    const token = currentToken();
    if (!token) {
      // No credentials yet — retry shortly; auth resume may still be running.
      timerRef.current = setTimeout(connect, 1000);
      return;
    }
    setStatus('connecting');
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    // The token is sent as the first message (never in the URL or handshake
    // headers) so it can't leak into proxy/access logs.
    const ws = new WebSocket(`${proto}://${window.location.host}/ws`);
    wsRef.current = ws;

    ws.onopen = () => {
      attemptRef.current = 0;
      setStatus('open');
      ws.send(JSON.stringify({ type: 'auth', token }));
    };
    ws.onmessage = (msg) => {
      let evt: LiveEvent;
      try {
        evt = JSON.parse(msg.data as string) as LiveEvent;
      } catch {
        return;
      }
      if (evt.type === 'hello') return; // handshake noise
      setEvents((prev) => [evt, ...prev].slice(0, MAX_BUFFER));
      subscribers.current.forEach((fn) => {
        try { fn(evt); } catch { /* subscriber errors never break the pipe */ }
      });
    };
    ws.onclose = () => {
      setStatus('closed');
      if (closedByUs.current) return;
      const backoff = Math.min(MAX_BACKOFF, 500 * 2 ** attemptRef.current);
      attemptRef.current += 1;
      timerRef.current = setTimeout(connect, backoff);
    };
    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    closedByUs.current = false;
    connect();
    return () => {
      closedByUs.current = true;
      if (timerRef.current) clearTimeout(timerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const subscribe = useCallback((fn: (e: LiveEvent) => void) => {
    subscribers.current.add(fn);
    return () => { subscribers.current.delete(fn); };
  }, []);

  return (
    <LiveContext.Provider value={{ status, events, subscribe }}>
      {children}
    </LiveContext.Provider>
  );
}

export function useLive(): LiveState {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error('useLive must be used within <LiveProvider>');
  return ctx;
}

/** Subscribe to a single live-event type; auto-unsubscribes on unmount. */
export function useLiveEvent(type: string, handler: (e: LiveEvent) => void): void {
  const { subscribe } = useLive();
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => subscribe((e) => {
    if (e.type === type) ref.current(e);
  }), [subscribe, type]);
}
