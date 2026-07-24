// Typed API client for the Aegis backend.
//
// Design notes:
//  - A single access token is held in memory (module scope) and mirrored into
//    the auth context. Refresh tokens live in localStorage so a reload can
//    re-establish a session; access tokens are deliberately NOT persisted.
//  - On a 401 the client performs a single transparent refresh + retry. A
//    refresh that itself fails clears the session and rejects, letting the
//    router bounce the user to /login.
//  - All calls go through the Vite dev proxy (/api → :8080) so there is no CORS
//    juggling in development; in production Nginx serves the same origin.

import type {
  Alert, AlertStatus, Cve, DashboardStats, Feed, Ioc, LoginResponse, Paged,
  Scan, SearchResult, Severity, TimelineEvent, AttackStat, TopSource, AuthUser,
  DetectionRule, RuleFormat, RuleStatus, RuleValidation,
  NotificationChannel, ChannelType, AlertRule, AlertRuleEventType,
  AlertRuleConditions, ChannelTestResult,
  ContainerAudit, ContainerAuditDetail, ContainerAuditKind,
} from './types';

const REFRESH_KEY = 'aegis.refresh';
const BASE = '/api';

let accessToken: string | null = null;
let onAuthChange: ((user: AuthUser | null) => void) | null = null;

// Mirror the live access token onto window so the WebSocket layer (which must
// not import this module — it would create a cycle) can read it when it opens
// or re-opens the /ws connection.
function mirrorToken(token: string | null): void {
  (window as unknown as { __aegisAccessToken?: string | null }).__aegisAccessToken = token;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
  mirrorToken(token);
}
export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}
export function setRefreshToken(token: string | null): void {
  if (token) localStorage.setItem(REFRESH_KEY, token);
  else localStorage.removeItem(REFRESH_KEY);
}
export function registerAuthListener(fn: (user: AuthUser | null) => void): void {
  onAuthChange = fn;
}

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, body: unknown, message?: string) {
    super(message ?? `API error ${status}`);
    this.status = status;
    this.body = body;
  }
}

interface RequestOpts {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  retryOn401?: boolean;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: RequestOpts['query']): string {
  const url = `${BASE}${path}`;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

async function refreshSession(): Promise<boolean> {
  const rt = getRefreshToken();
  if (!rt) return false;
  try {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refreshToken: rt }),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as LoginResponse;
    accessToken = data.accessToken;
    mirrorToken(accessToken);
    setRefreshToken(data.refreshToken);
    return true;
  } catch {
    return false;
  }
}

export async function request<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const { method = 'GET', body, query, retryOn401 = true, signal } = opts;
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;

  const res = await fetch(buildUrl(path, query), {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal,
  });

  if (res.status === 401 && retryOn401) {
    const ok = await refreshSession();
    if (ok) return request<T>(path, { ...opts, retryOn401: false });
    // Refresh failed → session is dead.
    accessToken = null;
    mirrorToken(null);
    setRefreshToken(null);
    onAuthChange?.(null);
    throw new ApiError(401, null, 'session_expired');
  }

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  const payload = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, payload, (payload as { error?: string })?.error);
  return payload as T;
}

// ------------------------------------------------------------------ //
// Endpoint wrappers — one function per route the console consumes.
// ------------------------------------------------------------------ //

export const api = {
  auth: {
    async login(email: string, password: string): Promise<LoginResponse> {
      const data = await request<LoginResponse>('/auth/login', {
        method: 'POST', body: { email, password }, retryOn401: false,
      });
      accessToken = data.accessToken;
      mirrorToken(accessToken);
      setRefreshToken(data.refreshToken);
      return data;
    },
    async me(): Promise<{ user: AuthUser }> {
      return request('/auth/me');
    },
    async logout(): Promise<void> {
      const rt = getRefreshToken();
      try {
        if (rt) await request('/auth/logout', { method: 'POST', body: { refreshToken: rt } });
      } finally {
        accessToken = null;
        mirrorToken(null);
        setRefreshToken(null);
        onAuthChange?.(null);
      }
    },
    tryResume: refreshSession,
  },

  dashboard: {
    stats: () => request<DashboardStats>('/dashboard/stats'),
    timeline: () => request<TimelineEvent[]>('/dashboard/timeline'),
    attackMatrix: () => request<AttackStat[]>('/dashboard/attack-matrix'),
    topSources: () => request<TopSource[]>('/dashboard/top-sources'),
  },

  iocs: {
    list: (q: {
      type?: string; severity?: Severity; source?: string; q?: string;
      active?: boolean; limit?: number; offset?: number;
    } = {}) => request<Paged<Ioc>>('/iocs', { query: q }),
    get: (id: string) => request<Ioc & { sightings: unknown[] }>(`/iocs/${id}`),
    create: (body: Partial<Ioc> & { type: string; value: string }) =>
      request<Ioc>('/iocs', { method: 'POST', body }),
    enrich: (id: string) =>
      request<{ enqueued: boolean; jobId: string }>(`/iocs/${id}/enrich`, { method: 'POST' }),
    remove: (id: string) => request<void>(`/iocs/${id}`, { method: 'DELETE' }),
  },

  cves: {
    list: (q: {
      kev?: boolean; minCvss?: number; minEpss?: number; q?: string;
      limit?: number; offset?: number;
    } = {}) => request<Paged<Cve>>('/cves', { query: q }),
    get: (id: string) => request<Cve>(`/cves/${id}`),
    recentKev: () => request<Cve[]>('/cves/kev/recent'),
  },

  rules: {
    list: (q: {
      format?: RuleFormat; status?: RuleStatus; enabled?: boolean; valid?: boolean;
      q?: string; limit?: number; offset?: number;
    } = {}) => request<Paged<DetectionRule>>('/rules', { query: q }),
    get: (id: string) => request<DetectionRule>(`/rules/${id}`),
    validate: (format: RuleFormat, content: string) =>
      request<RuleValidation>('/rules/validate', { method: 'POST', body: { format, content } }),
    create: (body: {
      format: RuleFormat; content: string; name?: string; description?: string;
      author?: string; severity?: Severity; status?: RuleStatus; tags?: string[];
      technique_ids?: string[]; is_enabled?: boolean;
    }) => request<DetectionRule>('/rules', { method: 'POST', body }),
    update: (id: string, body: Partial<{
      content: string; name: string; description: string; author: string;
      severity: Severity; status: RuleStatus; tags: string[];
      technique_ids: string[]; is_enabled: boolean;
    }>) => request<DetectionRule>(`/rules/${id}`, { method: 'PATCH', body }),
    remove: (id: string) => request<void>(`/rules/${id}`, { method: 'DELETE' }),
  },

  alerts: {
    list: (q: { status?: AlertStatus; severity?: Severity; limit?: number; offset?: number } = {}) =>
      request<Paged<Alert>>('/alerts', { query: q }),
    ack: (id: string) => request<{ ok: boolean }>(`/alerts/${id}/ack`, { method: 'POST' }),
    resolve: (id: string) => request<{ ok: boolean }>(`/alerts/${id}/resolve`, { method: 'POST' }),
  },

  channels: {
    list: () => request<{ data: NotificationChannel[] }>('/channels'),
    create: (body: {
      name: string; type: ChannelType; enabled?: boolean;
      config?: Record<string, unknown>; min_severity?: Severity;
    }) => request<NotificationChannel>('/channels', { method: 'POST', body }),
    update: (id: string, body: Partial<{
      name: string; enabled: boolean; config: Record<string, unknown>; min_severity: Severity;
    }>) => request<NotificationChannel>(`/channels/${id}`, { method: 'PATCH', body }),
    remove: (id: string) => request<void>(`/channels/${id}`, { method: 'DELETE' }),
    test: (id: string) => request<ChannelTestResult>(`/channels/${id}/test`, { method: 'POST' }),
  },

  alertRules: {
    list: () => request<{ data: AlertRule[] }>('/alert-rules'),
    create: (body: {
      name: string; description?: string; enabled?: boolean;
      event_type: AlertRuleEventType; conditions?: AlertRuleConditions;
      severity?: Severity; channels?: string[]; throttle_secs?: number;
    }) => request<AlertRule>('/alert-rules', { method: 'POST', body }),
    update: (id: string, body: Partial<{
      name: string; description: string; enabled: boolean;
      event_type: AlertRuleEventType; conditions: AlertRuleConditions;
      severity: Severity; channels: string[]; throttle_secs: number;
    }>) => request<AlertRule>(`/alert-rules/${id}`, { method: 'PATCH', body }),
    remove: (id: string) => request<void>(`/alert-rules/${id}`, { method: 'DELETE' }),
  },

  feeds: {
    list: () => request<{ data: Feed[] }>('/feeds'),
    runs: (id: string) => request<{ data: unknown[] }>(`/feeds/${id}/runs`),
    sync: (id: string) => request<{ enqueued: boolean; jobId: string }>(`/feeds/${id}/sync`, { method: 'POST' }),
  },

  scans: {
    list: (limit = 50) => request<{ data: Scan[] }>('/scans', { query: { limit } }),
    get: (id: string) => request<Scan & { ports: unknown[]; tls: unknown[]; findings: unknown[] }>(`/scans/${id}`),
    create: (body: { target: string; scanType?: string; assetId?: string; profile?: Record<string, unknown> }) =>
      request<{ id: string; status: string }>('/scans', { method: 'POST', body }),
  },

  search: {
    query: (q: string, limit = 25) =>
      request<{ query: string; count: number; results: SearchResult[]; grouped: Record<string, SearchResult[]> }>(
        '/search', { query: { q, limit } }),
  },

  container: {
    list: (limit = 50) => request<{ data: ContainerAudit[] }>('/container/audits', { query: { limit } }),
    get: (id: string) => request<ContainerAuditDetail>(`/container/audits/${id}`),
    create: (body: { name: string; kind: ContainerAuditKind; input: string }) =>
      request<{ id: string; status: string }>('/container/audits', { method: 'POST', body }),
    remove: (id: string) => request<void>(`/container/audits/${id}`, { method: 'DELETE' }),
  },

  malware: {
    list: (limit = 100) => request<{ data: import('./types').MalwareSample[] }>('/malware/samples', { query: { limit } }),
    get: (id: string) => request<import('./types').MalwareSampleDetail>(`/malware/samples/${id}`),
    submit: (form: FormData): Promise<{ id: string; sha256: string; score: number }> => {
      const headers: Record<string, string> = {};
      if (accessToken) headers.authorization = `Bearer ${accessToken}`;
      return fetch('/api/malware/samples', { method: 'POST', headers, body: form })
        .then(async (res) => {
          if (res.status === 401) {
            const ok = await refreshSession();
            if (ok) return fetch('/api/malware/samples', { method: 'POST', headers: { ...headers, authorization: `Bearer ${accessToken}` }, body: form }).then((r) => r.json());
          }
          if (!res.ok) { const p = await res.json().catch(() => null); throw new ApiError(res.status, p); }
          return res.json();
        });
    },
    remove: (id: string) => request<void>(`/malware/samples/${id}`, { method: 'DELETE' }),
  },
};
