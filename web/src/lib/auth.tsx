import {
  createContext, useContext, useEffect, useMemo, useState, type ReactNode,
} from 'react';
import { api, registerAuthListener, setAccessToken } from './api';
import type { AuthUser } from './types';

// ⚠️ RUNTIME VERIFICATION REQUIRED — auth flow depends on the live API + DB.

interface AuthState {
  user: AuthUser | null;
  status: 'loading' | 'authed' | 'anon';
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }): JSX.Element {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [status, setStatus] = useState<AuthState['status']>('loading');

  useEffect(() => {
    // Let the API client push us to anon on an unrecoverable 401.
    registerAuthListener((u) => {
      setUser(u);
      setStatus(u ? 'authed' : 'anon');
    });

    // Attempt to resume a session from the stored refresh token on cold load.
    let cancelled = false;
    (async () => {
      const resumed = await api.auth.tryResume();
      if (cancelled) return;
      if (!resumed) {
        setStatus('anon');
        return;
      }
      try {
        const { user: me } = await api.auth.me();
        if (cancelled) return;
        setUser(me);
        setStatus('authed');
      } catch {
        if (!cancelled) setStatus('anon');
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const value = useMemo<AuthState>(() => ({
    user,
    status,
    async login(email, password) {
      const res = await api.auth.login(email, password);
      setUser({ sub: res.user.id, email: res.user.email, roles: res.user.roles });
      setStatus('authed');
    },
    async logout() {
      await api.auth.logout();
      setAccessToken(null);
      setUser(null);
      setStatus('anon');
    },
  }), [user, status]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>');
  return ctx;
}

/** True when the current user holds a role (case-insensitive). */
export function useHasRole(...roles: string[]): boolean {
  const { user } = useAuth();
  if (!user) return false;
  const owned = new Set(user.roles.map((r) => r.toLowerCase()));
  return roles.some((r) => owned.has(r.toLowerCase()));
}
