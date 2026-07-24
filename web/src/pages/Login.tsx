import { useState, type FormEvent } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { ApiError } from '../lib/api';

export default function LoginPage(): JSX.Element {
  const { status, login } = useAuth();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (status === 'authed') {
    const from = (location.state as { from?: Location })?.from?.pathname ?? '/';
    return <Navigate to={from} replace />;
  }

  async function onSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setError('Invalid credentials.');
      else setError('Sign-in failed. Check the API is reachable.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid h-full place-items-center bg-base-900 px-4">
      {/* Faint grid backdrop for the operator-console feel. */}
      <div
        className="pointer-events-none fixed inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(#f5a524 1px, transparent 1px), linear-gradient(90deg, #f5a524 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />
      <div className="panel relative w-full max-w-sm p-8">
        <div className="mb-6 flex items-center gap-3">
          <img src="/aegis.svg" alt="" className="h-9 w-9" />
          <div>
            <h1 className="font-display text-lg font-bold tracking-wide text-ink">AEGIS CTI</h1>
            <p className="eyebrow">Threat Intelligence Console</p>
          </div>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <label className="block">
            <span className="eyebrow">Email</span>
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="mt-1 w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 font-mono text-sm text-ink focus:border-signal"
            />
          </label>
          <label className="block">
            <span className="eyebrow">Password</span>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="mt-1 w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 font-mono text-sm text-ink focus:border-signal"
            />
          </label>

          {error && (
            <p className="rounded border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-md bg-signal py-2 font-display text-sm font-semibold text-base-900 transition hover:bg-signal-soft disabled:opacity-50"
          >
            {busy ? 'Authenticating…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-6 text-center font-mono text-[10px] text-ink-faint">
          Authorized use only · activity is audited
        </p>
      </div>
    </div>
  );
}
