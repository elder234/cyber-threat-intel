import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  /** Changing this value resets the boundary — pass the route path so navigating away clears a crash. */
  resetKey?: string;
}

interface State {
  error: Error | null;
}

/**
 * Catches render-phase exceptions so one bad page cannot blank the whole app.
 *
 * Without this, a single `TypeError` in a cell renderer unmounts the entire
 * React tree — nav included — and the user sees a black screen with no clue
 * what happened. React only reports render errors to class components; there
 * is no hook equivalent.
 *
 * Note this catches *render* errors only. Async rejections (fetch, react-query)
 * surface through the query layer's own error states, not here.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Keep the component stack — it names the failing component, which the
    // message alone usually does not.
    // eslint-disable-next-line no-console
    console.error('Render error:', error, info.componentStack);
  }

  componentDidUpdate(prev: Props): void {
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <p className="font-mono text-xs uppercase tracking-widest text-sev-critical">
          This view failed to render
        </p>
        <p className="max-w-lg font-mono text-xs text-ink-dim">{error.message}</p>
        <p className="text-[11px] text-ink-faint">
          Navigate to another page to reset, or check the browser console for the component stack.
        </p>
        <button
          onClick={() => this.setState({ error: null })}
          className="rounded border border-base-500 px-3 py-1 text-xs text-ink-dim transition hover:border-signal hover:text-signal"
        >
          Try again
        </button>
      </div>
    );
  }
}
