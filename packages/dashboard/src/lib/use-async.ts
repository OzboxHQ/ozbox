import { useCallback, useEffect, useRef, useState } from 'react';

import { withRetry, type RetryPlan } from './retry';

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Run `load` now and then every `everyMs` (paused while the tab is hidden), and again on `reload()`. The previous
 * data stays on screen while a refresh is in flight so charts do not flash. With `retry` (a plan), a failed or unanswered run is tried
 * again before the error is reported, so one dropped request is not shown as a failure.
 */
export function useAsync<T>(load: (signal: AbortSignal) => Promise<T>, deps: unknown[], everyMs?: number, retry?: RetryPlan): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  const retryRef = useRef(retry);
  retryRef.current = retry;

  // A change of inputs starts from a clean slate.
  useEffect(() => {
    setData(null);
    setError(null);
    setLoading(true);
  }, deps);

  useEffect(() => {
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async () => {
      try {
        const v = await withRetry((s) => loadRef.current(s), retryRef.current ?? { waits: [] }, ctl.signal);
        if (ctl.signal.aborted) return;
        setData(v);
        setError(null);
      } catch (e) {
        if (ctl.signal.aborted) return;
        setError(e instanceof Error ? e : new Error(String(e)));
      } finally {
        if (!ctl.signal.aborted) {
          setLoading(false);
          if (everyMs) timer = setTimeout(schedule, everyMs);
        }
      }
    };
    const schedule = () => {
      if (document.hidden) timer = setTimeout(schedule, 1000);
      else void run();
    };
    void run();
    return () => {
      ctl.abort();
      if (timer) clearTimeout(timer);
    };
  }, [...deps, everyMs, tick]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  // A change applied anywhere (this tab, another tab) arrives over the live stream and refreshes every open view.
  useEffect(() => {
    const on = () => setTick((n) => n + 1);
    window.addEventListener('ozbox:changed', on);
    return () => window.removeEventListener('ozbox:changed', on);
  }, []);
  return { data, error, loading, reload };
}
