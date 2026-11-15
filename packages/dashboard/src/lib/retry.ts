import { ApiError } from '../api/error';

/** How a load is tried again: the waits between tries, and how long one try may go unanswered before it is given up and asked again. */
export interface RetryPlan {
  waits: readonly number[];
  attemptMs?: number;
}

/**
 * For a load the page cannot do without: one try and three more, each given three seconds to be answered (an answer that never
 * comes is a failure like any other, not a page waiting for ever), so the error shows within about twenty seconds.
 */
export const REQUIRED_LOAD_RETRY: RetryPlan = { waits: [500, 1500, 3000], attemptMs: 3000 };

/** A failure worth asking again about: the network, a busy server, a timeout. A refusal (401, 403, 404, ...) will not change. */
export function worthRetrying(e: unknown): boolean {
  if (e instanceof ApiError) return e.status === 0 || e.status === 408 || e.status === 429 || e.status >= 500;
  return true;
}

function pause(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((done) => {
    const id = setTimeout(done, ms);
    signal.addEventListener('abort', () => {
      clearTimeout(id);
      done();
    }, { once: true });
  });
}

/** One try of `load`, given up (aborted) after `attemptMs` without an answer, or when the whole run is aborted. */
async function oneTry<T>(load: (signal: AbortSignal) => Promise<T>, attemptMs: number | undefined, outer: AbortSignal): Promise<T> {
  if (attemptMs === undefined) return load(outer);
  const ctl = new AbortController();
  const stop = () => ctl.abort();
  outer.addEventListener('abort', stop, { once: true });
  const timer = setTimeout(stop, attemptMs);
  try {
    return await load(ctl.signal);
  } finally {
    clearTimeout(timer);
    outer.removeEventListener('abort', stop);
  }
}

/**
 * Runs `load`, and after a failure that is worth asking again about waits `plan.waits[i]` ms and tries once more, for as many
 * waits as are given. The last failure is thrown. An aborted run stops at once and throws what it had.
 */
export async function withRetry<T>(
  load: (signal: AbortSignal) => Promise<T>,
  plan: RetryPlan,
  signal: AbortSignal,
  wait: (ms: number, signal: AbortSignal) => Promise<void> = pause,
): Promise<T> {
  for (let i = 0; ; i += 1) {
    try {
      return await oneTry(load, plan.attemptMs, signal);
    } catch (e) {
      const next = plan.waits[i];
      if (next === undefined || signal.aborted || !worthRetrying(e)) throw e;
      await wait(next, signal);
      if (signal.aborted) throw e;
    }
  }
}
