import type { SelfTest } from '../api/types';
import { ApiError } from '../api/error';

/** How an upgrade ends once the provider's change is made: the box answers and its self-test is shown, or it does not. */
export type FollowResult =
  | { kind: 'result'; test: SelfTest }
  /** This server cannot ask the box at all (no way to reach its agent). Said plainly; never shown as a pass. */
  | { kind: 'unsupported'; reason: string }
  | { kind: 'timeout'; reason: string };

export interface FollowOptions {
  intervalMs: number;
  timeoutMs: number;
  /** Called after each unanswered try, with the time waited so far. */
  onWait?: (waitedMs: number, reason: string) => void;
  signal?: AbortSignal;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const sleepFor = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Ask the box for its self-test until it answers. A box that is still starting is `502 agent_unreachable` or
 * `409 box_not_running`: those mean "not yet", so the page keeps trying. Anything else is an answer.
 */
export async function followUpgrade(ask: () => Promise<SelfTest>, opts: FollowOptions): Promise<FollowResult> {
  const sleep = opts.sleep ?? sleepFor;
  const now = opts.now ?? Date.now;
  const started = now();
  let reason: string;
  for (;;) {
    if (opts.signal?.aborted) return { kind: 'timeout', reason: 'stopped' };
    try {
      return { kind: 'result', test: await ask() };
    } catch (e) {
      if (e instanceof ApiError && e.status === 501) return { kind: 'unsupported', reason: e.message };
      if (e instanceof ApiError && (e.status === 502 || e.status === 409 || e.status === 0)) reason = e.message;
      else if (e instanceof ApiError) return { kind: 'timeout', reason: e.message };
      else throw e;
    }
    const waited = now() - started;
    if (waited >= opts.timeoutMs) return { kind: 'timeout', reason };
    opts.onWait?.(waited, reason);
    await sleep(opts.intervalMs);
  }
}
