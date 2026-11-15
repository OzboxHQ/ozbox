import { describe, expect, it } from 'vitest';

import { ApiError } from '../api/error';
import { REQUIRED_LOAD_RETRY, withRetry, worthRetrying } from './retry';

const never = new AbortController().signal;

describe('withRetry', () => {
  it('asks again after a failure and returns the first answer that comes', async () => {
    const waits: number[] = [];
    let calls = 0;
    const v = await withRetry(
      async () => {
        calls += 1;
        if (calls < 3) throw new TypeError('network');
        return 'ok';
      },
      { waits: [10, 20, 30] },
      never,
      async (ms) => void waits.push(ms),
    );
    expect(v).toBe('ok');
    expect(calls).toBe(3);
    expect(waits).toEqual([10, 20]);
  });

  it('throws the last failure once every wait is used, after one try plus one per wait', async () => {
    let calls = 0;
    await expect(
      withRetry(
        async () => {
          calls += 1;
          throw new ApiError(503, 'busy', `try ${calls}`);
        },
        REQUIRED_LOAD_RETRY,
        never,
        async () => undefined,
      ),
    ).rejects.toThrow('try 4');
    expect(calls).toBe(1 + REQUIRED_LOAD_RETRY.waits.length);
  });

  it('shows its error within about twenty seconds in all', () => {
    expect(REQUIRED_LOAD_RETRY.waits.reduce((a, b) => a + b, 0) + (REQUIRED_LOAD_RETRY.waits.length + 1) * (REQUIRED_LOAD_RETRY.attemptMs ?? 0)).toBeLessThanOrEqual(20_000);
  });

  it('does not ask again about a refusal that will not change', async () => {
    let calls = 0;
    await expect(
      withRetry(
        async () => {
          calls += 1;
          throw new ApiError(403, 'role_forbidden', 'no');
        },
        { waits: [1, 1] },
        never,
        async () => undefined,
      ),
    ).rejects.toThrow('no');
    expect(calls).toBe(1);
  });

  it('gives up on a try that is never answered and asks again, so a lost answer is not a page that waits for ever', async () => {
    let calls = 0;
    const v = await withRetry(
      (signal) => {
        calls += 1;
        if (calls === 1) {
          // the answer never comes: only the abort ends it
          return new Promise<string>((_, fail) => signal.addEventListener('abort', () => fail(new DOMException('aborted', 'AbortError'))));
        }
        return Promise.resolve('answered');
      },
      { waits: [1], attemptMs: 20 },
      never,
    );
    expect(v).toBe('answered');
    expect(calls).toBe(2);
  });

  it('stops at once when the run is aborted while waiting', async () => {
    const ctl = new AbortController();
    let calls = 0;
    await expect(
      withRetry(
        async () => {
          calls += 1;
          throw new TypeError('network');
        },
        { waits: [5, 5] },
        ctl.signal,
        async () => ctl.abort(),
      ),
    ).rejects.toThrow('network');
    expect(calls).toBe(1);
  });
});

describe('worthRetrying', () => {
  it('retries the network, a busy server and a timeout, not a refusal', () => {
    expect(worthRetrying(new TypeError('Failed to fetch'))).toBe(true);
    for (const s of [0, 408, 429, 500, 502, 503]) expect(worthRetrying(new ApiError(s, 'x', 'x')), String(s)).toBe(true);
    for (const s of [400, 401, 403, 404, 409]) expect(worthRetrying(new ApiError(s, 'x', 'x')), String(s)).toBe(false);
  });
});
