import { describe, expect, it } from 'vitest';

import { createLimiter } from './limit';

const tick = () => new Promise<void>((r) => setTimeout(r, 0));

describe('createLimiter', () => {
  it('runs no more than n calls at once and lets every one finish', async () => {
    const limit = createLimiter(2);
    let running = 0;
    let peak = 0;
    const gates: (() => void)[] = [];
    const job = () =>
      limit(async () => {
        running += 1;
        peak = Math.max(peak, running);
        await new Promise<void>((open) => gates.push(open));
        running -= 1;
        return 'ok';
      });
    const all = Promise.all([job(), job(), job(), job(), job()]);
    await tick();
    expect(running).toBe(2);
    while (gates.length > 0) {
      gates.shift()?.();
      await tick();
    }
    expect(await all).toEqual(['ok', 'ok', 'ok', 'ok', 'ok']);
    expect(peak).toBe(2);
  });

  it('does not start a call whose signal was aborted while it waited, and does not lose its place for the others', async () => {
    const limit = createLimiter(1);
    let release: () => void = () => {};
    const first = limit(() => new Promise<void>((open) => { release = open; }));
    const ctl = new AbortController();
    let started = false;
    const second = limit(async () => { started = true; }, ctl.signal);
    let thirdRan = false;
    const third = limit(async () => { thirdRan = true; });
    ctl.abort();
    release();
    await first;
    await expect(second).rejects.toMatchObject({ name: 'AbortError' });
    await third;
    expect(started).toBe(false);
    expect(thirdRan).toBe(true);
  });

  it('passes a failure on and carries on with the next call', async () => {
    const limit = createLimiter(1);
    const bad = limit(async () => { throw new Error('boom'); });
    const good = limit(async () => 7);
    await expect(bad).rejects.toThrow('boom');
    expect(await good).toBe(7);
  });
});
