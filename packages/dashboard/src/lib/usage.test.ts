import { describe, expect, it } from 'vitest';

import type { BoxUsage, SelfTest } from '../api/types';
import { checkText, failingSteps, incidentText, newestFirst, overall, overallText } from './health';
import { adviceAction, adviceTitle, fleetPoints, USAGE_RANGES } from './usage';

const box = (name: string, pts: [number, number, number][]): BoxUsage => ({
  name,
  size: 'M',
  labels: {},
  cpu: null,
  mem_pct: null,
  cost_month_est_usd: null,
  points: pts.map(([ts_ms, cpu_pct, mem_pct]) => ({ ts_ms, cpu_pct, mem_pct })),
});

describe('usage helpers', () => {
  it('averages the fleet at each timestamp over the boxes that reported one', () => {
    const p = fleetPoints([box('a', [[1, 10, 20], [2, 30, 40]]), box('b', [[2, 50, 60]])], 'cpu_pct');
    expect(p).toEqual([{ t: 1, v: 10 }, { t: 2, v: 40 }]);
    expect(fleetPoints([], 'cpu_pct')).toEqual([]);
  });

  it('offers the three ranges the server knows', () => {
    expect(USAGE_RANGES.map((r) => r.id)).toEqual(['5s', '1m', '1h']);
  });

  it('words each kind of advice and its action', () => {
    expect(adviceTitle('dev', { kind: 'downsize', to: 'S' })).toBe('Move dev down to size S');
    expect(adviceTitle('dev', { kind: 'auto_pause', idle_share: 0.9 })).toBe('Pause dev when it is idle');
    expect(adviceAction({ kind: 'downsize', to: 'S' })).toBe('Review resize');
    expect(adviceAction({ kind: 'auto_pause', idle_share: 0.9 })).toBe('Review pause');
  });
});

describe('health helpers', () => {
  const t = (checks: SelfTest['checks']): SelfTest => ({ ts_ms: 1, ok: true, all_verified: true, checks });
  it('a failure outranks unknown, and unknown is never a pass', () => {
    expect(overall(t([{ name: 'a', outcome: 'pass' }]))).toBe('passed');
    expect(overall(t([{ name: 'a', outcome: 'pass' }, { name: 'b', outcome: 'unknown', reason: 'x' }]))).toBe('unverified');
    const failed = t([{ name: 'a', outcome: 'unknown', reason: 'x' }, { name: 'b', outcome: 'fail', step: 'tunnels up', reason: 'down' }]);
    expect(overall(failed)).toBe('failed');
    expect(failingSteps(failed)).toEqual([{ step: 'tunnels up', reason: 'down' }]);
    expect(overallText('unverified')).toMatch(/could not be verified/);
    expect(checkText({ name: 'b', outcome: 'unknown', reason: 'x' })).toBe('Unknown');
  });

  it('names incidents in words and sorts newest first', () => {
    expect(incidentText({ ts_ms: 1, kind: 'oom_kill', detail: '' })).toBe('Out of memory kill');
    expect(incidentText({ ts_ms: 1, kind: 'some_new_kind', detail: '' })).toBe('some new kind');
    expect(newestFirst([{ ts_ms: 1, kind: 'a', detail: '' }, { ts_ms: 5, kind: 'b', detail: '' }]).map((i) => i.ts_ms)).toEqual([5, 1]);
  });
});
