import { describe, expect, it } from 'vitest';

import { describeSeries, downsample, linePath, summarize } from './series';

describe('series', () => {
  it('summarises and describes in words', () => {
    const s = summarize([{ t: 0, v: 10 }, { t: 1, v: 30 }, { t: 2, v: 20 }]);
    expect(s).toEqual({ count: 3, min: 10, max: 30, mean: 20, last: 20 });
    expect(describeSeries('CPU', '%', s, 'Live')).toContain('now 20%');
    expect(describeSeries('CPU', '%', null, 'Live')).toBe('CPU: no data for Live.');
  });
  it('downsamples keeping the ends', () => {
    const items = Array.from({ length: 100 }, (_, i) => i);
    const d = downsample(items, 12);
    expect(d).toHaveLength(12);
    expect(d[0]).toBe(0);
    expect(d[11]).toBe(99);
  });
  it('builds a path inside the box', () => {
    expect(linePath([{ t: 0, v: 0 }, { t: 10, v: 100 }], 100, 50, 100)).toBe('M0.0 50.0 L100.0 0.0');
    expect(linePath([], 1, 1, 1)).toBe('');
  });
});
