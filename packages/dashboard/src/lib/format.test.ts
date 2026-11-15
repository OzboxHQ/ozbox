import { describe, expect, it } from 'vitest';

import { ABSENT, diskUsedPct, fmtBytes, fmtCost, fmtPct, fmtRelative, memUsedPct, sizeLabel } from './format';

describe('format', () => {
  it('shows an em dash for absent values, never zero', () => {
    expect(fmtPct(null)).toBe(ABSENT);
    expect(fmtPct(undefined)).toBe(ABSENT);
    expect(fmtPct(Number.NaN)).toBe(ABSENT);
    expect(fmtPct(0)).toBe('0%');
    expect(fmtBytes(null)).toBe(ABSENT);
    expect(fmtCost(null)).toBe(ABSENT);
    expect(fmtCost(undefined)).toBe(ABSENT);
    expect(fmtRelative(null)).toBe(ABSENT);
    expect(fmtRelative('not a date')).toBe(ABSENT);
    expect(sizeLabel(null)).toBe(ABSENT);
    expect(memUsedPct(null)).toBeNull();
    expect(diskUsedPct(undefined)).toBeNull();
  });

  it('formats sizes, bytes and relative times', () => {
    expect(sizeLabel('XL')).toBe('XL');
    expect(sizeLabel({ Gpu: 'Small' })).toBe('GPU-S');
    expect(sizeLabel({ Gpu: 'Large' })).toBe('GPU-L');
    expect(fmtBytes(1024 ** 3 * 16)).toBe('16 GiB');
    expect(fmtBytes(1536)).toBe('1.5 KiB');
    const now = new Date('2026-11-09T12:00:00Z');
    expect(fmtRelative('2026-11-09T11:30:00Z', now)).toBe('30 min ago');
    expect(fmtRelative('2026-11-09T11:59:50Z', now)).toBe('just now');
    expect(fmtRelative('2026-11-06T12:00:00Z', now)).toBe('3 days ago');
  });
});
