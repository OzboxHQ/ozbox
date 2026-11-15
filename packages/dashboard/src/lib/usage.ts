import type { Advice, BoxUsage, UsageRange } from '../api/types';
import { sizeLabel } from './format';
import type { Point } from './series';

export interface UsageRangeOption {
  id: UsageRange;
  label: string;
  /** The window the server looks back over, for the chart's axis. */
  withDate: boolean;
  refreshMs: number;
}

export const USAGE_RANGES: UsageRangeOption[] = [
  { id: '5s', label: 'Live, 5 s', withDate: false, refreshMs: 5_000 },
  { id: '1m', label: 'Last 3 h, 1 min', withDate: false, refreshMs: 30_000 },
  { id: '1h', label: 'Last 7 days, 1 h', withDate: true, refreshMs: 60_000 },
];

/** The fleet's average at each timestamp, over the boxes that reported one. */
export function fleetPoints(boxes: BoxUsage[], field: 'cpu_pct' | 'mem_pct'): Point[] {
  const acc = new Map<number, { sum: number; n: number }>();
  for (const b of boxes) {
    for (const p of b.points) {
      const e = acc.get(p.ts_ms) ?? { sum: 0, n: 0 };
      e.sum += p[field];
      e.n += 1;
      acc.set(p.ts_ms, e);
    }
  }
  return [...acc.entries()].sort((a, b) => a[0] - b[0]).map(([t, e]) => ({ t, v: e.sum / e.n }));
}

export function adviceTitle(box: string, advice: Advice): string {
  return advice.kind === 'downsize' ? `Move ${box} down to size ${sizeLabel(advice.to)}` : `Pause ${box} when it is idle`;
}

/** What the button does. Both go through the normal plan, review, apply flow. */
export function adviceAction(advice: Advice): string {
  return advice.kind === 'downsize' ? 'Review resize' : 'Review pause';
}
