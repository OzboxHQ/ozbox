import type { Step } from '../api/types';
import { ABSENT } from './format';

export interface Range {
  id: 'live' | 'hour' | 'week';
  label: string;
  step: Step;
  /** How far back to look. */
  spanMs: number;
  /** How often to refresh while the page is open. */
  refreshMs: number;
}

export const RANGES: Range[] = [
  { id: 'live', label: 'Live, 5 s', step: '5s', spanMs: 15 * 60_000, refreshMs: 5_000 },
  { id: 'hour', label: 'Last 6 h, 1 min', step: '1m', spanMs: 6 * 3_600_000, refreshMs: 30_000 },
  { id: 'week', label: 'Last 7 days, 1 h', step: '1h', spanMs: 7 * 86_400_000, refreshMs: 60_000 },
];

export interface Point {
  t: number;
  v: number;
}

export interface Summary {
  count: number;
  min: number;
  max: number;
  mean: number;
  last: number;
}

export function summarize(points: Point[]): Summary | null {
  if (points.length === 0) return null;
  let min = Infinity;
  let max = -Infinity;
  let sum = 0;
  for (const p of points) {
    min = Math.min(min, p.v);
    max = Math.max(max, p.v);
    sum += p.v;
  }
  const last = points[points.length - 1]?.v ?? 0;
  return { count: points.length, min, max, mean: sum / points.length, last };
}

/** At most `n` evenly spaced points, always keeping the last. */
export function downsample<T>(items: T[], n: number): T[] {
  if (items.length <= n || n < 2) return items.length <= n ? items : items.slice(-1);
  const out: T[] = [];
  for (let i = 0; i < n; i++) {
    const item = items[Math.round((i * (items.length - 1)) / (n - 1))];
    if (item !== undefined) out.push(item);
  }
  return out;
}

/** SVG path data for a line over a `w` x `h` box, y from `yMax` (top) down to 0 (bottom). */
export function linePath(points: Point[], w: number, h: number, yMax: number): string {
  if (points.length === 0) return '';
  const t0 = points[0]?.t ?? 0;
  const t1 = points[points.length - 1]?.t ?? t0;
  const span = Math.max(t1 - t0, 1);
  return points
    .map((p, i) => {
      const x = ((p.t - t0) / span) * w;
      const y = h - (Math.min(Math.max(p.v, 0), yMax) / yMax) * h;
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');
}

/** The text equivalent of a chart. */
export function describeSeries(name: string, unit: string, s: Summary | null, rangeLabel: string): string {
  if (!s) return `${name}: no data for ${rangeLabel}.`;
  const f = (v: number) => `${Math.round(v)}${unit}`;
  return `${name}, ${rangeLabel}: now ${f(s.last)}, lowest ${f(s.min)}, highest ${f(s.max)}, average ${f(s.mean)}.`;
}

export function fmtClock(ms: number, withDate: boolean): string {
  if (!Number.isFinite(ms)) return ABSENT;
  const d = new Date(ms);
  const hm = d.toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: withDate ? undefined : '2-digit', hour12: false });
  return withDate ? `${d.toLocaleDateString('en', { month: 'short', day: 'numeric' })} ${hm}` : hm;
}
