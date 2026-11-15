import type { BoxState, MetricsSample, Size } from '../api/types';
import { t } from './i18n';

/** Shown wherever a value is absent. Never a zero, never an invented number. */
export const ABSENT = '—';

function finite(v: number | null | undefined): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

export function fmtPct(v: number | null | undefined): string {
  return finite(v) ? `${Math.round(v)}%` : ABSENT;
}

export function fmtBytes(v: number | null | undefined): string {
  if (!finite(v) || v < 0) return ABSENT;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let n = v;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${i === 0 ? Math.round(n) : n.toFixed(n >= 10 ? 0 : 1)} ${units[i]}`;
}

/** Cost is not measured yet; the dashboard never shows a made-up figure. */
export function fmtCost(v: number | null | undefined, currency = 'USD'): string {
  if (!finite(v)) return ABSENT;
  return new Intl.NumberFormat('en', { style: 'currency', currency }).format(v);
}

export function sizeLabel(size: Size | null | undefined): string {
  if (size === null || size === undefined) return ABSENT;
  if (typeof size === 'string') return size;
  return size.Gpu === 'Small' ? 'GPU-S' : 'GPU-L';
}

export function sameSize(a: Size, b: Size): boolean {
  return sizeLabel(a) === sizeLabel(b);
}

const STATE_LABELS: Record<BoxState, string> = {
  creating: 'Creating',
  running: 'Running',
  pausing: 'Pausing',
  paused: 'Paused',
  resuming: 'Resuming',
  resizing: 'Resizing',
  destroying: 'Destroying',
  instance_missing: '',
  unknown: 'Unknown',
};

export function stateLabel(state: BoxState): string {
  if (state === 'instance_missing') return t('state.instance_missing');
  return STATE_LABELS[state] ?? ABSENT;
}

/** A box whose machine was removed mid-upgrade: /work is kept, and only finishing the upgrade or destroying acts on it. */
export function isMachineMissing(state: BoxState): boolean {
  return state === 'instance_missing';
}

export function fmtRelative(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return ABSENT;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return ABSENT;
  const s = Math.round((now.getTime() - t) / 1000);
  if (s < 0) return 'just now';
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

export function memUsedPct(s: MetricsSample | null | undefined): number | null {
  if (!s || !finite(s.mem_total_bytes) || s.mem_total_bytes <= 0) return null;
  return ((s.mem_total_bytes - s.mem_available_bytes) / s.mem_total_bytes) * 100;
}

export function diskUsedPct(s: MetricsSample | null | undefined): number | null {
  if (!s || !finite(s.disk_total_bytes) || s.disk_total_bytes <= 0) return null;
  return ((s.disk_total_bytes - s.disk_free_bytes) / s.disk_total_bytes) * 100;
}
