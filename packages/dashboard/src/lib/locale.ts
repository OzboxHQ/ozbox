import type { LocaleSettings } from '../api/types';
import { browserCountry } from './countries';
import { browserTimeZone, getTimezoneOptions } from './timezones';

/** Where the person probably is, from the browser: its time zone and the region of its language. Both are editable. */
export function suggestedLocale(): { country_code: string | null; time_zone: string } {
  return { country_code: browserCountry(), time_zone: browserTimeZone() };
}

/** What is chosen, else the suggestion. */
export function effectiveLocale(saved: LocaleSettings | undefined): { country_code: string | null; time_zone: string } {
  const s = suggestedLocale();
  return { country_code: saved?.country_code ?? s.country_code, time_zone: saved?.time_zone ?? s.time_zone };
}

export function validTimeZone(name: string): boolean {
  if (!name) return false;
  if (getTimezoneOptions().some((o) => o.value === name)) return true;
  try {
    new Intl.DateTimeFormat('en', { timeZone: name });
    return true;
  } catch {
    return false;
  }
}

/** A moment in the person's zone with UTC beside it: `2026-11-09 23:15 GMT+1 (22:15 UTC)`. Falls back to UTC alone. */
export function formatWithUtc(at: Date | number, zone: string | null | undefined): string {
  const d = typeof at === 'number' ? new Date(at) : at;
  const utc = new Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(d);
  const fmt = (z: string) => {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone: z, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'short' }).formatToParts(d);
    const p = (t: string) => parts.find((x) => x.type === t)?.value ?? '';
    return `${p('year')}-${p('month')}-${p('day')} ${p('hour')}:${p('minute')} ${p('timeZoneName')}`;
  };
  try {
    if (!zone || zone === 'UTC') return `${fmt('UTC')}`;
    return `${fmt(zone)} (${utc} UTC)`;
  } catch {
    return `${fmt('UTC')}`;
  }
}

/** A quiet-hours window written on the person's clock, with the same window in UTC: `23:00 to 07:00 (22:00 to 06:00 UTC)`. */
export function windowWithUtc(from: string, to: string, zone: string | null | undefined, at: Date = new Date()): string {
  const shift = (hhmm: string): string | null => {
    const [h, m] = hhmm.split(':').map(Number);
    if (h === undefined || m === undefined || Number.isNaN(h) || Number.isNaN(m) || !zone) return null;
    // The offset in force today, so daylight saving is followed.
    const local = new Intl.DateTimeFormat('en-GB', { timeZone: zone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(at).split(':').map(Number);
    const utc = new Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(at).split(':').map(Number);
    const offset = ((local[0] ?? 0) * 60 + (local[1] ?? 0)) - ((utc[0] ?? 0) * 60 + (utc[1] ?? 0));
    const total = (((h * 60 + m - offset) % 1440) + 1440) % 1440;
    return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`;
  };
  const a = shift(from);
  const b = shift(to);
  return a && b && zone !== 'UTC' ? `${from} to ${to} (${a} to ${b} UTC)` : `${from} to ${to}`;
}
