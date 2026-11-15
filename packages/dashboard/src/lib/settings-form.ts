import { z } from 'zod';

import type { BudgetSettings, DefaultsSettings, SizeInfo } from '../api/types';

/**
 * The forms edit text; the server stores numbers and enforces them. These schemas only catch typing mistakes early:
 * the server validates again and its message is shown if it refuses.
 */
const money = z.string().refine((v) => v === '' || (/^\d{1,7}(\.\d{1,2})?$/.test(v) && Number(v) > 0), 'Enter an amount above 0 such as 500 or 500.50, or leave it empty');
const hhmm = (msg: string) => z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, msg);

/** What the server uses until the owner changes them (shown only when an older server sends neither). */
export const DRIFT_PCT_DEFAULT = 25;
export const DRIFT_MIN_USD_DEFAULT = 2;

export const budgetSchema = z.object({
  monthly: money,
  maxRunning: z.string().refine((v) => v === '' || (/^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 1000), 'A whole number from 1 to 1000, or leave it empty'),
  at50: z.boolean(),
  at80: z.boolean(),
  at100: z.boolean(),
  quietFrom: hhmm('Use a time like 23:00'),
  quietTo: hhmm('Use a time like 07:00'),
  utcOffset: z.string().refine((v) => /^-?\d{1,4}$/.test(v) && Math.abs(Number(v)) <= 840, 'Whole minutes from -840 to 840, for example 60 for UTC+1'),
  inApp: z.boolean(),
  /** Share (1 to 1000 percent) by which the bill and the estimate may differ before a day is flagged. */
  driftPct: z.string().refine((v) => /^\d{1,4}(\.\d{1,2})?$/.test(v) && Number(v) >= 1 && Number(v) <= 1000, 'A share from 1 to 1000 percent, for example 25'),
  /** Amount in dollars the difference must also reach; 0 means any amount. */
  driftMinUsd: z.string().refine((v) => /^\d{1,7}(\.\d{1,2})?$/.test(v), 'An amount of 0 or more, for example 2 or 2.50'),
  /** Monthly price per size id, as typed. Empty means not known. */
  prices: z.record(z.string(), money),
});
export type BudgetForm = z.infer<typeof budgetSchema>;

export const defaultsSchema = z.object({
  size: z.string().min(1, 'Choose a size'),
  disk: z.string().regex(/^\d+$/, 'Enter a whole number of GB').refine((v) => Number(v) >= 20, 'At least 20 GB'),
  autoPauseMinutes: z.string().regex(/^\d+$/, 'Enter whole minutes').refine((v) => Number(v) >= 5 && Number(v) <= 1440, 'Between 5 and 1440 minutes'),
  alwaysOn: z.boolean(),
  imageChannel: z.enum(['stable', 'next']),
});
export type DefaultsForm = z.infer<typeof defaultsSchema>;

export function budgetToForm(b: BudgetSettings): BudgetForm {
  return {
    monthly: b.monthly_usd === null ? '' : String(b.monthly_usd),
    maxRunning: b.max_running_boxes === null ? '' : String(b.max_running_boxes),
    at50: b.alert_50,
    at80: b.alert_80,
    at100: b.alert_100,
    quietFrom: b.quiet_from,
    quietTo: b.quiet_to,
    utcOffset: String(b.utc_offset_minutes),
    inApp: b.in_app,
    driftPct: String(b.drift_alert_pct ?? DRIFT_PCT_DEFAULT),
    driftMinUsd: String(b.drift_alert_min_usd ?? DRIFT_MIN_USD_DEFAULT),
    prices: Object.fromEntries(Object.entries(b.size_prices_usd).map(([k, v]) => [k, String(v)])),
  };
}

export function formToBudget(f: BudgetForm): BudgetSettings {
  const prices: Record<string, number> = {};
  for (const [k, v] of Object.entries(f.prices)) if (v !== '') prices[k] = Number(v);
  return {
    monthly_usd: f.monthly === '' ? null : Number(f.monthly),
    alert_50: f.at50,
    alert_80: f.at80,
    alert_100: f.at100,
    quiet_from: f.quietFrom,
    quiet_to: f.quietTo,
    utc_offset_minutes: Number(f.utcOffset),
    in_app: f.inApp,
    max_running_boxes: f.maxRunning === '' ? null : Number(f.maxRunning),
    size_prices_usd: prices,
    drift_alert_pct: Number(f.driftPct),
    drift_alert_min_usd: Number(f.driftMinUsd),
  };
}

/** The size id (`M`, `GPU-S`) the server's size object is shown as. */
export function sizeId(size: DefaultsSettings['size']): string {
  if (typeof size === 'string') return size;
  return size.Gpu === 'Small' ? 'GPU-S' : 'GPU-L';
}

export function defaultsToForm(d: DefaultsSettings): DefaultsForm {
  return { size: sizeId(d.size), disk: String(d.work_disk_gb), autoPauseMinutes: String(d.auto_pause_minutes), alwaysOn: d.always_on, imageChannel: d.image_channel };
}

/** `null` when the size is not one the provider offers. */
export function formToDefaults(f: DefaultsForm, sizes: SizeInfo[]): DefaultsSettings | null {
  const size = sizes.find((s) => s.id === f.size)?.size;
  if (!size) return null;
  return { size, work_disk_gb: Number(f.disk), auto_pause_minutes: Number(f.autoPauseMinutes), always_on: f.alwaysOn, image_channel: f.imageChannel };
}
