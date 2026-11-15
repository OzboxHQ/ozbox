import type { BillProblemKind, BillResponse, BudgetFigure, CauseKind, DayTotal, OrphanItem, OrphanKind, OrphanReason } from '../api/bill';
import { ABSENT, fmtCost } from './format';
import { t, type MessageKey } from './i18n';

/** Money in the bill's own currency; "—" when there is no figure. Never a zero standing in for "unknown". */
export function money(v: number | null | undefined, currency: string | null | undefined): string {
  return fmtCost(v, currency ?? 'USD');
}

const CAUSE: Record<CauseKind, MessageKey> = {
  untagged_box: 'bill.cause_untagged_box',
  unmodelled_service: 'bill.cause_unmodelled_service',
  unmodelled_in_ec2_other: 'bill.cause_unmodelled_in_ec2_other',
  price_changed: 'bill.cause_price_changed',
  partly_watched: 'bill.cause_partly_watched',
  discount_or_spot: 'bill.cause_discount_or_spot',
  not_in_bill: 'bill.cause_not_in_bill',
};

/** The sentence for the first (most likely) cause of a flagged day. */
export function causeText(causes: { kind: CauseKind; detail: string | null }[]): string {
  const c = causes[0];
  if (!c) return t('bill.cause_unknown');
  return t(CAUSE[c.kind], { detail: c.detail ?? '' });
}

const REASON: Record<OrphanReason, MessageKey> = {
  no_managed_tag: 'orph.reason_no_managed_tag',
  retired_work_disk: 'orph.reason_retired_work_disk',
  work_disk_no_box: 'orph.reason_work_disk_no_box',
  unattached_volume: 'orph.reason_unattached_volume',
  snapshot_no_box: 'orph.reason_snapshot_no_box',
  snapshot_box_gone: 'orph.reason_snapshot_box_gone',
  unsigned_image: 'orph.reason_unsigned_image',
  failed_image: 'orph.reason_failed_image',
};

export const reasonText = (r: OrphanReason): string => t(REASON[r]);

const KIND: Record<OrphanKind, MessageKey> = {
  instance: 'orph.kind_instance',
  volume: 'orph.kind_volume',
  snapshot: 'orph.kind_snapshot',
  image: 'orph.kind_image',
};

export const kindText = (k: OrphanKind): string => t(KIND[k]);

/** The days that can be drawn and compared: the provider has finished them and both figures exist. */
export function chartRows(days: DayTotal[]): { date: string; real: number; estimate: number | null }[] {
  return days.filter((d) => !d.partial && d.real !== null).map((d) => ({ date: d.date, real: d.real ?? 0, estimate: d.estimate }));
}

export function unfinishedDays(days: DayTotal[]): string[] {
  return days.filter((d) => d.partial).map((d) => d.date);
}

export type GaugeTone = 'ok' | 'warn' | 'over';

export interface Gauge {
  /** 0 to 100, for the bar. */
  fill: number;
  /** The true share, which may be over 100. */
  pct: number;
  tone: GaugeTone;
}

/** The budget gauge, or `null` when there is no budget or no figure (a missing figure is never drawn as empty). */
export function gauge(b: BudgetFigure): Gauge | null {
  if (b.monthly_usd === null || b.percent === null || !Number.isFinite(b.percent)) return null;
  const pct = Math.max(0, b.percent);
  return { fill: Math.min(100, pct), pct, tone: pct >= 100 ? 'over' : pct >= 80 ? 'warn' : 'ok' };
}

/** The thresholds that will alert, as `50%, 80%`; empty when all are off. */
export function alertList(b: BudgetFigure): string {
  return b.thresholds
    .filter((x) => x.on)
    .map((x) => `${x.percent}%`)
    .join(', ');
}

export function firedList(b: BudgetFigure): string {
  return b.fired.map((p) => `${p}%`).join(', ');
}

export function ageText(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return ABSENT;
  if (seconds < 3600) return t('cost.age_minutes', { n: Math.max(1, Math.round(seconds / 60)) });
  if (seconds < 172800) return t('cost.age_hours', { n: Math.round(seconds / 3600) });
  return t('cost.age_days', { n: Math.round(seconds / 86400) });
}

const PROBLEM: Record<BillProblemKind, MessageKey> = {
  tag_not_active: 'bill.problem_tag_not_active_title',
  access_denied: 'bill.problem_access_denied_title',
  not_enabled: 'bill.problem_not_enabled_title',
  unsupported: 'bill.problem_unsupported_title',
  other: 'bill.problem_other_title',
};

export const problemTitle = (k: BillProblemKind): string => t(PROBLEM[k]);

/** Whether the steps to turn the bill on are worth showing: only when the account is the thing missing. */
export function showsActivation(k: BillProblemKind): boolean {
  return k === 'tag_not_active' || k === 'not_enabled';
}

/** The signed difference as text for a screen reader and a sighted reader alike: never colour alone. */
export function diffText(diff: number, currency: string | null | undefined): string {
  if (!Number.isFinite(diff)) return ABSENT;
  const sign = diff > 0 ? '+' : diff < 0 ? '−' : '';
  return `${sign}${money(Math.abs(diff), currency)}`;
}

export function diffHint(diff: number | null): string | null {
  if (diff === null || !Number.isFinite(diff)) return null;
  if (Math.abs(diff) < 0.005) return t('bill.stat_diff_same');
  return diff > 0 ? t('bill.stat_diff_up') : t('bill.stat_diff_down');
}

/** Items the person may choose: only what Oz Box may delete. */
export function chooseable(items: OrphanItem[]): OrphanItem[] {
  return items.filter((i) => i.deletable);
}

/** What a set of items costs a month, or `null` when any of them has no known price. */
export function totalCost(items: OrphanItem[]): number | null {
  let sum = 0;
  for (const i of items) {
    if (i.month_cost === null) return null;
    sum += i.month_cost;
  }
  return sum;
}

/** The typed words must match exactly (surrounding spaces are not part of them). */
export function confirmMatches(typed: string, needed: string): boolean {
  return needed.length > 0 && typed.trim() === needed;
}

/** Why a resource cannot be chosen, in words. */
export function lockedText(i: OrphanItem): string | null {
  if (i.deletable) return null;
  return i.kind === 'image' && i.class === 'unused' ? t('orph.locked_image') : t('orph.locked_untagged');
}

/** Whether there is a real bill behind the page (as opposed to an estimate with a reason). */
export const hasBill = (b: BillResponse): boolean => b.basis === 'bill' && b.reconciliation !== null;
