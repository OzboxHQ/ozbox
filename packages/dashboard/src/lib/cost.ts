import type { CostResponse, PriceInfo } from '../api/types';
import { t } from './i18n';
import { fmtCost } from './format';

/** "AWS Price List API, on-demand Linux · fetched 3 h ago", or "stale" when the prices are old. Never shown as live. */
export function priceSourceLine(p: PriceInfo | null, enteredUsed: boolean): string {
  if (!p) return enteredUsed ? t('cost.source_entered') : t('cost.source_none');
  const age = p.age_s < 3600 ? t('cost.age_minutes', { n: Math.max(1, Math.round(p.age_s / 60)) }) : p.age_s < 172800 ? t('cost.age_hours', { n: Math.round(p.age_s / 3600) }) : t('cost.age_days', { n: Math.round(p.age_s / 86400) });
  return `${p.source} · ${t('cost.fetched', { age })}${p.stale ? ` · ${t('cost.stale')}` : ''}`;
}

/** An estimate, always labelled as one. "—" when no price is known. */
export function fmtEstimate(v: number | null | undefined, currency: string | null | undefined): string {
  if (v === null || v === undefined || !currency) return fmtCost(null);
  return `${fmtCost(v, currency)} ${t('cost.est')}`;
}

export function costFor(cost: CostResponse | null, name: string) {
  return cost?.boxes.find((b) => b.name === name) ?? null;
}
