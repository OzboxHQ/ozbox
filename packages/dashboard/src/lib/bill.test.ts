import { describe, expect, it } from 'vitest';

import type { BillResponse, BudgetFigure, DayTotal, OrphanItem } from '../api/bill';
import { hrefs, parseRoute } from './router';
import { alertList, causeText, chartRows, chooseable, confirmMatches, diffHint, diffText, firedList, gauge, hasBill, lockedText, money, problemTitle, reasonText, showsActivation, totalCost, unfinishedDays } from './bill';

const budget = (over: Partial<BudgetFigure> = {}): BudgetFigure => ({
  monthly_usd: 1000,
  spent: 500,
  currency: 'USD',
  basis: 'bill',
  real_through: '2026-11-07',
  percent: 50,
  thresholds: [
    { percent: 50, on: true },
    { percent: 80, on: false },
    { percent: 100, on: true },
  ],
  fired: [50],
  ...over,
});

const item = (over: Partial<OrphanItem> = {}): OrphanItem => ({
  id: 'vol-1',
  kind: 'volume',
  region: 'r',
  class: 'unused',
  reason: 'retired_work_disk',
  box_name: null,
  name: null,
  size_gb: 10,
  created: null,
  month_cost: 1,
  cost_is_most: false,
  deletable: true,
  ...over,
});

describe('bill helpers', () => {
  it('shows an absent amount as a dash, never zero', () => {
    expect(money(null, 'USD')).toBe('—');
    expect(money(12.5, 'USD')).toBe('$12.50');
  });

  it('words the first cause and fills its detail', () => {
    expect(causeText([])).toBe('No single cause found.');
    expect(causeText([{ kind: 'unmodelled_service', detail: 'Amazon Virtual Private Cloud' }])).toContain('Amazon Virtual Private Cloud');
    expect(causeText([{ kind: 'partly_watched', detail: '6' }])).toContain('6 hours');
  });

  it('draws only finished days and names the others', () => {
    const days: DayTotal[] = [
      { date: '2026-11-07', partial: false, estimate: 20, real: 21 },
      { date: '2026-11-08', partial: true, estimate: 20, real: 3 },
      { date: '2026-11-09', partial: true, estimate: 4, real: null },
    ];
    expect(chartRows(days)).toEqual([{ date: '2026-11-07', real: 21, estimate: 20 }]);
    expect(unfinishedDays(days)).toEqual(['2026-11-08', '2026-11-09']);
  });

  it('draws the budget gauge only when there is both a budget and a figure, and caps the bar not the number', () => {
    expect(gauge(budget())).toEqual({ fill: 50, pct: 50, tone: 'ok' });
    expect(gauge(budget({ percent: 85 }))?.tone).toBe('warn');
    expect(gauge(budget({ percent: 140 }))).toEqual({ fill: 100, pct: 140, tone: 'over' });
    expect(gauge(budget({ monthly_usd: null, percent: null }))).toBeNull();
    expect(gauge(budget({ percent: null }))).toBeNull();
  });

  it('lists the thresholds that are on and the ones already told', () => {
    expect(alertList(budget())).toBe('50%, 100%');
    expect(alertList(budget({ thresholds: [] }))).toBe('');
    expect(firedList(budget({ fired: [50, 80] }))).toBe('50%, 80%');
  });

  it('writes a difference with its sign and a hint that is not colour', () => {
    expect(diffText(10, 'USD')).toBe('+$10.00');
    expect(diffText(-3, 'USD')).toBe('−$3.00');
    expect(diffText(0, 'USD')).toBe('$0.00');
    expect(diffHint(10)).toBe('The bill is higher');
    expect(diffHint(-1)).toBe('The bill is lower');
    expect(diffHint(0.001)).toBe('They match');
    expect(diffHint(null)).toBeNull();
  });

  it('says what each problem is and when the activation steps help', () => {
    expect(problemTitle('tag_not_active')).toContain('tag');
    expect(showsActivation('tag_not_active')).toBe(true);
    expect(showsActivation('not_enabled')).toBe(true);
    expect(showsActivation('unsupported')).toBe(false);
    expect(showsActivation('access_denied')).toBe(false);
  });

  it('lets a person choose only what Oz Box may delete, and sums a cost only when every price is known', () => {
    const items = [item(), item({ id: 'i-1', kind: 'instance', class: 'untagged', deletable: false }), item({ id: 'ami-1', kind: 'image', deletable: false })];
    expect(chooseable(items).map((i) => i.id)).toEqual(['vol-1']);
    expect(lockedText(items[0] as OrphanItem)).toBeNull();
    expect(lockedText(items[1] as OrphanItem)).toContain('Not tagged');
    expect(lockedText(items[2] as OrphanItem)).toContain('built');
    expect(totalCost([item({ month_cost: 2 }), item({ month_cost: 3 })])).toBe(5);
    expect(totalCost([item({ month_cost: 2 }), item({ month_cost: null })])).toBeNull();
  });

  it('matches the typed words exactly, ignoring only surrounding space', () => {
    expect(confirmMatches('delete-2', 'delete-2')).toBe(true);
    expect(confirmMatches('  delete-2 ', 'delete-2')).toBe(true);
    expect(confirmMatches('Delete-2', 'delete-2')).toBe(false);
    expect(confirmMatches('delete-3', 'delete-2')).toBe(false);
    expect(confirmMatches('', '')).toBe(false);
  });

  it('words every reason', () => {
    for (const r of ['no_managed_tag', 'retired_work_disk', 'work_disk_no_box', 'unattached_volume', 'snapshot_no_box', 'snapshot_box_gone', 'unsigned_image', 'failed_image'] as const) {
      expect(reasonText(r).length).toBeGreaterThan(5);
    }
  });

  it('has a bill only when it was read and reconciled', () => {
    const base = { basis: 'estimate', reconciliation: null } as unknown as BillResponse;
    expect(hasBill(base)).toBe(false);
    expect(hasBill({ ...base, basis: 'bill', reconciliation: {} as BillResponse['reconciliation'] })).toBe(true);
  });

  it('has its own route, under Costs', () => {
    expect(parseRoute('/costs/bill')).toEqual({ page: 'bill' });
    expect(hrefs.bill).toBe('/costs/bill');
    expect(parseRoute('/costs')).toEqual({ page: 'missing' });
    expect(parseRoute('/costs/other')).toEqual({ page: 'missing' });
  });
});
