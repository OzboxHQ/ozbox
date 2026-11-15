import { describe, expect, it } from 'vitest';

import type { BudgetSettings, DefaultsSettings, SizeInfo } from '../api/types';
import { budgetSchema, budgetToForm, defaultsSchema, defaultsToForm, formToBudget, formToDefaults, sizeId } from './settings-form';

const budget: BudgetSettings = {
  monthly_usd: 500.5,
  alert_50: true,
  alert_80: false,
  alert_100: true,
  quiet_from: '23:00',
  quiet_to: '07:00',
  utc_offset_minutes: 60,
  in_app: false,
  max_running_boxes: 4,
  size_prices_usd: { M: 200, S: 100 },
  drift_alert_pct: 30,
  drift_alert_min_usd: 2.5,
};
const defaults: DefaultsSettings = { size: { Gpu: 'Small' }, work_disk_gb: 200, auto_pause_minutes: 90, always_on: false, image_channel: 'stable' };
const sizes: SizeInfo[] = [
  { id: 'M', size: 'M', vcpus: 8, memory_gb: 32, gpus: 0 },
  { id: 'GPU-S', size: { Gpu: 'Small' }, vcpus: 8, memory_gb: 32, gpus: 1 },
];

describe('settings forms', () => {
  it('round-trips a budget through the form text', () => {
    const f = budgetToForm(budget);
    expect(budgetSchema.safeParse(f).success).toBe(true);
    expect(formToBudget(f)).toEqual(budget);
  });

  it('an empty budget, cap or price means none, never zero', () => {
    const f = { ...budgetToForm(budget), monthly: '', maxRunning: '', prices: { M: '', S: '100' } };
    const b = formToBudget(f);
    expect(b.monthly_usd).toBeNull();
    expect(b.max_running_boxes).toBeNull();
    expect(b.size_prices_usd).toEqual({ S: 100 });
  });

  it('catches typing mistakes before the server does', () => {
    const f = budgetToForm(budget);
    for (const bad of [{ monthly: 'lots' }, { monthly: '0' }, { maxRunning: '0' }, { maxRunning: '1001' }, { quietFrom: '25:00' }, { utcOffset: '900' }, { utcOffset: 'x' }, { driftPct: '0' }, { driftPct: '1001' }, { driftPct: 'x' }, { driftMinUsd: '-1' }, { driftMinUsd: '' }, { prices: { M: '-3' } }]) {
      expect(budgetSchema.safeParse({ ...f, ...bad }).success, JSON.stringify(bad)).toBe(false);
    }
  });

  it('the drift alert accepts its limits and falls back to the server defaults for an older server', () => {
    const f = budgetToForm(budget);
    for (const ok of [{ driftPct: '1' }, { driftPct: '1000' }, { driftMinUsd: '0' }, { driftMinUsd: '12.5' }]) {
      expect(budgetSchema.safeParse({ ...f, ...ok }).success, JSON.stringify(ok)).toBe(true);
    }
    const old: BudgetSettings = { ...budget };
    delete old.drift_alert_pct;
    delete old.drift_alert_min_usd;
    const g = budgetToForm(old);
    expect([g.driftPct, g.driftMinUsd]).toEqual(['25', '2']);
    expect(formToBudget({ ...f, driftPct: '40', driftMinUsd: '0' })).toMatchObject({ drift_alert_pct: 40, drift_alert_min_usd: 0 });
  });

  it('validates defaults and maps the size back to the provider size', () => {
    const f = defaultsToForm(defaults);
    expect(f.size).toBe('GPU-S');
    expect(defaultsSchema.safeParse(f).success).toBe(true);
    expect(defaultsSchema.safeParse({ ...f, disk: '5' }).success).toBe(false);
    expect(defaultsSchema.safeParse({ ...f, autoPauseMinutes: '2' }).success).toBe(false);
    expect(formToDefaults(f, sizes)).toEqual(defaults);
    expect(formToDefaults({ ...f, size: 'XXL' }, sizes)).toBeNull();
    expect(sizeId('XL')).toBe('XL');
  });
});
