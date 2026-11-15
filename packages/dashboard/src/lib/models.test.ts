import { describe, expect, it } from 'vitest';

import type { BoxRecord, EngineInfo, ModelPrice, ModelProvider, UsageRow } from '../api/types';
import { en } from '../i18n/en';
import { barPercent, fieldsFor, GUIDE_STEPS, gpuBoxes, KIND_LABEL, KINDS, MODEL_RE, perMtok, priceIsStale, providersFor, REGION_RE, RESOURCE_RE, tokens, usd } from './models';

const price = (o: Partial<ModelPrice>): ModelPrice => ({ input_per_mtok_usd: 1, output_per_mtok_usd: 2, origin: 'built_in', source: 'https://example.com', as_of: '2025-06', estimate: true, age_months: 17, ...o });
const prov = (id: string, kind: ModelProvider['kind']): ModelProvider => ({ id, kind, label: id, base_url: null, local_endpoint: false, monthly_cap_usd: null, region: null, resource: null, hosted_on: null });

describe('provider types', () => {
  it('every type has a label and a guide, and every guide step is in the catalogue', () => {
    for (const k of KINDS) {
      expect(en[KIND_LABEL[k]], k).toBeTruthy();
      expect(GUIDE_STEPS[k].length, k).toBeGreaterThanOrEqual(3);
      for (const key of GUIDE_STEPS[k]) expect(en[key], key).toBeTruthy();
    }
  });

  it('the cloud types name what they need and only the local type may skip a key', () => {
    expect(fieldsFor('bedrock')).toMatchObject({ region: true, resource: false, ownCloud: true, keyOptional: false });
    expect(fieldsFor('azure_openai')).toMatchObject({ resource: true, region: false, ownCloud: true });
    expect(fieldsFor('vertex').ownCloud).toBe(true);
    expect(fieldsFor('openai_compatible')).toMatchObject({ baseUrl: true, keyOptional: true });
    expect(KINDS.filter((k) => fieldsFor(k).keyOptional)).toEqual(['openai_compatible']);
  });

  it('region, resource and model names are checked like the server checks them', () => {
    expect(REGION_RE.test('us-east-1')).toBe(true);
    expect(REGION_RE.test('eu-central-1')).toBe(true);
    expect(REGION_RE.test('us-east')).toBe(false);
    expect(REGION_RE.test('evil.example.com')).toBe(false);
    expect(RESOURCE_RE.test('my-resource')).toBe(true);
    expect(RESOURCE_RE.test('-bad')).toBe(false);
    expect(RESOURCE_RE.test('a.b')).toBe(false);
    expect(MODEL_RE.test('anthropic.claude-v1:0')).toBe(true);
    expect(MODEL_RE.test('has space')).toBe(false);
  });
});

describe('engines and providers', () => {
  const engine: EngineInfo = { id: 'claude-code', label: 'Claude Code', kinds: ['anthropic', 'bedrock'] };
  it('an engine is offered only the providers it can speak to', () => {
    const list = [prov('a', 'anthropic'), prov('o', 'openai'), prov('b', 'bedrock')];
    expect(providersFor(engine, list).map((p) => p.id)).toEqual(['a', 'b']);
    expect(providersFor(undefined, list)).toEqual([]);
  });
});

describe('prices and usage', () => {
  it('formats money and tokens without inventing precision', () => {
    expect(perMtok(3)).toBe('3');
    expect(perMtok(0.15)).toBe('0.15');
    expect(usd(0)).toBe('0.00');
    expect(usd(0.001)).toBe('<0.01');
    expect(usd(12.345)).toBe('12.35');
    expect(tokens(999)).toBe('999');
    expect(tokens(1500)).toBe('1.5k');
    expect(tokens(2_500_000)).toBe('2.5M');
  });

  it('only an old built-in price is called stale', () => {
    expect(priceIsStale(price({ age_months: 17 }))).toBe(true);
    expect(priceIsStale(price({ age_months: 2 }))).toBe(false);
    expect(priceIsStale(price({ origin: 'entered', age_months: null }))).toBe(false);
    expect(priceIsStale(null)).toBe(false);
  });

  it('a day bar is relative to the busiest day, by cost and by tokens when nothing is priced', () => {
    const row = (key: string, cost: number, inp = 0): UsageRow => ({ key, input_tokens: inp, output_tokens: 0, cached_input_tokens: 0, calls: 1, est_cost_usd: cost, unpriced_calls: 0 });
    const rows = [row('a', 1), row('b', 4)];
    expect(barPercent(rows[0] as UsageRow, rows)).toBe(25);
    expect(barPercent(rows[1] as UsageRow, rows)).toBe(100);
    const free = [row('a', 0, 100), row('b', 0, 50)];
    expect(barPercent(free[1] as UsageRow, free)).toBe(50);
    expect(barPercent(row('z', 0), [row('z', 0)])).toBe(0);
  });

  it('GPU boxes are the ones with a GPU size', () => {
    const box = (name: string, size: BoxRecord['spec']['size']): BoxRecord => ({ spec: { name, size, work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} }, state: 'running', provider: 'fake', provider_id: null, machine_type: null, snapshots: [], created_at: null, last_activity_at: null });
    expect(gpuBoxes([box('a', 'M'), box('g', { Gpu: 'Small' })]).map((b) => b.spec.name)).toEqual(['g']);
  });
});
