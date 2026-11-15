import { describe, expect, it } from 'vitest';

import type { BoxRecord, MetricsNow, MetricsSample } from '../api/types';
import { deriveAlerts } from './alerts';

function box(name: string, state: BoxRecord['state'] = 'running'): BoxRecord {
  return {
    spec: { name, size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} },
    state, provider: 'fake', provider_id: null, machine_type: null, snapshots: [], created_at: null, last_activity_at: null,
  };
}
function now(memUsed: number, diskUsed: number): MetricsNow {
  const sample = { ts_ms: 0, cpu_pct: 1, mem_total_bytes: 100, mem_available_bytes: 100 - memUsed, disk_total_bytes: 100, disk_free_bytes: 100 - diskUsed, runs: [] } as unknown as MetricsSample;
  return { source: 'simulated', sample };
}

describe('deriveAlerts', () => {
  it('is empty when all is well', () => {
    expect(deriveAlerts([box('a')], { a: now(50, 50) })).toEqual([]);
  });
  it('flags memory, disk and unknown state, urgent first', () => {
    const out = deriveAlerts([box('a'), box('b', 'unknown')], { a: now(95, 90) });
    expect(out.map((x) => x.id)).toEqual(['a:memory', 'b:state', 'a:disk']);
  });
  it('puts a failing self-test in Needs you, and says nothing for a passing one', () => {
    const failed = { ts_ms: 1, ok: false, all_verified: true, checks: [{ name: 'Backups', step: 'backup', outcome: 'fail', reason: 'no repository' }] } as never;
    const passed = { ts_ms: 1, ok: true, all_verified: true, checks: [{ name: 'Backups', step: 'backup', outcome: 'pass', reason: '' }] } as never;
    const out = deriveAlerts([box('a'), box('b')], {}, { a: failed, b: passed });
    expect(out.map((x) => x.id)).toEqual(['a:selftest']);
    expect(out[0]?.severity).toBe('critical');
    expect(out[0]?.text).toContain('backup');
  });
  it('says nothing about a box with no metrics', () => {
    expect(deriveAlerts([box('a')], {})).toEqual([]);
  });
});
