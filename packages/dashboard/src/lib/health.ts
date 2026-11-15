import { t } from './i18n';
import type { Incident, SelfTest, SelfTestCheck } from '../api/types';

export type Overall = 'failed' | 'unverified' | 'passed';

/** A failed check outranks everything; an unknown check is never counted as a pass. */
export function overall(t: SelfTest): Overall {
  if (t.checks.some((c) => c.outcome === 'fail')) return 'failed';
  if (t.checks.some((c) => c.outcome === 'unknown')) return 'unverified';
  return 'passed';
}

export function overallText(o: Overall): string {
  return o === 'failed' ? 'A check failed' : o === 'unverified' ? 'Passed, but some checks could not be verified' : 'All checks passed';
}

export function checkText(c: SelfTestCheck): string {
  return c.outcome === 'pass' ? 'Pass' : c.outcome === 'fail' ? 'Fail' : 'Unknown';
}

/** The steps that failed, in order, with the reason. */
export function failingSteps(t: SelfTest): { step: string; reason: string }[] {
  return t.checks.flatMap((c) => (c.outcome === 'fail' ? [{ step: c.step, reason: c.reason }] : []));
}

const KINDS: Record<string, string> = {
  restart: 'Restarted',
  oom_kill: 'Out of memory kill',
  stop_request_failed: 'Stop request failed',
  checkpoint_failed: 'Checkpoint failed',
  self_test_failed: 'Self-test failed',
  backup_failed: 'Backup failed',
  run_start_failed: 'A run could not start',
  run_timed_out: 'A run timed out',
  interruption: 'Interrupted by the provider',
  metrics_degraded: 'Usage reporting degraded',
  unexpected: 'Unexpected problem',
};

/** Kinds whose label comes from the message catalogue. */
const KIND_KEYS = {
  disk_grown: 'health.disk_grown',
  disk_grow_failed: 'health.disk_grow_failed',
} as const;

export function incidentText(i: Incident): string {
  if (i.kind in KIND_KEYS) return t(KIND_KEYS[i.kind as keyof typeof KIND_KEYS]);
  return KINDS[i.kind] ?? i.kind.replace(/_/g, ' ');
}

/** Newest first. */
export function newestFirst(items: Incident[]): Incident[] {
  return [...items].sort((a, b) => b.ts_ms - a.ts_ms);
}
