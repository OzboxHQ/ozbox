import { describe, expect, it } from 'vitest';

import type { SetupPlan } from '../api/setup';
import { canContinue, estimateLabel, fromCheck, initialState, setupReducer, stepNumber, stepsFor, type SetupAction, type SetupState } from './setup-flow';

const run = (actions: SetupAction[], from: SetupState = initialState) => actions.reduce(setupReducer, from);
const plan = (over: Partial<SetupPlan> = {}): SetupPlan => ({
  plan_id: 'p1',
  step: 'state_bucket',
  summary: 'State storage',
  changes: [{ kind: 'bucket.create', description: 'Create it', risk: 'medium' }],
  notes: [],
  estimate_usd_month: 0,
  noop: false,
  expires_in_s: 600,
  ...over,
});

describe('which steps a provider has', () => {
  it('the free sandbox is short, a cloud has every check', () => {
    expect(stepsFor('fake')).toEqual(['provider', 'locale', 'done']);
    expect(stepsFor('aws')).toContain('bucket');
    expect(stepsFor('aws')).toContain('network');
    expect(stepsFor('hcloud')).not.toContain('bucket');
    expect(stepsFor(null)).toEqual(['provider']);
  });
  it('the order puts the guard rail before anything can be created and security last', () => {
    const s = stepsFor('aws');
    expect(s.indexOf('sign_in')).toBeLessThan(s.indexOf('permissions'));
    expect(s.indexOf('permissions')).toBeLessThan(s.indexOf('region'));
    expect(s.indexOf('network')).toBeLessThan(s.indexOf('guardrails'));
    expect(s[s.length - 2]).toBe('security');
  });
});

describe('moving on', () => {
  it('needs a provider first, then each step has to be passed', () => {
    let s = run([{ type: 'next' }]);
    expect(s.step).toBe('provider');
    s = run([{ type: 'provider', provider: 'aws' }, { type: 'next' }]);
    expect(s.step).toBe('sign_in');
    expect(run([{ type: 'next' }], s).step).toBe('sign_in');
    s = run([{ type: 'signed_in', identity: null }, { type: 'next' }], s);
    expect(s.step).toBe('permissions');
    expect(canContinue(s)).toBe(false);
    s = run([{ type: 'permissions', probes: [], ok: false }], s);
    expect(canContinue(s)).toBe(false);
    s = run([{ type: 'permissions', probes: [], ok: true }, { type: 'next' }], s);
    expect(s.step).toBe('region');
  });
  it('changing the profile forgets the sign-in, because it is a different identity', () => {
    const s = run([{ type: 'provider', provider: 'aws' }, { type: 'signed_in', identity: null }, { type: 'profile', value: 'other' }]);
    expect(s.signedIn).toBe(false);
  });
  it('switching provider starts over but keeps the typed profile', () => {
    const s = run([{ type: 'profile', value: 'work' }, { type: 'provider', provider: 'aws' }, { type: 'signed_in', identity: null }, { type: 'provider', provider: 'hcloud' }]);
    expect(s.signedIn).toBe(false);
    expect(s.profile).toBe('work');
    expect(s.provider).toBe('hcloud');
  });
  it('back never leaves the first step and never leaves done', () => {
    expect(run([{ type: 'back' }]).step).toBe('provider');
    const s = run([{ type: 'provider', provider: 'fake' }, { type: 'finished' }, { type: 'back' }]);
    expect(s.step).toBe('done');
  });
  it('nothing moves while something is running', () => {
    const s = run([{ type: 'provider', provider: 'aws' }, { type: 'signed_in', identity: null }, { type: 'busy' }, { type: 'next' }, { type: 'back' }]);
    expect(s.step).toBe('provider');
  });
});

describe('plan, then apply', () => {
  const at = (): SetupState => run([{ type: 'provider', provider: 'aws' }, { type: 'region', value: 'us-east-1' }]);
  it('a plan is shown before it can be applied, and applying is only possible from review', () => {
    let s = run([{ type: 'apply', which: 'bucket' }], at());
    expect(s.bucket.phase).toBe('none');
    s = run([{ type: 'planning', which: 'bucket' }, { type: 'apply', which: 'bucket' }], at());
    expect(s.bucket.phase).toBe('planning');
    s = run([{ type: 'planning', which: 'bucket' }, { type: 'planned', which: 'bucket', plan: plan() }], at());
    expect(s.bucket.phase).toBe('review');
    expect(canContinue({ ...s, step: 'bucket' })).toBe(false);
    s = run([{ type: 'apply', which: 'bucket' }, { type: 'applied', which: 'bucket' }], s);
    expect(s.bucket.phase).toBe('applied');
    expect(canContinue({ ...s, step: 'bucket' })).toBe(true);
  });
  it('a plan that is already satisfied needs no apply', () => {
    const s = run([{ type: 'planning', which: 'network' }, { type: 'planned', which: 'network', plan: plan({ noop: true, changes: [], step: 'network' }) }], at());
    expect(s.network.phase).toBe('applied');
  });
  it('a failed apply goes back to review with the same plan, a failed plan back to nothing', () => {
    let s = run([{ type: 'planning', which: 'bucket' }, { type: 'planned', which: 'bucket', plan: plan() }, { type: 'apply', which: 'bucket' }, { type: 'failed', problem: { code: 'apply_failed', message: 'no' } }], at());
    expect(s.bucket).toEqual({ phase: 'review', plan: plan() });
    expect(s.problem?.code).toBe('apply_failed');
    s = run([{ type: 'planning', which: 'network' }, { type: 'failed', problem: { code: 'bucket_missing', message: 'x' } }], at());
    expect(s.network.phase).toBe('none');
    expect(s.busy).toBe(false);
  });
  it('choosing another region discards the plans made for the first', () => {
    const s = run([{ type: 'planning', which: 'bucket' }, { type: 'planned', which: 'bucket', plan: plan() }, { type: 'region', value: 'eu-west-1' }], at());
    expect(s.bucket.phase).toBe('none');
  });
});

describe('the guard rail and security', () => {
  const g = (): SetupState => run([{ type: 'provider', provider: 'aws' }]);
  it('needs a budget and a channel that can deliver', () => {
    const base = { ...g(), step: 'guardrails' as const };
    expect(canContinue(run([{ type: 'guardrails', budgetSet: true, alertReady: false }], base))).toBe(false);
    expect(canContinue(run([{ type: 'guardrails', budgetSet: false, alertReady: true }], base))).toBe(false);
    expect(canContinue(run([{ type: 'guardrails', budgetSet: true, alertReady: true }], base))).toBe(true);
  });
  it('a failed security check blocks, a reminder needs the acknowledgement', () => {
    const base = { ...g(), step: 'security' as const };
    const items = [{ id: 'two_factor', state: 'reminder' as const, message: 'm' }];
    let s = run([{ type: 'security', items, blocking: false }], base);
    expect(canContinue(s)).toBe(false);
    s = run([{ type: 'ack', value: true }], s);
    expect(canContinue(s)).toBe(true);
    s = run([{ type: 'security', items, blocking: true }], s);
    expect(canContinue(s)).toBe(false);
  });
  it('the free sandbox needs only the time zone and no budget', () => {
    const s = { ...run([{ type: 'provider', provider: 'fake' }, { type: 'next' }]) };
    expect(s.step).toBe('locale');
    expect(canContinue(s)).toBe(false);
    expect(canContinue(run([{ type: 'locale_saved' }], s))).toBe(true);
  });
});

describe('helpers', () => {
  it('numbers the steps without counting done', () => {
    expect(stepNumber(run([{ type: 'provider', provider: 'aws' }]))).toEqual({ n: 1, of: 9 });
  });
  it('turns a check answer into an action', () => {
    expect(fromCheck('permissions', { report: { probes: [], ok: true } })).toEqual({ type: 'permissions', probes: [], ok: true });
    expect(fromCheck('regions', { report: { candidates: [], suggested: 'eu-west-1' } })).toEqual({ type: 'regions', candidates: [], suggested: 'eu-west-1' });
  });
  it('picks the suggested region only when none was chosen', () => {
    const c = [{ region: 'eu-west-1', name: 'Ireland', ms: 20, offers_sizes: true }];
    expect(run([{ type: 'regions', candidates: c, suggested: 'eu-west-1' }]).region).toBe('eu-west-1');
    expect(run([{ type: 'region', value: 'us-east-1' }, { type: 'regions', candidates: c, suggested: 'eu-west-1' }]).region).toBe('us-east-1');
  });
  it('an unknown estimate is a dash, not zero', () => {
    expect(estimateLabel(null)).toBe('—');
    expect(estimateLabel(0)).toBe('$0');
    expect(estimateLabel(32.85)).toBe('about $32.85/month');
  });
});
