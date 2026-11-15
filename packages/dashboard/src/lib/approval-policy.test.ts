import { describe, expect, it } from 'vitest';

import type { ApprovalPolicy } from '../api/tasks';
import { capsLoosen, capsToForm, formToCaps, formToPolicy, policyChanges, policyLoosens, policyToForm, usedPct } from './approval-policy';

const policy: ApprovalPolicy = {
  ask: ['push_protected_branch', 'ask_command'],
  protected_branches: ['main', 'release/*'],
  ask_commands: ['sudo', 'rm -rf'],
  spend_threshold_cents: 2000,
  expiry_s: 28800,
  approvers: [],
  allow_requester: true,
  step_up: ['production_resource'],
};

describe('the approval policy form', () => {
  it('round-trips a policy', () => {
    const r = formToPolicy(policyToForm(policy));
    expect(r).toEqual({ ok: true, value: policy });
  });

  it('refuses text that could not be a branch, a command or a dollar amount', () => {
    const f = policyToForm(policy);
    expect(formToPolicy({ ...f, protected_branches: 'bad branch' })).toEqual({ ok: false, error: 'policy.err_branches' });
    expect(formToPolicy({ ...f, ask_commands: 'rm\u0007' })).toEqual({ ok: false, error: 'policy.err_commands' });
    expect(formToPolicy({ ...f, spend_threshold: 'lots' })).toEqual({ ok: false, error: 'policy.err_threshold' });
    expect(formToPolicy({ ...f, approvers: 'a b' })).toEqual({ ok: false, error: 'policy.err_approvers' });
  });

  it('an empty threshold means no threshold, and kinds keep their canonical order', () => {
    const f = { ...policyToForm(policy), spend_threshold: '', ask: ['ask_command', 'push_protected_branch'] as ApprovalPolicy['ask'] };
    const r = formToPolicy(f);
    expect(r.ok && r.value.spend_threshold_cents).toBeNull();
    expect(r.ok && r.value.ask).toEqual(['push_protected_branch', 'ask_command']);
  });

  it('lists exactly what changed for the review step', () => {
    const next = { ...policy, expiry_s: 3600, protected_branches: ['main'] };
    const c = policyChanges(policy, next, (k) => k);
    expect(c.map((x) => x.key)).toEqual(['policy.f_branches', 'policy.f_expiry']);
    expect(policyChanges(policy, policy, (k) => k)).toEqual([]);
  });
});

describe('the spend limits form', () => {
  it('reads dollars and per-person lines', () => {
    const r = formToCaps({ fleet: '500', person: '50.5', overrides: 'ada = 100\nbo=20.25' });
    expect(r).toEqual({ ok: true, value: { fleet_monthly_cents: 50000, person_monthly_cents: 5050, per_person: { ada: 10000, bo: 2025 } } });
  });
  it('empty means no limit, and a bad line is refused', () => {
    expect(formToCaps({ fleet: '', person: '', overrides: '' })).toEqual({ ok: true, value: { fleet_monthly_cents: null, person_monthly_cents: null, per_person: {} } });
    expect(formToCaps({ fleet: 'x', person: '', overrides: '' })).toEqual({ ok: false, error: 'caps.err_fleet' });
    expect(formToCaps({ fleet: '', person: '', overrides: 'ada 100' })).toEqual({ ok: false, error: 'caps.err_override' });
  });
  it('round-trips and shows how much of a limit is used', () => {
    const caps = { fleet_monthly_cents: 5000, person_monthly_cents: null, per_person: { ada: 1000 } };
    expect(formToCaps(capsToForm(caps))).toEqual({ ok: true, value: caps });
    expect(usedPct(2500, 5000)).toBe(50);
    expect(usedPct(9000, 5000)).toBe(100);
    expect(usedPct(10, null)).toBeNull();
  });
});

describe('what counts as loosening (mirrors the server, which asks for the passkey)', () => {
  it('is false for no change and for a change that asks for more', () => {
    expect(policyLoosens(policy, policy)).toBe(false);
    expect(policyLoosens(policy, { ...policy, ask: [...policy.ask, 'outbound_message'], expiry_s: 60 * 60 })).toBe(false);
    expect(policyLoosens(policy, { ...policy, spend_threshold_cents: 500, allow_requester: true })).toBe(false);
  });

  it('counts an expiry raised past 8 hours, and nothing else about expiry (owner decision D16)', () => {
    const at = (expiry_s: number) => ({ ...policy, expiry_s });
    expect(policyLoosens(policy, at(8 * 3600))).toBe(false);
    expect(policyLoosens(policy, at(8 * 3600 + 60))).toBe(true);
    expect(policyLoosens(policy, at(72 * 3600))).toBe(true);
    expect(policyLoosens(at(3600), at(8 * 3600))).toBe(false);
    expect(policyLoosens(at(3600), at(24 * 3600))).toBe(true);
    expect(policyLoosens(at(24 * 3600), at(24 * 3600))).toBe(false);
    expect(policyLoosens(at(72 * 3600), at(24 * 3600))).toBe(false);
    expect(policyLoosens(at(24 * 3600), at(72 * 3600))).toBe(true);
  });

  it('is true for each way of asking for less', () => {
    expect(policyLoosens(policy, { ...policy, ask: ['ask_command'] })).toBe(true);
    expect(policyLoosens(policy, { ...policy, protected_branches: ['main'] })).toBe(true);
    expect(policyLoosens(policy, { ...policy, ask_commands: ['sudo'] })).toBe(true);
    expect(policyLoosens(policy, { ...policy, spend_threshold_cents: null })).toBe(true);
    expect(policyLoosens(policy, { ...policy, spend_threshold_cents: 5000 })).toBe(true);
    expect(policyLoosens(policy, { ...policy, step_up: [] })).toBe(true);
    const strict = { ...policy, allow_requester: false, approvers: ['ada'] };
    expect(policyLoosens(strict, { ...strict, allow_requester: true })).toBe(true);
    expect(policyLoosens(strict, { ...strict, approvers: [] })).toBe(true);
    expect(policyLoosens(strict, { ...strict, approvers: ['ada', 'bob'] })).toBe(true);
    expect(policyLoosens(strict, { ...strict, approvers: ['ada'] })).toBe(false);
  });

  it('treats a raised or removed spend limit as loosening, a lowered or added one not', () => {
    const caps = { fleet_monthly_cents: 5000, person_monthly_cents: null, per_person: { ada: 1000 } };
    expect(capsLoosen(caps, caps)).toBe(false);
    expect(capsLoosen(caps, { ...caps, fleet_monthly_cents: 4000, person_monthly_cents: 100 })).toBe(false);
    expect(capsLoosen(caps, { ...caps, fleet_monthly_cents: 9000 })).toBe(true);
    expect(capsLoosen(caps, { ...caps, fleet_monthly_cents: null })).toBe(true);
    expect(capsLoosen(caps, { ...caps, per_person: {} })).toBe(true);
    expect(capsLoosen(caps, { ...caps, per_person: { ada: 2000 } })).toBe(true);
    // bob has no limit of his own, so he is held to the default; a new own limit above it is a raise
    const withDefault = { fleet_monthly_cents: 5000, person_monthly_cents: 100, per_person: { ada: 1000 } };
    expect(capsLoosen(withDefault, { ...withDefault, per_person: { ada: 1000, bob: 9000 } })).toBe(true);
    expect(capsLoosen(withDefault, { ...withDefault, per_person: { ada: 1000, bob: 50 } })).toBe(false);
    expect(capsLoosen(withDefault, { ...withDefault, per_person: {} })).toBe(false);
    expect(capsLoosen(caps, { ...caps, per_person: { ada: 500, bob: 9000 } })).toBe(false);
  });
});
