import { describe, expect, it } from 'vitest';

import type { ApplyResponse, PlanResponse } from '../api/types';
import { applyRequest, canConfirm, flowReducer, idle, ops, type FlowState } from './plan-flow';

function planFor(over: Partial<PlanResponse> = {}): PlanResponse {
  return {
    plan_id: 'p1',
    plan: { operation: ops.pause('dev'), provider: 'fake', changes: [{ kind: 'x', description: 'Stop', risk: 'low' }], notes: [], based_on: 'b' },
    box_name: 'dev',
    max_risk: 'low',
    noop: false,
    requires_confirm_name: false,
    expires_in_s: 600,
    ...over,
  };
}

function toReview(plan: PlanResponse): FlowState {
  let s = flowReducer(idle, { type: 'start', operation: plan.plan.operation });
  s = flowReducer(s, { type: 'planned', plan });
  return s;
}

describe('plan flow', () => {
  it('never applies without passing through review and an explicit confirm', () => {
    let s = flowReducer(idle, { type: 'start', operation: ops.pause('dev') });
    expect(s.phase).toBe('planning');
    expect(flowReducer(s, { type: 'confirm' }).phase).toBe('planning');
    s = flowReducer(s, { type: 'planned', plan: planFor() });
    expect(s.phase).toBe('review');
    expect(applyRequest(s)).toBeNull();
    s = flowReducer(s, { type: 'confirm' });
    expect(s.phase).toBe('applying');
    expect(applyRequest(s)).toEqual({ plan_id: 'p1', plan: planFor().plan });
  });

  it('a high-risk plan needs the exact box name', () => {
    const high = planFor({ max_risk: 'high', requires_confirm_name: true });
    let s = toReview(high);
    expect(canConfirm(s)).toBe(false);
    s = flowReducer(s, { type: 'typed', text: 'DEV' });
    expect(canConfirm(s)).toBe(false);
    expect(flowReducer(s, { type: 'confirm' }).phase).toBe('review');
    s = flowReducer(s, { type: 'typed', text: 'dev' });
    expect(canConfirm(s)).toBe(true);
    s = flowReducer(s, { type: 'confirm' });
    expect(applyRequest(s)?.confirm_name).toBe('dev');
  });

  it('a plan that does nothing cannot be applied', () => {
    expect(canConfirm(toReview(planFor({ noop: true })))).toBe(false);
  });

  it('cancel closes, except while applying', () => {
    let s = toReview(planFor());
    expect(flowReducer(s, { type: 'cancel' })).toEqual(idle);
    s = flowReducer(s, { type: 'confirm' });
    expect(flowReducer(s, { type: 'cancel' }).phase).toBe('applying');
    const response: ApplyResponse = { plan: planFor().plan, applied: true, result: null };
    s = flowReducer(s, { type: 'applied', response });
    expect(s.phase).toBe('done');
    expect(flowReducer(s, { type: 'cancel' })).toEqual(idle);
  });

  it('failures land in an error state with the message', () => {
    const s = flowReducer(flowReducer(idle, { type: 'start', operation: ops.pause('dev') }), { type: 'failed', message: 'nope', code: 'x' });
    expect(s).toMatchObject({ phase: 'error', message: 'nope' });
  });
});
