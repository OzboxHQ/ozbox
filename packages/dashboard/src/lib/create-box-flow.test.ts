import { describe, expect, it } from 'vitest';

import type { ApplyResponse, PlanResponse } from '../api/types';
import { canContinue, createReducer, diskProblem, initialCreate, nameProblem, needsNetwork, parseLabels, refusalFix, stageOf, toOperation, type CreateAction, type CreateState } from './create-box-flow';

const start = () => initialCreate({ size: 'M', diskGb: 200 });
const run = (actions: CreateAction[], from: CreateState = start()) => actions.reduce(createReducer, from);
const plan = (noop = false): PlanResponse =>
  ({ plan_id: 'p', plan: { operation: { op: 'create' }, provider: 'fake', changes: [], notes: [], based_on: '' }, noop, requires_confirm_name: false, box_name: 'dev' }) as unknown as PlanResponse;
const applied = { applied: true } as unknown as ApplyResponse;

describe('the name', () => {
  it('is validated like a box name, live, and against existing boxes', () => {
    expect(nameProblem('', [])).toBe('create.name_required');
    for (const bad of ['Dev', '9lives', 'a--b', 'a_b', '-a', 'a-']) expect(nameProblem(bad, []), bad).toBe('create.name_invalid');
    expect(nameProblem('dev-1', [])).toBeNull();
    expect(nameProblem('dev', ['dev'])).toBe('create.name_taken');
  });
  it('blocks the first step until it is good', () => {
    expect(canContinue(start(), [])).toBe(false);
    expect(canContinue(run([{ type: 'set', patch: { name: 'dev' } }]), [])).toBe(true);
    expect(canContinue(run([{ type: 'set', patch: { name: 'dev' } }]), ['dev'])).toBe(false);
  });
});

describe('size and disk', () => {
  it('the disk must be a whole number of gigabytes in range', () => {
    expect(diskProblem(19)).toBe(true);
    expect(diskProblem(20)).toBe(false);
    expect(diskProblem(65537)).toBe(true);
    expect(diskProblem(20.5)).toBe(true);
    const s = run([{ type: 'set', patch: { name: 'dev', diskGb: 5 } }, { type: 'next' }]);
    expect(s.step).toBe('size');
    expect(canContinue(s, [])).toBe(false);
  });
});

describe('labels and options', () => {
  it('parses key=value lines and reports the rest', () => {
    expect(parseLabels('project=web\n\n team = a b ')).toEqual({ labels: { project: 'web', team: 'a b' }, bad: [] });
    expect(parseLabels('novalue\n=x\nok=1').bad).toEqual(['novalue', '=x']);
  });
  it('always-on replaces auto-pause in the request', () => {
    const f = { ...start().form, name: 'dev', alwaysOn: true, labels: 'a=b' };
    expect(toOperation(f).spec.labels).toEqual({ a: 'b', 'ozbox-always-on': 'true' });
    expect(toOperation({ ...f, alwaysOn: false }).spec.labels).toEqual({ a: 'b' });
    expect(toOperation({ ...f, region: '  ' }).spec.region).toBeNull();
    expect(toOperation({ ...f, region: 'eu-west-1' }).spec.region).toBe('eu-west-1');
  });
  it('a label line that is not key=value blocks the step', () => {
    const s = { ...start(), step: 'options' as const };
    expect(canContinue(run([{ type: 'set', patch: { labels: 'oops' } }], s), [])).toBe(false);
    expect(canContinue(run([{ type: 'set', patch: { labels: 'a=b' } }], s), [])).toBe(true);
  });
});

describe('a profile', () => {
  it('fills the tools and the box defaults it carries, and leaves the rest', () => {
    const s = run([{ type: 'profile', name: 'web', tools: ['git', 'node'], size: 'L', alwaysOn: true }]);
    expect(s.form).toMatchObject({ profile: 'web', tools: ['git', 'node'], size: 'L', alwaysOn: true, diskGb: 200 });
  });
});

describe('the plan is the review, and applying needs it', () => {
  const atReview = () => ({ ...start(), step: 'review' as const });
  it('only a plan on screen that changes something can be applied', () => {
    expect(run([{ type: 'apply' }], atReview()).review.phase).toBe('none');
    let s = run([{ type: 'planning' }, { type: 'planned', plan: plan(true) }, { type: 'apply' }], atReview());
    expect(s.review.phase).toBe('review');
    s = run([{ type: 'planning' }, { type: 'planned', plan: plan() }], atReview());
    expect(canContinue(s, [])).toBe(true);
    s = run([{ type: 'apply' }, { type: 'applied', response: applied }], s);
    expect(s.step).toBe('progress');
    expect(s.stage).toBe('booting');
  });
  it('changing anything after the plan was made throws the plan away', () => {
    const s = run([{ type: 'planning' }, { type: 'planned', plan: plan() }, { type: 'set', patch: { diskGb: 300 } }], atReview());
    expect(s.review.phase).toBe('none');
  });
  it('a change that arrives while the change is being applied does not wipe it, so the answer is not lost', () => {
    // applying runs in the background now; the tool list (or anything else) setting the form meanwhile used to drop the review
    const s = run([{ type: 'planning' }, { type: 'planned', plan: plan() }, { type: 'apply' }, { type: 'set', patch: { tools: ['git'] } }, { type: 'applied', response: applied }], atReview());
    expect(s.step).toBe('progress');
    expect(s.form.tools).toEqual(['git']);
  });
  it('a refusal keeps its code and fix, and a failed apply returns to review', () => {
    let s = run([{ type: 'planning' }, { type: 'refused', code: 'refused', message: 'over budget', fix: null }], atReview());
    expect(s.review).toMatchObject({ phase: 'refused', code: 'refused' });
    s = run([{ type: 'planning' }, { type: 'planned', plan: plan() }, { type: 'apply' }, { type: 'failed', message: 'x' }], atReview());
    expect(s.review.phase).toBe('review');
    expect(s.problem).toBe('x');
  });
  it('cannot go back while applying or once creating', () => {
    const applying = run([{ type: 'planning' }, { type: 'planned', plan: plan() }, { type: 'apply' }, { type: 'back' }], atReview());
    expect(applying.step).toBe('review');
    expect(run([{ type: 'back' }], { ...start(), step: 'progress' }).step).toBe('progress');
  });
});

describe('progress', () => {
  it('reads the stage from what can be observed', () => {
    expect(stageOf(null, false, null)).toBe('creating');
    expect(stageOf({ state: 'creating' }, false, null)).toBe('creating');
    expect(stageOf({ state: 'running' }, false, null)).toBe('booting');
    expect(stageOf({ state: 'running' }, true, null)).toBe('self_test');
    expect(stageOf({ state: 'running' }, true, true)).toBe('ready');
    expect(stageOf({ state: 'running' }, true, false)).toBe('failed');
  });
  it('a failed self-test is shown as failed, a passed one as ready', () => {
    const p = { ...start(), step: 'progress' as const };
    expect(run([{ type: 'self_test', passed: true }], p).stage).toBe('ready');
    expect(run([{ type: 'self_test', passed: false }], p).stage).toBe('failed');
  });
});

describe('refusals say what to do', () => {
  it('maps the server codes to a fix', () => {
    expect(refusalFix('guardrails_missing')).toBe('create.fix_guardrails');
    expect(refusalFix('refused')).toBe('create.fix_budget');
    expect(refusalFix('weird')).toBe('create.fix_generic');
    expect(needsNetwork('creating needs a private subnet: set subnet_id')).toBe(true);
    expect(needsNetwork('over budget')).toBe(false);
  });
});
