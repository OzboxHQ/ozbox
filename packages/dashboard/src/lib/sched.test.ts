import { describe, expect, it } from 'vitest';

import type { Delivery, ScheduleItem, SchedRun } from '../api/sched';
import { boxChoices, choiceFromTarget, defaultEngine, deliveryWhy, emptyScheduleForm, engineChoices, emptyTriggerForm, formToInput, previewKey, runNote, scheduleSchema, scheduleToForm, targetFromChoice, triggerFormToInput, triggerSchema, whenText } from './sched';

const base = { ...emptyScheduleForm('Africa/Lagos'), name: 'Morning brief', whenText: 'every weekday at 9am', prompt: 'Summarise CI.', box: 'alpha' };

const item: ScheduleItem = {
  id: 'sch-1', name: 'Morning brief', when: { kind: 'cron', expr: '0 9 * * 1-5' }, plain: 'every weekday at 9am', time_zone: 'Africa/Lagos', owner: '', engine: 'claude',
  prompt: 'Summarise CI.', skill: null, target: { box_name: 'alpha', profile: null }, caps: { max_spend_cents: 250, max_minutes: 30 }, results_to: ['alert'], catch_up_minutes: 120,
  enabled: true, heartbeat: false, next: null, last_run: null, running: false, cost: null,
};

describe('the schedule form', () => {
  it('accepts plain words or cron, and a heartbeat with an interval', () => {
    expect(scheduleSchema.safeParse(base).success).toBe(true);
    expect(scheduleSchema.safeParse({ ...base, whenText: '', cron: '*/5 * * * *' }).success).toBe(true);
    expect(scheduleSchema.safeParse({ ...base, kind: 'heartbeat', whenText: '', prompt: '', everyMinutes: '15' }).success).toBe(true);
  });

  it('refuses what cannot work, with a message key', () => {
    const issues = (v: object) => scheduleSchema.safeParse({ ...base, ...v }).error?.issues.map((i) => i.message) ?? [];
    expect(issues({ name: ' ' })).toContain('err_name');
    expect(issues({ whenText: '', cron: '' })).toContain('err_when');
    expect(issues({ prompt: '', skill: '' })).toContain('err_prompt');
    expect(issues({ box: '' })).toContain('err_box');
    expect(issues({ engine: 'Claude Code' })).toContain('err_engine');
    expect(issues({ kind: 'heartbeat', everyMinutes: '1' })).toContain('err_every');
    expect(issues({ maxSpend: '-3' })).toContain('err_number');
  });

  it('turns dollars into cents and words into the request the server reads', () => {
    const input = formToInput({ ...base, maxSpend: '2.5', maxMinutes: '30', alertOnFinish: true });
    expect(input).toMatchObject({ when_text: 'every weekday at 9am', time_zone: 'Africa/Lagos', caps: { max_spend_cents: 250, max_minutes: 30 }, results_to: ['alert'], heartbeat: false });
    expect(input.cron).toBeUndefined();
    expect(formToInput({ ...base, whenText: '', cron: '0 9 * * *' }).cron).toBe('0 9 * * *');
    expect(formToInput({ ...base, kind: 'heartbeat', everyMinutes: '20' }).every_minutes).toBe(20);
  });

  it('round-trips a stored schedule into the form', () => {
    const f = scheduleToForm(item);
    expect(f).toMatchObject({ whenText: 'every weekday at 9am', cron: '', maxSpend: '2.5', maxMinutes: '30', box: 'alpha', alertOnFinish: true });
  });

  it('a change to the time invalidates the preview, a change to the prompt does not', () => {
    expect(previewKey(base)).toBe(previewKey({ ...base, prompt: 'other' }));
    expect(previewKey(base)).not.toBe(previewKey({ ...base, whenText: 'every day at 8am' }));
    expect(previewKey(base)).not.toBe(previewKey({ ...base, timeZone: 'UTC' }));
  });

  it('describes when it runs', () => {
    expect(whenText(item)).toBe('every weekday at 9am');
    expect(whenText({ ...item, plain: null })).toBe('0 9 * * 1-5 in Africa/Lagos');
    expect(whenText({ ...item, when: { kind: 'every', minutes: 30 } })).toBe('Every 30 minutes');
  });
});

const run = (r: Partial<SchedRun>): SchedRun => ({ id: 'r', owner_id: 's', source: 'schedule', slot_ms: 0, started_ms: 0, finished_ms: null, status: 'skipped', detail: 'server words', reason: '', args: {}, box_name: null, woke_box: false, cost: null, result_url: null, ...r });

describe('run notes', () => {
  it('words known reasons itself and falls back to the server sentence', () => {
    expect(runNote(run({ reason: 'overlap' }), 120)).toBe('Skipped: the previous run was still going.');
    expect(runNote(run({ reason: 'missed' }), 120)).toContain('120 minutes late');
    expect(runNote(run({ reason: 'caught_up', args: { late_minutes: '45' } }), 120)).toBe('Made up 45 minutes late.');
    expect(runNote(run({ reason: 'resume_failed' }), 120)).toBe('server words');
    expect(runNote(run({ reason: 'caught_up', args: { late_minutes: '5', skipped_earlier: '9' } }), 120)).toContain('9 earlier missed runs');
  });
});

describe('triggers', () => {
  const f = { ...emptyTriggerForm(), name: 'PR review', template: 'Review {{pull_request.title}}', box: 'alpha', events: 'pull_request, push' };
  it('validates and builds the request, with events only for GitHub', () => {
    expect(triggerSchema.safeParse(f).success).toBe(true);
    expect(triggerSchema.safeParse({ ...f, template: '' }).error?.issues[0]?.message).toBe('err_template');
    expect(triggerFormToInput(f).events).toEqual(['pull_request', 'push']);
    expect(triggerFormToInput({ ...f, scheme: 'generic' }).events).toEqual([]);
  });

  it('explains each refusal in words', () => {
    const d = (o: string, reason: string): Delivery => ({ id: 'd', trigger_id: 't', ts_ms: 0, outcome: o, reason, delivery_id: null, event: null, size: 0, run_id: null });
    expect(deliveryWhy(d('refused', 'bad_signature'))).toMatch(/signature did not match/);
    expect(deliveryWhy(d('refused', 'replayed'))).toMatch(/sent again/);
    expect(deliveryWhy(d('refused', 'expired'))).toMatch(/timestamp/);
    expect(deliveryWhy(d('refused', 'too_large'))).toMatch(/larger/);
    expect(deliveryWhy(d('accepted', ''))).toMatch(/Started a run/);
  });
});

describe('the box picker\'s profile choices', () => {
  it('turns a choice into a target and back', () => {
    expect(targetFromChoice('alpha')).toEqual({ box_name: 'alpha', profile: null });
    expect(targetFromChoice('profile:gpu')).toEqual({ box_name: null, profile: 'gpu' });
    expect(choiceFromTarget({ box_name: null, profile: 'gpu' })).toBe('profile:gpu');
    expect(choiceFromTarget({ box_name: 'alpha', profile: null })).toBe('alpha');
  });
  it('offers each box, then each profile once, sorted', () => {
    const boxes = [
      { spec: { name: 'b', labels: { profile: 'gpu' } } },
      { spec: { name: 'a', labels: { profile: 'dev' } } },
      { spec: { name: 'c', labels: { profile: 'gpu' } } },
      { spec: { name: 'd' } },
    ];
    expect(boxChoices(boxes)).toEqual(['b', 'a', 'c', 'd', 'profile:dev', 'profile:gpu']);
  });
});

describe('the engine a new schedule or trigger runs on', () => {
  it('is the one a supervisor registers, and on a demo server the demo agent', () => {
    expect(emptyScheduleForm('UTC').engine).toBe('claude-code');
    expect(emptyTriggerForm().engine).toBe('claude-code');
    expect(defaultEngine('live')).toBe('claude-code');
    expect(defaultEngine(undefined)).toBe('claude-code');
    expect(defaultEngine('simulated')).toBe('fake');
    expect(emptyScheduleForm('UTC', defaultEngine('simulated')).engine).toBe('fake');
    expect(emptyTriggerForm(defaultEngine('simulated')).engine).toBe('fake');
  });

  it('offers what the server can run, and keeps a stored engine it does not know so it is shown, not lost', () => {
    expect(engineChoices('live', 'claude-code')).toEqual(['claude-code']);
    expect(engineChoices('simulated', 'fake')).toEqual(['fake', 'claude-code']);
    expect(engineChoices('live', 'codex')).toEqual(['claude-code', 'codex']);
  });
});
