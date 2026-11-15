import { describe, expect, it } from 'vitest';

import type { Grant, PermSettings, VerifyReport } from '../api/perm';
import { EMPTY_GRANT, actionList, hostList, hostProblem, withHosts, cleanRule, grantBody, grantProblem, minutesLeft, newRule, problems, ruleProblem, splitGrants, withMode, withRule, withoutRule } from './perm';

const grant = (over: Partial<Grant>): Grant => ({
  id: 'g1',
  granted_by: 'owner',
  scope: 'box',
  scope_id: 'main',
  actions: ['*'],
  reason: 'ship the fix',
  created_ms: 0,
  expires_ms: 30 * 60_000,
  factor: 'step_up',
  factor_is_real: true,
  allow_unattended: false,
  max_uses: null,
  uses: 0,
  revoked_ms: null,
  revoked_by: null,
  state: 'active',
  ...over,
});

const ok: typeof EMPTY_GRANT = { ...EMPTY_GRANT, scopeId: 'main', reason: 'ship the fix', minutes: '30', confirm: 'main' };

describe('grant form', () => {
  it('accepts a complete form and asks nothing more behind a sign-in', () => {
    expect(grantProblem(ok, 240, false)).toBeNull();
    expect(grantProblem({ ...ok, confirm: '' }, 240, true)).toBeNull();
  });
  it('names the first thing wrong', () => {
    expect(grantProblem({ ...ok, scopeId: '' }, 240, false)).toBe('scope_id');
    expect(grantProblem({ ...ok, reason: 'fix' }, 240, false)).toBe('reason');
    expect(grantProblem({ ...ok, minutes: '241' }, 240, false)).toBe('minutes');
    expect(grantProblem({ ...ok, minutes: '0' }, 240, false)).toBe('minutes');
    expect(grantProblem({ ...ok, minutes: '1.5' }, 240, false)).toBe('minutes');
    expect(grantProblem({ ...ok, actions: ' ' }, 240, false)).toBe('actions');
    expect(grantProblem({ ...ok, confirm: 'mian' }, 240, false)).toBe('confirm');
  });
  it('sends the typed confirmation only when signed out', () => {
    expect(grantBody(ok, false).confirm).toBe('main');
    expect('confirm' in grantBody(ok, true)).toBe(false);
    expect(grantBody({ ...ok, actions: 'git.*, command.run' }, true).actions).toEqual(['git.*', 'command.run']);
  });
  it('reads a list of actions and drops what is not one', () => {
    expect(actionList('git.* command.run; rm -rf')).toEqual(['git.*', 'rm', '-rf']);
    expect(actionList('')).toEqual([]);
  });
});

describe('grants', () => {
  it('counts minutes up so a grant never shows 0 while it is still live', () => {
    expect(minutesLeft({ expires_ms: 61_000 }, 0)).toBe(2);
    expect(minutesLeft({ expires_ms: 1_000 }, 0)).toBe(1);
    expect(minutesLeft({ expires_ms: 1_000 }, 5_000)).toBe(0);
  });
  it('splits active from past', () => {
    const s = splitGrants([grant({}), grant({ id: 'g2', state: 'revoked' }), grant({ id: 'g3', state: 'expired' })]);
    expect(s.active.map((g) => g.id)).toEqual(['g1']);
    expect(s.past.map((g) => g.id)).toEqual(['g2', 'g3']);
  });
});

describe('rules', () => {
  const base: PermSettings = { default_mode: 'ask', modes: [], rules: [], browser_hosts: [] };
  it('needs an action, and an id for a narrow scope', () => {
    expect(ruleProblem(newRule())).toBe('action');
    expect(ruleProblem({ ...newRule(), action: 'git.push', scope: 'box' })).toBe('scope_id');
    expect(ruleProblem({ ...newRule(), action: 'git.push', scope: 'box', scope_id: 'main' })).toBeNull();
    expect(ruleProblem({ ...newRule(), action: 'git.push' })).toBeNull();
  });
  it('turns blanks into nothing', () => {
    const r = cleanRule({ ...newRule(), action: ' git.push ', command: '  ', path: '', note: ' hi ' });
    expect(r).toMatchObject({ action: 'git.push', command: null, path: null, note: 'hi' });
  });
  it('adds and removes without changing the rest', () => {
    const added = withRule(withMode(base, 'plan_only'), { ...newRule(), id: 'r1', action: 'git.*' });
    expect(added.default_mode).toBe('plan_only');
    expect(added.rules).toHaveLength(1);
    expect(withoutRule(added, 'r1').rules).toHaveLength(0);
    expect(base.rules).toHaveLength(0);
  });
});

describe('verification report', () => {
  const clean: VerifyReport = { ok: true, entries: 3, checkpoints: 1, head_seq: 3, head_hash: 'abc', altered: [], deleted: [], out_of_order: [], bad_seals: [], truncated: null, unreadable_lines: [], unsealed_tail: 0, seals_checked: true };
  it('has nothing to say about an intact chain', () => {
    expect(problems(clean)).toEqual([]);
  });
  it('lists every kind of trouble it was given', () => {
    const bad: VerifyReport = { ...clean, ok: false, altered: [4], deleted: [{ after_seq: 5, before_seq: 7 }], out_of_order: [6], bad_seals: [50], truncated: { sealed_seq: 60, last_seq: 47 }, unreadable_lines: [3] };
    expect(problems(bad).map(([k]) => k)).toEqual(['altered', 'deleted', 'order', 'seals', 'truncated', 'unreadable']);
  });
});

const base0: PermSettings = { default_mode: 'ask', modes: [], rules: [], browser_hosts: [] };

describe('browser hosts', () => {
  it('reads names separated any way and drops repeats', () => {
    expect(hostList('Example.com, *.docs.example.org\nexample.com  ')).toEqual(['example.com', '*.docs.example.org']);
    expect(hostList('')).toEqual([]);
  });
  it('accepts hosts and wildcard hosts, and nothing else', () => {
    expect(hostProblem(['example.com', '*.docs.example.org', 'a-b.example.co.uk'])).toBe(false);
    for (const bad of ['localhost', 'http://example.com', 'example.com/x', '*example.com', 'ex ample.com', '-a.com', 'a..com']) expect(hostProblem([bad])).toBe(true);
    expect(hostProblem(Array.from({ length: 51 }, (_, i) => `h${i}.example.com`))).toBe(true);
  });
  it('keeps the rest of the settings', () => {
    expect(withHosts({ ...base0, default_mode: 'plan_only' }, ['example.com'])).toEqual({ default_mode: 'plan_only', modes: [], rules: [], browser_hosts: ['example.com'] });
  });
});
