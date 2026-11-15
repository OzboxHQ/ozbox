import { describe, expect, it } from 'vitest';

import type { ApprovalRequest, Task } from '../api/tasks';
import { anyFilter, bulkCount, canBulk, columnOf, filtersFromSearch, fmtCents, fmtElapsed, groupByColumn, isCapPause, minutesLeft, needsKey, NO_FILTERS, offeredActions, parseCount, parseDollars, safeHref, sinceFor, splitList } from './tasks';

function task(over: Partial<Task>): Task {
  return {
    id: 't1', state: 'queued', engine: 'fake', box: 'alpha', repo: null, branch: null, skill: null, prompt: 'x', person: 'ada',
    origin: { kind: 'manual' }, created_ms: 0, started_ms: null, finished_ms: null, elapsed_s: 0, spend_cents: 0, tokens: 0,
    caps: { max_runtime_s: null, max_spend_cents: null, max_tokens: null }, deliver_to: [], needs: null, queue_reason: null,
    wip_branch: null, links: [], summary: null, error: null, retry_of: null, cancelling: false, ...over,
  };
}

describe('the board', () => {
  it('has five columns and puts failed and cancelled runs in Done', () => {
    expect(columnOf('failed')).toBe('done');
    expect(columnOf('cancelled')).toBe('done');
    expect(columnOf('needs_you')).toBe('needs_you');
    const g = groupByColumn([task({ id: 'a', state: 'running' }), task({ id: 'b', state: 'failed' }), task({ id: 'c', state: 'done' })]);
    expect(g.running.map((t) => t.id)).toEqual(['a']);
    expect(g.done.map((t) => t.id)).toEqual(['b', 'c']);
    expect(g.queued).toEqual([]);
  });

  it('formats money and time without inventing precision', () => {
    expect(fmtCents(5)).toBe('$0.05');
    expect(fmtCents(123456)).toBe('$1,234.56');
    expect(fmtElapsed(45)).toBe('45s');
    expect(fmtElapsed(125)).toBe('2m 05s');
    expect(fmtElapsed(3725)).toBe('1h 02m');
  });

  it('reads dollars and counts, and refuses anything else', () => {
    expect(parseDollars('5')).toBe(500);
    expect(parseDollars('$5.5')).toBe(550);
    expect(parseDollars('5.05')).toBe(505);
    for (const bad of ['', 'lots', '-1', '1.234', '1e3']) expect(parseDollars(bad)).toBeNull();
    expect(parseCount('120')).toBe(120);
    expect(parseCount('12.5')).toBeNull();
  });
});

describe('bulk actions', () => {
  const tasks = [task({ id: 'q', state: 'queued' }), task({ id: 'r', state: 'running', cancelling: true }), task({ id: 'f', state: 'failed' }), task({ id: 'd', state: 'done' })];
  it('applies only to the states each makes sense for', () => {
    expect(canBulk('cancel', tasks[0]!)).toBe(true);
    expect(canBulk('cancel', tasks[1]!)).toBe(false);
    expect(canBulk('retry', tasks[2]!)).toBe(true);
    expect(canBulk('retry', tasks[3]!)).toBe(false);
    expect(canBulk('review', tasks[3]!)).toBe(true);
    expect(bulkCount('review', tasks, new Set(['q', 'f', 'd']))).toBe(2);
  });
});

describe('what needs a person', () => {
  it('names each reason and tells a cap pause from an approval', () => {
    expect(needsKey({ kind: 'spend_cap' })).toBe('tasks.needs_spend');
    expect(needsKey({ kind: 'approval', approval_id: 'a1' })).toBe('tasks.needs_approval');
    expect(isCapPause(task({ state: 'needs_you', needs: { kind: 'time_cap' } }))).toBe(true);
    expect(isCapPause(task({ state: 'needs_you', needs: { kind: 'approval', approval_id: 'a1' } }))).toBe(false);
    expect(isCapPause(task({ state: 'running' }))).toBe(false);
  });
  it('an open request never shows zero minutes left', () => {
    expect(minutesLeft({ expires_in_s: 10 } as ApprovalRequest)).toBe(1);
    expect(minutesLeft({ expires_in_s: 3600 } as ApprovalRequest)).toBe(60);
  });
});

describe('filters and lists', () => {
  it('knows when a filter is on and what "since" means', () => {
    expect(anyFilter(NO_FILTERS)).toBe(false);
    expect(anyFilter({ ...NO_FILTERS, box: 'alpha' })).toBe(true);
    expect(sinceFor('any', 1000)).toBeUndefined();
    expect(sinceFor('7d', 8 * 86_400_000)).toBe(86_400_000);
    expect(sinceFor('today', 86_400_000 + 5)).toBe(86_400_000);
  });
  it('reads the box a link filters on, and nothing else', () => {
    expect(filtersFromSearch('?box=alpha')).toEqual({ ...NO_FILTERS, box: 'alpha' });
    expect(filtersFromSearch('?state=failed&engine=x')).toEqual(NO_FILTERS);
    expect(filtersFromSearch('')).toEqual(NO_FILTERS);
    expect(filtersFromSearch(`?box=${'x'.repeat(65)}`)).toEqual(NO_FILTERS);
  });
  it('splits a typed list into distinct entries', () => {
    expect(splitList('main, staging\nmain,,release/*')).toEqual(['main', 'staging', 'release/*']);
  });
});

describe('links from an agent', () => {
  it('only web addresses become links', () => {
    expect(safeHref('https://example.com/pull/1')).toBe('https://example.com/pull/1');
    for (const bad of ['javascript:alert(1)', 'file:///etc/passwd', 'data:text/html,x', 'not a url', '//evil.example']) expect(safeHref(bad)).toBeNull();
  });
});

describe('what a task offers a person', () => {
  const at = (state: Task['state'], extra: Partial<Task> = {}) => ({ state, cancelling: false, needs: null, ...extra }) as Pick<Task, 'state' | 'cancelling' | 'needs'>;
  it('offers nothing to a role that cannot start runs, in any state', () => {
    for (const s of ['queued', 'running', 'needs_you', 'review', 'done', 'failed', 'cancelled'] as const) expect(offeredActions(at(s), false)).toEqual([]);
  });
  it('offers cancel while it can still stop, and not while it is stopping', () => {
    expect(offeredActions(at('running'), true)).toEqual(['cancel']);
    expect(offeredActions(at('running', { cancelling: true }), true)).toEqual([]);
  });
  it('offers retry and review on a task that ended badly, accept on one in review, resume on one paused at a limit', () => {
    expect(offeredActions(at('failed'), true)).toEqual(['retry', 'review']);
    expect(offeredActions(at('review'), true)).toEqual(['accept']);
    expect(offeredActions(at('done'), true)).toEqual(['review']);
    expect(offeredActions(at('needs_you', { needs: { kind: 'spend_cap' } as Task['needs'] }), true)).toEqual(['cancel', 'resume']);
    expect(offeredActions(at('needs_you', { needs: { kind: 'approval' } as Task['needs'] }), true)).toEqual(['cancel']);
  });
});
