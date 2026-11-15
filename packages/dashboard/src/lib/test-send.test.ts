import { describe, expect, it } from 'vitest';

import type { TestRun } from '../api/alert-types';
import { allSent, runTestSend } from './test-send';

const run = (state: 'running' | 'done', items: TestRun['items']): TestRun => ({ id: 'abc', state, items });

function fakeClient(answers: TestRun[]) {
  const asked: string[] = [];
  return {
    asked,
    client: {
      startTest: async (channel: string) => {
        asked.push(`start ${channel}`);
        return answers[0] as TestRun;
      },
      testRun: async (id: string) => {
        asked.push(`poll ${id}`);
        return (answers[Math.min(asked.length - 1, answers.length - 1)] ?? answers[0]) as TestRun;
      },
    },
  };
}

describe('following a test send', () => {
  it('reports every channel as pending, then each answer as it arrives, then stops', async () => {
    const { client, asked } = fakeClient([
      run('running', [{ channel: 'sms', status: 'pending' }, { channel: 'push', status: 'pending' }]),
      run('running', [{ channel: 'sms', status: 'sent', detail: 'sent' }, { channel: 'push', status: 'pending' }]),
      run('done', [{ channel: 'sms', status: 'sent', detail: 'sent' }, { channel: 'push', status: 'failed', detail: 'no device is registered' }]),
    ]);
    const seen: string[][] = [];
    const r = await runTestSend(client, 'sms', (x) => seen.push(x.items.map((i) => i.status)), { sleep: async () => {} });
    expect(seen).toEqual([['pending', 'pending'], ['sent', 'pending'], ['sent', 'failed']]);
    expect(r.timedOut).toBe(false);
    expect(allSent(r.run)).toBe(false);
    expect(asked).toEqual(['start sms', 'poll abc', 'poll abc']);
  });

  it('does not repeat an update when nothing changed', async () => {
    const same = run('running', [{ channel: 'slack', status: 'pending' }]);
    const { client } = fakeClient([same, same, run('done', [{ channel: 'slack', status: 'sent', detail: 'sent' }])]);
    let updates = 0;
    const r = await runTestSend(client, 'slack', () => updates++, { sleep: async () => {} });
    expect(updates).toBe(2);
    expect(allSent(r.run)).toBe(true);
  });

  it('stops asking after the limit and says so, leaving the rest pending', async () => {
    const waiting = run('running', [{ channel: 'email', status: 'pending' }]);
    const { client } = fakeClient([waiting]);
    let clock = 0;
    const r = await runTestSend(client, 'email', () => {}, { sleep: async () => { clock += 10_000; }, now: () => clock, maxMs: 30_000 });
    expect(r.timedOut).toBe(true);
    expect(r.run.items[0]?.status).toBe('pending');
  });

  it('a run with nothing in it is not a success', () => {
    expect(allSent(run('done', []))).toBe(false);
  });
});
