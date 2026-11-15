import { describe, expect, it } from 'vitest';

import type { TestRun } from '../api/alert-types';
import { shownFor, testSendStore } from './test-send-store';

const run = (id: string): TestRun => ({ id, state: 'running', items: [{ channel: 'sms', status: 'pending' }] });

describe('the test send a card shows', () => {
  it('keeps one per channel, tells subscribers and forgets on close', () => {
    let calls = 0;
    const off = testSendStore.subscribe(() => calls++);
    testSendStore.set('sms', run('a'));
    testSendStore.set('slack', run('b'));
    expect(shownFor(testSendStore.get(), { channel: 'sms' })?.shown.run.id).toBe('a');
    expect(shownFor(testSendStore.get(), { channel: 'email' })).toBeNull();
    testSendStore.clear('sms');
    expect(shownFor(testSendStore.get(), { channel: 'sms' })).toBeNull();
    expect(shownFor(testSendStore.get(), { channel: 'slack' })?.shown.run.id).toBe('b');
    expect(calls).toBe(3);
    off();
    testSendStore.set('sms', run('c'));
    expect(calls).toBe(3);
    testSendStore.clear('sms');
    testSendStore.clear('slack');
  });

  it('shows the latest webhook test on the webhooks card', () => {
    testSendStore.set('webhook:one', run('1'));
    testSendStore.set('webhook:two', run('2'));
    const hit = shownFor(testSendStore.get(), { prefix: 'webhook:' });
    expect(hit?.key).toBe('webhook:two');
    testSendStore.clear('webhook:one');
    testSendStore.clear('webhook:two');
  });
});
