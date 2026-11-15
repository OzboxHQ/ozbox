import type { TestRun } from '../api/alert-types';
import type { ApiClient } from '../api/client';

export interface TestSendOptions {
  /** How often to ask how it is going. */
  everyMs?: number;
  /** Give up asking after this long; the server itself stops waiting on a channel well before. */
  maxMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  person?: string;
}

export interface TestSendResult {
  run: TestRun;
  /** True when this page stopped asking before every channel had answered. */
  timedOut: boolean;
}

type Api = Pick<ApiClient, 'startTest' | 'testRun'>;

const wait = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));

/**
 * Start a test send and follow it: `onUpdate` is called with the first answer (every channel pending) and again each
 * time something changed, until the server says the run is done or `maxMs` has passed.
 */
export async function runTestSend(client: Api, channel: string, onUpdate: (run: TestRun) => void, opts: TestSendOptions = {}): Promise<TestSendResult> {
  const { everyMs = 500, maxMs = 40_000, sleep = wait, now = Date.now } = opts;
  const started = now();
  let run = await client.startTest(channel, undefined, opts.person);
  onUpdate(run);
  while (run.state === 'running') {
    if (now() - started >= maxMs) return { run, timedOut: true };
    await sleep(everyMs);
    const next = await client.testRun(run.id);
    if (JSON.stringify(next) !== JSON.stringify(run)) onUpdate(next);
    run = next;
  }
  return { run, timedOut: false };
}

/** Whether every channel of a finished run was sent. */
export const allSent = (run: TestRun): boolean => run.items.length > 0 && run.items.every((i) => i.status === 'sent');
