import { expect, test } from '@playwright/test';

import { startRealThisBox, type RealStack } from './real-stack';
import { bearer } from './support';

// X2, end to end: a box whose configuration says `provider = "fake"` is a box running the DEMO. The demo says so on every page,
// and it refuses the three things that would be real on the box: a shell, files and a browser. A person gets words, not a
// shell labelled as the box's terminal.
let s: RealStack;
test.beforeAll(async () => {
  s = await startRealThisBox({ port: 4183, config: 'provider = "fake"\n', noDaemon: true, seedBoxes: ['alpha'] });
});
test.afterAll(async () => {
  await s?.stop();
});

test('a demo on a box is marked as demo', async ({ request }) => {
  const i = (await (await request.get(`${s.origin}/v1/info`, { headers: bearer(s) })).json()) as { fleet: { demo: boolean } };
  expect(i.fleet.demo).toBe(true);
});

test('a demo on a box refuses a terminal and files, and says why (its browser is pinned by the unit tests)', async ({ request }) => {
  const name = 'alpha';
  // The session is made first; the refusal arrives as the error frame of its output stream, with no shell behind it.
  const term = await request.post(`${s.origin}/v1/boxes/${name}/terminal`, { headers: bearer(s), data: { cols: 80, rows: 24 } });
  expect(term.status()).toBe(200);
  const { session } = (await term.json()) as { session: string };
  // the output is a long response of frames: read the first ones and stop, rather than wait for the end of a stream
  const ctl = new AbortController();
  const out = await fetch(`${s.origin}/v1/terminal/${session}/output`, { headers: bearer(s), signal: ctl.signal });
  expect(out.status).toBe(200);
  const reader = out.body!.getReader();
  let frames = '';
  const stop = setTimeout(() => ctl.abort(), 10_000);
  try {
    while (!frames.includes('demo terminal')) {
      const { value, done } = await reader.read();
      if (done) break;
      frames += Buffer.from(value).toString('utf8');
    }
  } catch {
    // aborted: judged by what arrived
  } finally {
    clearTimeout(stop);
    ctl.abort();
  }
  expect(frames, 'a shell was opened on a box by the demo').toContain('demo terminal');
  expect(frames).toContain('"code":"unsupported"');
  const files = await request.get(`${s.origin}/v1/boxes/${name}/files/roots`, { headers: bearer(s) });
  expect(files.status(), 'the demo served a folder on a box').toBeGreaterThanOrEqual(400);
  expect(await files.text()).toContain('demo');
});
