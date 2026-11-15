import { expect, test } from '@playwright/test';

import { sweepEveryRoute, WIDTHS, type InfoLite } from './support';

// Tier C: a server somebody runs for real: the laptop's dashboard on the sandbox account (C1), or `main`'s dashboard through
// its tunnel (C2). By hand, or from a gated workflow: it never runs in the ordinary suite.
//   OZBOX_E2E_REAL=1  OZBOX_E2E_URL=<access link, or the tunnel address>  [OZBOX_E2E_STORAGE_STATE=<a signed-in session>]
//   OZBOX_E2E_BOX=<the box to open box pages for>
// Reads only: the writes of the release gate (a snapshot, a schedule, a file under /work/tmp/g7-*) are listed in the plan's
// run log and done by hand until a throwaway box exists to point a write spec at.
const URL_ = process.env['OZBOX_E2E_URL'];
test.skip(process.env['OZBOX_E2E_REAL'] !== '1' || !URL_, 'tier C needs a real server: set OZBOX_E2E_REAL=1 and OZBOX_E2E_URL');
if (process.env['OZBOX_E2E_STORAGE_STATE']) test.use({ storageState: process.env['OZBOX_E2E_STORAGE_STATE'] });

const u = new URL(URL_ ?? 'http://127.0.0.1');
const token = u.hash.replace('#token=', '');

for (const w of WIDTHS) {
  test(`every route on a real server at ${w}px`, async ({ page }) => {
    test.setTimeout(420_000);
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await page.request.get(`${u.origin}/v1/info`, { headers });
    expect(res.status(), 'the server did not answer /v1/info (not signed in?)').toBe(200);
    const i = (await res.json()) as InfoLite;
    // a real server is never the demo, and a box says "this box"
    expect(i.fleet.demo, 'this server is the demo, not a real one').toBe(false);
    expect(i.metrics).toBe('live');
    const box = process.env['OZBOX_E2E_BOX'] ?? ((await (await page.request.get(`${u.origin}/v1/boxes`, { headers })).json()) as { spec: { name: string } }[])[0]?.spec.name ?? 'main-box';
    if (token) await page.goto(`${u.origin}/${u.hash}`);
    await sweepEveryRoute(page, u.origin, box, w, i);
  });
}
