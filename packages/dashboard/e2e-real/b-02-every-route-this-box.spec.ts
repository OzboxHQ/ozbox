import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS, sweepEveryRoute, type InfoLite } from './support';

// X3, tier B: a signed-in person on a REAL this-box server visits EVERY page of the dashboard at 390, 820, 1024 and 1440. No page
// is blank or loading forever, none shows made-up data or a demo banner, and the fleet pages say the fleet is not connected.
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;
const SERVER_INFO: InfoLite = { provider: 'thisbox', metrics: 'live', fleet: { mode: 'this_box', demo: false, connected: false } };

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4181, signIn: true });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: s.origin, code: s.code, stop: async () => undefined });
});
test.afterAll(async () => {
  await s?.stop();
});

for (const w of WIDTHS) {
  test(`every route on a real box at ${w}px`, async () => {
    test.setTimeout(300_000);
    // the server says what it is: follow it, so a box that is not a this-box fails the contract loudly
    const i = (await (await page.request.get(`${s.origin}/v1/info`)).json()) as InfoLite;
    expect(i.provider).toBe(SERVER_INFO.provider);
    expect(i.fleet.demo).toBe(false);
    await sweepEveryRoute(page, s.origin, s.box, w, i);
  });
}
