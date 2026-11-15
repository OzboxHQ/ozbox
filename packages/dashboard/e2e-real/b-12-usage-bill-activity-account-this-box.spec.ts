import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { bearer, WIDTHS } from './support';

// G7 R6, tier B: Usage, Bill, Activity and Account of a REAL this-box dashboard (a real ozboxd, a real `ozbox serve`). One
// server is opened with an access link (no one signed in) and one behind a passkey sign-in. The pages say what is real and what
// is not: the fleet is not connected (no bill, no cost), a box the server could not read is named, Activity names the person
// (or the access link), and Account needs a sign-in. Nothing is mocked.
test.describe.configure({ mode: 'serial' });

let tok: RealStack;
let signed: RealStack;
let page: Page;
let owner: Page;
const live = process.platform === 'linux';

test.beforeAll(async ({ browser }) => {
  tok = await startRealThisBox({ port: 4202 });
  signed = await startRealThisBox({ port: 4201, signIn: true, person: 'alice' });
  page = await (await browser.newContext()).newPage();
  owner = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(owner);
  await owner.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(owner, { origin: signed.origin, code: signed.code, stop: async () => undefined }, 'alice');
});
test.afterAll(async () => {
  await tok?.stop();
  await signed?.stop();
});

const openTok = async (path: string, w: number) => {
  await page.setViewportSize({ width: w, height: 900 });
  await page.goto(`${tok.origin}${path}#token=${tok.token}`);
};

interface Reads {
  usage: { source: string; unreachable: { name: string; reason: string }[] };
  suggestions: { source: string; unreachable: { name: string; reason: string }[]; items: unknown[] };
}
const readsOf = async (): Promise<Reads> => ({
  usage: (await (await page.request.get(`${tok.origin}/v1/usage?range=1m`, { headers: bearer(tok) })).json()) as Reads['usage'],
  suggestions: (await (await page.request.get(`${tok.origin}/v1/suggestions`, { headers: bearer(tok) })).json()) as Reads['suggestions'],
});

for (const w of WIDTHS) {
  test(`Usage on a box says the fleet is not connected, names a box it could not read, and shows no demo marks at ${w}px`, async () => {
    const r = await readsOf();
    expect(r.usage.source).toBe('live');
    expect(r.suggestions.source).toBe('live');
    await openTok('/usage', w);
    await expect(page.getByRole('heading', { name: 'Usage', level: 1 })).toBeVisible();
    await expect(page.getByTestId('fleet-not-connected')).toBeVisible();
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expect(page.getByTestId('usage-source-note')).toHaveCount(0);
    await expect(page.getByTestId('suggestions-source-note')).toHaveCount(0);
    // what a box costs is a fleet figure: a dash with the reason, never a number and never "enter a price"
    await expect(page.getByText('Estimated cost a month').locator('xpath=..')).toContainText('Fleet not connected', { timeout: 15_000 });
    await expect(page.getByTestId('cost-error')).toHaveCount(0);
    if (live) {
      expect(r.usage.unreachable).toEqual([]);
      await expect(page.getByTestId('unreachable-note')).toHaveCount(0);
    } else {
      // no /proc here: the server says which box and why, and the page shows it instead of "No running boxes"
      expect(r.usage.unreachable.map((u) => u.name)).toEqual([tok.box]);
      // a week of history that is empty is "nothing to judge yet", not a box that failed to answer
      expect(r.suggestions.items).toEqual([]);
      await expect(page.getByTestId('unreachable-note')).toContainText(tok.box);
      await expect(page.getByTestId('unreachable-note')).toContainText(r.usage.unreachable[0]?.reason ?? 'unreachable');
      await expect(page.getByTestId('suggestions-none')).toBeVisible();
      await expect(page.getByText('No running boxes')).toHaveCount(0);
    }
    await expectNoSidewaysScroll(page);
  });

  test(`Bill on a box says the fleet is not connected and asks the provider for nothing at ${w}px`, async () => {
    const asked: string[] = [];
    page.on('request', (q) => {
      if (q.url().includes('/v1/cost')) asked.push(q.url());
    });
    await openTok('/costs/bill', w);
    await expect(page.getByRole('heading', { name: 'Bill', level: 1 })).toBeVisible();
    await expect(page.getByTestId('bill-not-connected')).toContainText('Bill: fleet not connected');
    await expect(page.getByTestId('fleet-not-connected')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Read the bill now' })).toHaveCount(0);
    await expect(page.getByTestId('orphans-card')).toHaveCount(0);
    await expect(page.getByRole('alert')).toHaveCount(0);
    await page.waitForTimeout(1500);
    expect(asked, 'a box asked for a bill or a cost it cannot have').toEqual([]);
    page.removeAllListeners('request');
    // and the server agrees: it answers a typed "fleet not connected"
    const r = await page.request.get(`${tok.origin}/v1/cost/bill`, { headers: bearer(tok) });
    expect([r.status(), ((await r.json()) as { code: string }).code]).toEqual([409, 'fleet_not_connected']);
    await expectNoSidewaysScroll(page);
  });

  test(`Account opened with an access link says it needs a sign-in at ${w}px`, async () => {
    await openTok('/account', w);
    await expect(page.getByTestId('account-needs-signin')).toContainText('Account needs a sign-in');
    await expectNoSidewaysScroll(page);
  });
}

test('Activity behind an access link names the access link, and says it is since the server started', async () => {
  const cur = await page.request.get(`${tok.origin}/v1/settings`, { headers: bearer(tok) });
  const { settings } = (await cur.json()) as { settings: unknown };
  const put = await page.request.put(`${tok.origin}/v1/settings`, { headers: bearer(tok), data: settings });
  expect(put.status(), await put.text()).toBe(200);
  const feed = (await (await page.request.get(`${tok.origin}/v1/activity`, { headers: bearer(tok) })).json()) as { since_start: boolean; entries: { actor: string; action: string }[] };
  expect(feed.since_start).toBe(true);
  expect(feed.entries.find((e) => e.action === 'update settings')?.actor).toBe('access link');
  for (const w of WIDTHS) {
    await openTok('/activity', w);
    await expect(page.getByTestId('activity-since-start')).toContainText('since it started');
    await expect(page.getByText('access link').locator('visible=true').first()).toBeVisible();
    await expect(page.getByText('this computer')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  }
});

test('Activity behind a sign-in names the signed-in person, and Account works', async () => {
  const done = await owner.evaluate(async () => {
    const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
    const h = { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf };
    const cur = (await (await fetch('/v1/settings')).json()) as { settings: unknown };
    const res = await fetch('/v1/settings', { method: 'PUT', headers: h, body: JSON.stringify(cur.settings) });
    return res.status;
  });
  expect(done).toBe(200);
  const feed = await owner.evaluate(async () => (await (await fetch('/v1/activity')).json()) as { entries: { actor: string; action: string }[] });
  expect(feed.entries.find((e) => e.action === 'update settings')?.actor).toBe('alice');
  for (const w of WIDTHS) {
    await owner.setViewportSize({ width: w, height: 900 });
    await owner.goto(`${signed.origin}/activity`);
    const list = w >= 768 ? owner.getByRole('table', { name: 'Activity' }) : owner.getByRole('list', { name: 'Activity' });
    await expect(list).toContainText('alice');
    await expect(owner.getByText('this computer')).toHaveCount(0);
    await expect(owner.getByText('access link')).toHaveCount(0);
    await expectNoSidewaysScroll(owner);
    await owner.goto(`${signed.origin}/account`);
    await expect(owner.getByTestId('my-role')).toHaveText('Your role: Owner');
    await expect(owner.getByTestId('account-needs-signin')).toHaveCount(0);
    await expectNoSidewaysScroll(owner);
  }
});
