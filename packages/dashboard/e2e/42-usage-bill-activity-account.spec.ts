import { expect, test, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, url } from './fixtures';

// G7 R6 on the demo provider (tier A): Usage and its suggestions say they are demo figures, name a box they could not read
// instead of saying nothing, and fail with a way to try again; Activity says how long it remembers and who did each thing;
// Account says it needs a sign-in on a dashboard opened with an access link. A `page.route` appears only for an error state,
// and always beside an assertion on what the real server answers.
const token = () => new URL(url()).hash.replace('#token=', '');
const origin = () => new URL(url()).origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

interface Reads {
  usage: { source: string; unreachable: unknown[] };
  suggestions: { source: string; unreachable: unknown[]; items: unknown[] };
}
async function reads(page: Page): Promise<Reads> {
  const usage = (await (await page.request.get(`${origin()}/v1/usage?range=1m`, { headers: headers() })).json()) as Reads['usage'];
  const suggestions = (await (await page.request.get(`${origin()}/v1/suggestions`, { headers: headers() })).json()) as Reads['suggestions'];
  return { usage, suggestions };
}

for (const w of WIDTHS) {
  test(`usage at ${w}px: demo figures and suggestions are marked, and what the server said about unreachable boxes is on screen`, async ({ page }) => {
    const r = await reads(page);
    expect(r.usage.source).toBe('simulated');
    expect(r.suggestions.source).toBe('simulated');
    // the demo provider reads every box it has, so nothing is unreachable
    expect(r.usage.unreachable).toEqual([]);
    expect(r.suggestions.unreachable).toEqual([]);

    await page.setViewportSize({ width: w, height: 900 });
    await open(page, '/usage');
    await expect(page.getByRole('heading', { name: 'Usage', level: 1 })).toBeVisible();
    await expect(page.getByTestId('demo-banner')).toBeVisible();
    await expect(page.getByTestId('usage-source-note')).toContainText('Demo usage');
    await expect(page.getByTestId('suggestions-source-note')).toContainText('Demo suggestions');
    await expect(page.getByTestId('unreachable-note')).toHaveCount(0);
    await expect(page.getByTestId('fleet-not-connected')).toHaveCount(0);
    // the cards the page shows are the cards the server sent
    const card = page.getByTestId('suggestions');
    await expect(card).toBeVisible();
    await expect(card.getByRole('button', { name: /^Review (resize|pause)/ })).toHaveCount(r.suggestions.items.length);
    if (r.suggestions.items.length === 0) await expect(page.getByTestId('suggestions-none')).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (w < 1024) await expectTouchTargets(page, card);
  });
}

test('usage: a box the server could not read is named with the reason, never "No running boxes"', async ({ page }) => {
  const r = await reads(page);
  expect(r.usage.unreachable).toEqual([]);
  // the injected answer is the shape the server sends when no running box answered
  await page.route('**/v1/usage?*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        source: 'live',
        range: '1m',
        step_ms: 60000,
        to_ms: Date.now(),
        boxes: [],
        unreachable: [{ name: 'bravo', reason: 'did not answer within 10 seconds' }],
        by_label: { key: 'project', groups: [] },
        by_run: [],
        fleet: { cpu_mean: null, mem_mean: null, cost_month_est_usd: null },
      }),
    }),
  );
  for (const w of WIDTHS) {
    await page.setViewportSize({ width: w, height: 900 });
    await open(page, '/usage');
    const note = page.getByTestId('unreachable-note');
    await expect(note).toContainText('bravo');
    await expect(note).toContainText('did not answer within 10 seconds');
    await expect(page.getByText('No usage could be read')).toBeVisible();
    await expect(page.getByText('No running boxes')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  }
});

test('usage: a failed read of the suggestions says so and Try again brings the real answer back', async ({ page }) => {
  const r = await reads(page);
  await page.setViewportSize({ width: 390, height: 900 });
  await page.route('**/v1/suggestions', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'injected failure' }) }));
  await open(page, '/usage');
  const card = page.getByTestId('suggestions');
  await expect(card.getByTestId('load-error')).toContainText('injected failure');
  await page.unroute('**/v1/suggestions');
  await card.getByRole('button', { name: 'Try again' }).click();
  await expect(card.getByTestId('load-error')).toHaveCount(0);
  await expect(card.getByRole('button', { name: /^Review (resize|pause)/ })).toHaveCount(r.suggestions.items.length);
});

for (const w of WIDTHS) {
  test(`activity at ${w}px: says how long it remembers and who did each thing`, async ({ page }) => {
    // a real change by this dashboard: a plan is a recorded act
    const plan = await page.request.post(`${origin()}/v1/plans`, { headers: headers(), data: { operation: { op: 'pause', name: 'charlie' } } });
    expect(plan.status()).toBe(200);
    const feed = (await (await page.request.get(`${origin()}/v1/activity`, { headers: headers() })).json()) as { since_start: boolean; entries: { actor: string; action: string }[] };
    expect(feed.since_start).toBe(true);
    expect(feed.entries.length).toBeGreaterThan(0);
    // on a dashboard opened with an access link, nobody is signed in: it says access link, not a person and not "this computer"
    // (hooks and timers earlier in this run are "automation": a person is never invented for them)
    expect(feed.entries.filter((e) => e.action === 'plan pause').every((e) => e.actor === 'access link')).toBe(true);
    expect(feed.entries.some((e) => e.actor === 'access link')).toBe(true);
    expect(feed.entries.every((e) => e.actor === 'access link' || e.actor === 'automation')).toBe(true);

    await page.setViewportSize({ width: w, height: 900 });
    await open(page, '/activity');
    await expect(page.getByTestId('activity-since-start')).toContainText('since it started');
    await expect(page.getByTestId('activity-since-start')).toContainText('A restart clears this list');
    await expect(page.getByText('access link').locator('visible=true').first()).toBeVisible();
    await expect(page.getByText('this computer')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });
}

test('activity: a failed read says so, and Try again brings the real list back', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await page.route('**/v1/activity', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'injected failure' }) }));
  await open(page, '/activity');
  await expect(page.getByTestId('load-error')).toContainText('Activity could not be loaded');
  await expect(page.getByTestId('load-error')).toContainText('injected failure');
  await expect(page.getByText('Nothing yet')).toHaveCount(0);
  await page.unroute('**/v1/activity');
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByTestId('load-error')).toHaveCount(0);
  await expect(page.getByTestId('activity-since-start')).toBeVisible();
  await expect(page.getByText('access link').locator('visible=true').first()).toBeVisible();
});

for (const w of WIDTHS) {
  test(`account at ${w}px: with an access link there is no account, and the page says so`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: 900 });
    await open(page, '/account');
    await expect(page.getByRole('heading', { name: 'Account', level: 1 })).toBeVisible();
    await expect(page.getByTestId('account-needs-signin')).toContainText('Account needs a sign-in');
    await expect(page.getByTestId('account-needs-signin')).toContainText('access link');
    await expect(page.locator('#main').getByText(/undefined|NaN/)).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });
}
