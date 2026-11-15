import { expect, test } from '@playwright/test';

import { applyPlan } from './apply';
import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// G7 R3, tier A (the demo provider): Files, Tools and the Terminal say, in words, that their data is the demo's. The terminal
// names its target before and while it is connected. Failures on Files and Tools are said, not swallowed into an empty page.
// The four tests that use `page.route` inject a failure the demo server cannot produce on demand, and they check only the error
// WORDING and that nothing is swallowed. The real-server half of the same states is asserted below without any mock: the API's
// own `source` fields, a real refusal for a box that does not exist, and (in `e2e-real/b-07`) a real daemon.
const BOX = 'r3-demo';
const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

test.beforeAll(async ({ request }) => {
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers: headers(),
    data: { operation: { op: 'create', spec: { name: BOX, size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} } } },
  });
  const body = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers(), { plan_id: body.plan_id })).ok()).toBe(true);
});

test('the real server says where Files, Tools and a terminal come from, and refuses a box that is not there in words', async ({ request }) => {
  const get = (path: string) => request.get(`${origin()}${path}`, { headers: headers() });
  expect(((await (await get(`/v1/boxes/${BOX}/files/roots`)).json()) as { source: string }).source).toBe('simulated');
  expect(((await (await get(`/v1/boxes/${BOX}/tools`)).json()) as { source: string }).source).toBe('simulated');
  const term = await request.post(`${origin()}/v1/boxes/${BOX}/terminal`, { headers: headers(), data: { cols: 80, rows: 24 } });
  const body = (await term.json()) as { session: string; target: unknown };
  expect(body.target).toEqual({ box: BOX, source: 'simulated', runs_as: 'demo' });
  await request.delete(`${origin()}/v1/terminal/${body.session}`, { headers: headers() });
  for (const p of ['files', 'tools']) {
    const r = await get(`/v1/boxes/ghost-box/${p}${p === 'files' ? '/roots' : ''}`);
    expect(r.status()).toBeGreaterThanOrEqual(400);
    expect(String(((await r.json()) as { error?: string }).error ?? '').length).toBeGreaterThan(5);
  }
});

for (const width of WIDTHS) {
  test(`a box that is not there is said in words by Files and Tools at ${width}px (real refusal, no mock)`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const p of ['files', 'tools']) {
      await open(page, `/boxes/ghost-box/${p}`);
      await expect(page.locator('#main [role="alert"]').first()).toBeVisible({ timeout: 15_000 });
    }
  });

  test.describe(`Files, Tools and Terminal at ${width}px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
    });

    test('Files says its folder is the demo\'s, not the box\'s disk', async ({ page }) => {
      await open(page, `/boxes/${BOX}/files`);
      await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible();
      const note = page.getByTestId('files-source-note');
      await expect(note).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('files-source-badge')).toHaveText('Simulated');
      await expect(note).toContainText('not the box');
      await expect(page.getByTestId('demo-banner')).toBeVisible();
      await expectNoSidewaysScroll(page);
    });

    test('Files says so when a refresh fails, and keeps what it had', async ({ page }) => {
      await open(page, `/boxes/${BOX}/files`);
      await expect(page.getByTestId('files-source-note')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByRole('button', { name: 'exchange', exact: true })).toBeVisible();
      // the one injected failure of this spec: a folder read that the server answers with an error
      await page.route('**/files/list**', (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the box did not answer' }) }));
      // the folder is re-read every 15 seconds, so the next poll meets the failure
      const err = page.getByTestId('files-refresh-error');
      await expect(err).toBeVisible({ timeout: 25_000 });
      await expect(err).toContainText('may be out of date');
      await expect(page.getByRole('button', { name: 'exchange', exact: true })).toBeVisible();
      await expectNoSidewaysScroll(page);
    });

    test('Tools says its installs are simulated', async ({ page }) => {
      await open(page, `/boxes/${BOX}/tools`);
      await expect(page.getByRole('heading', { name: 'Tools', level: 1 })).toBeVisible();
      const note = page.getByTestId('tools-source-note');
      await expect(note).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('tools-source-badge')).toHaveText('Simulated');
      await expect(note).toContainText('Nothing is installed on any box');
      await expect(page.getByTestId('demo-banner')).toBeVisible();
      await expectNoSidewaysScroll(page);
    });

    test('Tools shows a failed profile list instead of an empty one', async ({ page }) => {
      await page.route('**/v1/profiles', (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the profiles folder could not be read' }) }));
      await open(page, `/boxes/${BOX}/tools`);
      const err = page.getByTestId('profiles-error');
      await expect(err).toBeVisible({ timeout: 15_000 });
      await expect(err).toContainText('could not be read');
      await expect(page.getByText('No profiles yet.')).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    });

    test('Tools says a server with no tools has none, rather than a blank page', async ({ page }) => {
      await page.route(`**/v1/boxes/${BOX}/tools`, (r) => r.fulfill({ status: 501, contentType: 'application/json', body: JSON.stringify({ code: 'agent_unreachable', message: 'this server cannot reach a box' }) }));
      await open(page, `/boxes/${BOX}/tools`);
      const msg = page.getByTestId('tools-unavailable');
      await expect(msg).toBeVisible({ timeout: 15_000 });
      await expect(msg).toContainText('this server cannot reach a box');
      await expect(page.getByTestId('tools-error')).toHaveCount(0);
    });

    test('the Terminal names its box and says its shell is the demo\'s', async ({ page }) => {
      await open(page, `/boxes/${BOX}/terminal`);
      const target = page.getByTestId('terminal-target');
      await expect(target).toContainText(BOX);
      await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
      await expect(target).toHaveAttribute('data-source', 'simulated');
      await expect(target).toHaveAttribute('data-runs-as', 'demo');
      await expect(target).toContainText(`Demo shell for ${BOX}`);
      await expect(page.getByTestId('terminal-source-badge')).toHaveText('Simulated');
      await expect(page.getByTestId('terminal-source-note')).toContainText('not the box');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.getByTestId('terminal'));
    });
  });
}
