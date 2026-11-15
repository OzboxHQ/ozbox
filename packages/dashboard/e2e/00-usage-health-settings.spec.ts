import { type APIRequestContext, expect, test } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// These run first, while alpha, bravo and charlie are running. Only the last two tests change anything, and only
// settings (never boxes).

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
type Budget = Record<string, unknown> & { max_running_boxes?: number | null };

// The server is shared by every spec after this one, so a cap on running boxes that this file sets must not outlive it: each
// later spec leaves boxes running (a failed first attempt leaves one more), and under any cap they add up to it and every create
// is refused. Raising the number only moved that point further out. The file puts the cap back to what it found, at the end.
let capBefore: number | null | undefined;
async function readBudget(request: APIRequestContext): Promise<{ settings: { budget: Budget } }> {
  const r = await request.get(`${origin()}/v1/settings`, { headers: { Authorization: `Bearer ${token()}` } });
  return (await r.json()) as { settings: { budget: Budget } };
}
test.beforeAll(async ({ request }) => {
  capBefore = (await readBudget(request)).settings.budget.max_running_boxes ?? null;
});
test.afterAll(async ({ request }) => {
  const cur = (await readBudget(request)).settings;
  const budget: Budget = { ...cur.budget, max_running_boxes: capBefore ?? null };
  const put = await request.put(`${origin()}/v1/settings`, { headers: { Authorization: `Bearer ${token()}` }, data: { ...cur, budget } });
  expect(put.ok(), await put.text()).toBe(true);
});

test('suggestions are shown, name the saving as a dash without prices, and apply nothing', async ({ page, request }) => {
  await open(page, '/usage');
  const list = page.getByRole('list', { name: 'Suggestions' });
  const alpha = list.getByRole('listitem').filter({ hasText: 'alpha' });
  await expect(alpha.getByText('Move alpha down to size S')).toBeVisible();
  await expect(alpha.getByText('—').first()).toBeVisible();
  const charlie = list.getByRole('listitem').filter({ hasText: 'charlie' });
  await expect(charlie.getByText('Pause charlie when it is idle')).toBeVisible();
  await expect(list.getByRole('listitem').filter({ hasText: 'bravo' })).toHaveCount(0);
  // Review opens the normal plan sheet; cancelling leaves the box exactly as it was
  await alpha.getByRole('button', { name: 'Review resize' }).click();
  const sheet = page.getByTestId('plan-sheet');
  await expect(sheet.getByRole('heading', { name: 'Resize alpha' })).toBeVisible();
  await expect(sheet.getByRole('list', { name: 'Changes' }).getByRole('listitem').first()).toBeVisible();
  await sheet.getByRole('button', { name: 'Cancel' }).click();
  const u = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const res = await request.get(`${u.origin}/v1/boxes/alpha`, { headers: { Authorization: `Bearer ${u.hash.replace('#token=', '')}` } });
  const rec = (await res.json()) as { spec: { size: string }; state: string };
  expect(rec.spec.size).toBe('M');
  expect(rec.state).toBe('running');
});

test('usage shows a range, and a breakdown by box, project and run', async ({ page }) => {
  await open(page, '/usage');
  await expect(page.getByRole('heading', { name: 'Usage', level: 1 })).toBeVisible();
  for (const name of ['Last 3 h, 1 min', 'Last 7 days, 1 h', 'Live, 5 s']) {
    await page.getByRole('tab', { name }).click();
    await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('table', { name: 'Usage by box' }).getByRole('row')).toHaveCount(4); // header + three running boxes
  }
  await expect(page.getByText('Simulated').first()).toBeVisible();
  await page.getByRole('tab', { name: 'By project' }).click();
  const projects = page.getByRole('table', { name: 'Usage by project' });
  await expect(projects.getByRole('row', { name: /web/ })).toContainText('alpha, bravo');
  await expect(projects.getByRole('row', { name: /\(none\)/ })).toContainText('charlie');
  await page.getByRole('tab', { name: 'By run' }).click();
  await expect(page.getByRole('table', { name: 'Usage by run' }).getByRole('row').nth(1)).toBeVisible();
});

test('the Health tab shows the failing step, and an unverified check is not a pass', async ({ page }) => {
  await open(page, '/boxes/bravo');
  await page.getByRole('tab', { name: 'Health' }).click();
  const test = page.getByTestId('selftest');
  await expect(test.getByText('A check failed')).toBeVisible();
  await expect(test.getByRole('alert')).toContainText('Failed step: tunnels up.');
  await expect(test.getByRole('list', { name: 'Checks' }).getByRole('listitem').filter({ hasText: 'tunnels up' }).getByText('Fail')).toBeVisible();
  await expect(page.getByTestId('incidents').getByText('Self-test failed')).toBeVisible();
  await expect(page.getByTestId('incidents').getByText('Restarted', { exact: true })).toBeVisible();
  await open(page, '/boxes/alpha');
  await page.getByRole('tab', { name: 'Health' }).click();
  await expect(page.getByTestId('selftest').getByText('All checks passed')).toBeVisible();
});

for (const width of WIDTHS) {
  test(`usage and health at ${width}px: no sideways scroll${width < 1024 ? ', 44px targets' : ''}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/usage');
    await expect(page.getByRole('table', { name: 'Usage by box' })).toBeVisible();
    await page.waitForTimeout(300);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
    for (const tab of ['By project', 'By run']) {
      await page.getByRole('tab', { name: tab }).click();
      await page.waitForTimeout(200);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('main'));
    }
    await open(page, '/boxes/bravo');
    await page.getByRole('tab', { name: 'Health' }).click();
    await expect(page.getByTestId('selftest')).toBeVisible();
    await page.waitForTimeout(200);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
  });
}

test('budget settings are saved by the server, not the browser, and a price shows the saving', async ({ page, browser }) => {
  await open(page, '/settings/budgets');
  await page.getByRole('button', { name: 'Edit' }).click();
  const sheet = page.getByTestId('budget-sheet');
  // a typing mistake is caught in the form
  await sheet.getByLabel('Most boxes running at once (optional)').fill('0');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  // set for the rest of this file only: the afterAll above puts the shared server's cap back to what it was
  await sheet.getByLabel('Most boxes running at once (optional)').fill('10');
  await sheet.getByLabel('Size M', { exact: true }).fill('200');
  await sheet.getByLabel('Size S', { exact: true }).fill('100');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  // a brand new browser profile (no storage at all) sees the same values: they live on the server
  const fresh = await browser.newContext();
  const other = await fresh.newPage();
  await open(other, '/settings/budgets');
  await expect(other.getByText('Most boxes running at once').locator('xpath=following-sibling::dd[1]')).toHaveText('10');
  await expect(other.getByTestId('budget-note')).toContainText('enforced when a box is created');
  await fresh.close();
  await open(page, '/usage');
  const alpha = page.getByRole('list', { name: 'Suggestions' }).getByRole('listitem').filter({ hasText: 'alpha' });
  await expect(alpha.getByText('$100.00 a month')).toBeVisible();
});

test('box defaults are saved by the server and fill what a new box leaves out', async ({ page, browser, request }) => {
  await open(page, '/settings/defaults');
  await page.getByRole('button', { name: 'Edit' }).click();
  const sheet = page.getByTestId('defaults-sheet');
  await sheet.getByLabel('Work disk (GB)').fill('250');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  const fresh = await browser.newContext();
  const other = await fresh.newPage();
  await open(other, '/settings/defaults');
  await expect(other.getByText('Work disk', { exact: true }).locator('xpath=following-sibling::dd[1]')).toHaveText('250 GB');
  await fresh.close();
  // the server fills a create request that leaves size and disk out (planning changes nothing)
  const u = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const token = u.hash.replace('#token=', '');
  const res = await request.post(`${u.origin}/v1/plans`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { operation: { op: 'create', spec: { name: 'defaults-probe' } } },
  });
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as { plan: { operation: { spec: { work_disk_gb: number } } } };
  expect(body.plan.operation.spec.work_disk_gb).toBe(250);
});
