
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The Bill page on the demo provider: a made-up, deterministic bill beside the estimate, with three flagged days (a
// service the estimate does not model, a day the server was only partly watching, and spend with no box tag), the
// budget on the real figure, and a forgotten-resources list with a plan-then-apply delete that needs typed words.
// Nothing here reaches a real cloud: the demo provider has no account, and what it "deletes" is made up too.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function setBudget(request: APIRequestContext, monthly: number | null) {
  const got = await request.get(`${origin()}/v1/settings`, { headers: headers() });
  const body = (await got.json()) as { settings: { budget: Record<string, unknown> } };
  body.settings.budget['monthly_usd'] = monthly;
  const put = await request.put(`${origin()}/v1/settings`, { headers: headers(), data: body.settings });
  expect(put.ok()).toBeTruthy();
}

/** The server reads the bill on its first tick; wait until the page has it. */
async function waitForBill(request: APIRequestContext) {
  await expect
    .poll(async () => ((await (await request.get(`${origin()}/v1/cost/bill`, { headers: headers() })).json()) as { basis: string }).basis, { timeout: 20_000 })
    .toBe('bill');
}

for (const width of WIDTHS) {
  test(`bill at ${width}px: real figures beside the estimate, drift with causes, budget gauge`, async ({ page, request }) => {
    await waitForBill(request);
    await setBudget(request, 1000);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/costs/bill');
      await expect(page.getByRole('heading', { name: 'Bill', level: 1 })).toBeVisible();
      await expect(page.getByTestId('bill-stats')).toBeVisible();
      await expectNoSidewaysScroll(page);

      // What the figures are, said in words: a bill, with its source, and the lag note
      await expect(page.getByTestId('bill-source')).toContainText('From the provider bill');
      await expect(page.getByTestId('bill-source')).toContainText('Demo data');
      await expect(page.getByTestId('bill-lag-note')).toContainText('24 hours late');

      // The chart draws finished days and names the ones it leaves out
      await expect(page.getByTestId('bill-chart')).toBeVisible();
      await expect(page.getByTestId('bill-unfinished')).toContainText('Not drawn');

      // The three stories, each with its likely cause
      const drift = page.getByTestId('bill-drift');
      await expect(drift.getByTestId('bill-drift-row')).toHaveCount(4);
      await expect(drift).toContainText('A service Oz Box does not estimate: Amazon Virtual Private Cloud');
      await expect(drift).toContainText('watching for only 6 hours');
      await expect(drift).toContainText('no box name');
      await expect(drift).toContainText('No box tag');

      // By box: alpha and beta, with a difference that is a sign and a word, never only a colour
      const boxes = page.getByTestId('bill-box-table');
      await expect(boxes).toContainText('alpha');
      await expect(page.getByTestId('bill-service-table')).toContainText('Amazon Virtual Private Cloud');

      // The budget says which figure it used. On the first two days of a month the bill has no finished day in the
      // month yet, so the estimate is used and the page must say that instead.
      const budget = page.getByTestId('bill-budget');
      const figure = (await (await request.get(`${origin()}/v1/cost/bill`, { headers: headers() })).json()) as { budget: { basis: string | null; percent: number | null } };
      if (figure.budget.basis === 'bill') {
        await expect(page.getByTestId('bill-budget-basis')).toHaveText('From the provider bill');
        await expect(budget).toContainText('Counted from the provider bill through');
      } else {
        if (figure.budget.basis === 'estimate') await expect(page.getByTestId('bill-budget-basis')).toHaveText('Estimate only');
        await expect(budget).not.toContainText('Counted from the provider bill through');
      }
      if (figure.budget.percent === null) await expect(page.getByTestId('bill-gauge')).toHaveCount(0);
      else {
        await expect(page.getByTestId('bill-gauge')).toBeVisible();
        await expect(page.getByTestId('bill-gauge')).toHaveAttribute('aria-valuetext', /% of the budget/);
      }

      // Model spend is an estimate and says so
      await expect(page.getByTestId('bill-models')).toContainText('An estimate from the token counts');

      if (width < 1024) await expectTouchTargets(page, page.getByTestId('bill-budget'));
      await expectNoSidewaysScroll(page);
      for (const id of ['bill-stats', 'bill-budget', 'bill-chart', 'bill-box-table', 'bill-drift', 'bill-models']) await axeClean(page, id);
    } finally {
      await setBudget(request, null);
    }
  });

  test(`bill at ${width}px: with no budget the gauge is not drawn and a way to set one is offered`, async ({ page, request }) => {
    await waitForBill(request);
    await setBudget(request, null);
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/costs/bill');
    const budget = page.getByTestId('bill-budget');
    await expect(budget).toContainText('No monthly budget is set');
    await expect(page.getByTestId('bill-gauge')).toHaveCount(0);
    await expect(budget.getByRole('link', { name: 'Set a budget' })).toBeVisible();
    await expectNoSidewaysScroll(page);
  });

  test(`forgotten resources at ${width}px: listed with cost, untagged ones locked, delete needs the typed words`, async ({ page, request }) => {
    await waitForBill(request);
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/costs/bill');
    const card = page.getByTestId('orphans-card');
    await expect(card.getByTestId('orphans-table')).toBeVisible();
    const retired = card.getByTestId('orphan-vol-0demo000retired');
    await expect(retired).toContainText('An old /work disk a restore kept');
    await expect(retired).toContainText('200 GB');
    await expect(retired).toContainText('$16.00');
    // an untagged lookalike is listed with a reason and cannot be chosen
    const stray = card.getByTestId('orphan-i-0demo000stray');
    await expect(stray).toContainText('Not tagged, so Oz Box will not delete it');
    await expect(stray.getByRole('checkbox')).toHaveCount(0);
    // an image is listed and cannot be chosen either
    await expect(card.getByTestId('orphan-ami-0demo000unsigned')).toContainText('Images are retired where they are built');
    await expectNoSidewaysScroll(page);
    await axeClean(page, 'orphans-card');

    const del = card.getByRole('button', { name: /^Delete \d+ selected/ });
    await expect(del).toBeDisabled();
    await retired.getByRole('checkbox').click();
    await card.getByTestId('orphan-snap-0demo000gone').getByRole('checkbox').click();
    await expect(del).toBeEnabled();
    if (width < 1024) await expectTouchTargets(page, card);
    await del.click();

    const sheet = page.getByTestId('orphans-sheet');
    await expect(sheet).toBeVisible();
    await expect(sheet).toContainText('This cannot be undone');
    await expect(sheet).toContainText('vol-0demo000retired');
    const confirm = sheet.getByLabel('Type delete-2 to confirm');
    const go = sheet.getByRole('button', { name: 'Delete permanently' });
    await expect(go).toBeDisabled();
    await confirm.fill('delete-3');
    await expect(go).toBeDisabled();
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page, 'orphans-sheet');
    await confirm.fill('delete-2');
    await expect(go).toBeEnabled();
    // One demo account serves every width, so the narrower widths stop at the review and the widest deletes.
    if (width !== 1440) {
      await sheet.getByRole('button', { name: 'Cancel' }).click();
      await expect(sheet).toHaveCount(0);
      await expect(card.getByTestId('orphan-vol-0demo000retired')).toBeVisible();
      return;
    }
    await go.click();

    await expect(sheet).toHaveCount(0);
    await expect(card.getByTestId('orphans-last-delete')).toContainText('Deleted 2 resource(s).');
    await expect(card.getByTestId('orphan-vol-0demo000retired')).toHaveCount(0);
    await expect(card.getByTestId('orphan-i-0demo000stray')).toBeVisible();
  });
}

test('the bill drift alert is set in Settings, Budgets, checked in the form, and the server reports it back', async ({ page, request }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await open(page, '/settings/budgets');
  await page.getByRole('button', { name: 'Edit' }).click();
  const sheet = page.getByTestId('budget-sheet');
  const pct = sheet.getByLabel('Difference (percent)');
  const min = sheet.getByLabel('Difference (dollars)');
  try {
    // a share outside 1 to 1000 and a negative amount are caught before the server is asked
    await pct.fill('0');
    await min.fill('-1');
    await sheet.getByRole('button', { name: 'Save' }).click();
    await expect(sheet.getByText('A share from 1 to 1000 percent')).toBeVisible();
    await expect(sheet.getByText('An amount of 0 or more')).toBeVisible();
    await expectNoSidewaysScroll(page);
    await expectTouchTargets(page, sheet);
    await axeClean(page, 'budget-sheet');

    await pct.fill('40');
    await min.fill('3.5');
    await sheet.getByRole('button', { name: 'Save' }).click();
    await expect(sheet).toBeHidden();
    await expect(page.getByText('Bill drift alert').locator('xpath=following-sibling::dd[1]')).toHaveText('Flag a day that differs by 40% and 3.5 dollars');
    const bill = (await (await request.get(`${origin()}/v1/cost/bill`, { headers: headers() })).json()) as { drift_threshold: { percent: number; min: number } };
    expect(bill.drift_threshold).toEqual({ percent: 40, min: 3.5 });
  } finally {
    // the demo server is shared: put the defaults back
    const got = await request.get(`${origin()}/v1/settings`, { headers: headers() });
    const body = (await got.json()) as { settings: { budget: Record<string, unknown> } };
    body.settings.budget['drift_alert_pct'] = 25;
    body.settings.budget['drift_alert_min_usd'] = 2;
    await request.put(`${origin()}/v1/settings`, { headers: headers(), data: body.settings });
  }
});
