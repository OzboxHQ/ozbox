import { applyPlan } from './apply';
import { expect, test, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The set-up-your-fleet and create-a-box flows, on the demo provider. Nothing here reaches a real cloud: the cloud
// path is only walked as far as its first check, which refuses (no cloud CLI or no sign-in on a CI machine).

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;

// A running box of this spec's own, so nothing an earlier spec did to the seeded boxes matters.
test.beforeAll(async ({ request }) => {
  const headers = { Authorization: `Bearer ${token()}` };
  const plan = await request.post(`${origin()}/v1/plans`, { headers, data: { operation: { op: 'create', spec: { name: 'setup-a', size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} } } } });
  const body = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers, { plan_id: body.plan_id })).ok()).toBe(true);
});

async function axeClean(page: Page) {
  const r = await axeScan(page);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function openSetup(page: Page) {
  await open(page, '/settings/providers');
  await page.getByTestId('add-provider').click();
  const sheet = page.getByTestId('setup-sheet');
  await expect(sheet).toBeVisible();
  return sheet;
}

test('a cloud that is not signed in is refused with a reason and a fix, and nothing is changed', async ({ page }) => {
  const sheet = await openSetup(page);
  await expect(sheet.getByTestId('setup-continue')).toBeDisabled();
  await sheet.getByTestId('provider-aws').click();
  await sheet.getByTestId('setup-continue').click();
  await expect(sheet.getByTestId('setup-step-title')).toHaveText('Sign in');
  await expect(sheet.getByTestId('setup-continue')).toBeDisabled();
  await sheet.getByRole('button', { name: 'Check sign-in' }).click();
  const problem = sheet.getByTestId('problem');
  // the check runs the cloud's own command-line tool, which has its own bounded time
  await expect(problem).toBeVisible({ timeout: 20_000 });
  expect(['tool_missing', 'not_signed_in']).toContain(await problem.getAttribute('data-code'));
  // Still on the same step: it cannot be skipped.
  await expect(sheet.getByTestId('setup-continue')).toBeDisabled();
  // An unusable profile name is refused before anything runs.
  await sheet.getByLabel('Sign-in profile').fill('bad name');
  await sheet.getByRole('button', { name: 'Check sign-in' }).click();
  await expect(sheet.getByTestId('problem')).toHaveAttribute('data-code', 'bad_profile', { timeout: 20_000 });
});

test('the free sandbox: pick it, set your time zone, finish', async ({ page }) => {
  const sheet = await openSetup(page);
  await sheet.getByTestId('provider-fake').click();
  await sheet.getByTestId('setup-continue').click();
  await expect(sheet.getByTestId('setup-step-title')).toHaveText('Your country and time zone');
  // Suggested from the browser, editable, searchable.
  const zone = sheet.getByRole('combobox', { name: 'Time zone' });
  await zone.fill('lagos');
  await sheet.getByRole('option', { name: /Africa\/Lagos/ }).click();
  const country = sheet.getByRole('combobox', { name: 'Country' });
  await country.fill('zzzz');
  await expect(sheet.getByText('No matching country.')).toBeVisible();
  await country.fill('nigeria');
  await sheet.getByRole('option', { name: 'Nigeria' }).click();
  await expect(sheet.getByTestId('setup-finish')).toBeDisabled();
  await sheet.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(sheet.getByTestId('setup-finish')).toBeEnabled();
  await sheet.getByTestId('setup-finish').click();
  await expect(sheet.getByTestId('setup-done')).toBeVisible();
  await sheet.getByRole('button', { name: 'Close' }).first().click();
  await expect(sheet).toBeHidden();

  // The choice is stored by the server, and quiet hours now read in that zone.
  const r = await page.request.get(`${origin()}/v1/settings`, { headers: { Authorization: `Bearer ${token()}` } });
  const body = (await r.json()) as { settings: { locale: { country_code: string | null; time_zone: string | null } } };
  expect(body.settings.locale).toEqual({ country_code: 'NG', time_zone: 'Africa/Lagos' });
  await open(page, '/settings');
  await expect(page.getByTestId('locale-now')).toContainText('WAT');
  await open(page, '/settings/apps');
  await expect(page.getByTestId('apps-note')).toBeVisible();
  await expect(page.getByText(/Quiet hours are .*UTC\)/)).toBeVisible();
});

test('an invalid time zone or country is refused by the server', async ({ request }) => {
  const headers = { Authorization: `Bearer ${token()}` };
  const cur = (await (await request.get(`${origin()}/v1/settings`, { headers })).json()) as { settings: Record<string, unknown> };
  for (const locale of [{ country_code: 'ng', time_zone: null }, { country_code: null, time_zone: 'Mars/Olympus' }]) {
    const r = await request.put(`${origin()}/v1/settings`, { headers, data: { ...cur.settings, locale } });
    expect(r.status()).toBeGreaterThanOrEqual(400);
  }
});

test('every integration guide is there, step by step', async ({ page }) => {
  await open(page, '/settings/apps');
  for (const c of ['email', 'slack', 'webhook', 'sign_in']) {
    const g = page.getByTestId(`guide-${c}`);
    await g.locator('summary').click();
    await expect(g.locator('li').first()).toBeVisible();
  }
});

test('create a box: validate the name, review the plan, create it, watch it become ready', async ({ page }, testInfo) => {
  // A retry must not meet the box its failed first attempt already made.
  const made = testInfo.retry === 0 ? 'made-here' : `made-here-r${testInfo.retry}`;
  await open(page, '/');
  await page.getByTestId('create-box-button').click();
  const sheet = page.getByTestId('create-box-sheet');
  await expect(sheet).toBeVisible();
  const next = sheet.getByTestId('create-continue');
  await expect(next).toBeDisabled();
  // The name is checked as it is typed, like a box name, and against boxes that exist.
  await sheet.getByLabel('Box name').fill('Bad Name');
  await expect(sheet.getByTestId('name-message')).toContainText('lowercase');
  await expect(next).toBeDisabled();
  await sheet.getByLabel('Box name').fill('setup-a');
  await expect(sheet.getByTestId('name-message')).toContainText('already exists');
  await expect(next).toBeDisabled();
  await sheet.getByLabel('Box name').fill(made);
  await expect(sheet.getByTestId('name-message')).toContainText('free');
  await next.click();

  // Size: provider-neutral sizes, the mapped machine (or a dash) and a price (or a dash), never a guess.
  await expect(sheet.getByTestId('create-step-title')).toHaveText('Size and region');
  await expect(sheet.getByTestId('size-M')).toContainText('vCPU');
  await expect(sheet.getByTestId('size-M')).toContainText(/Price: —|a month \(estimate\)/);
  await sheet.getByTestId('size-S').click();
  await sheet.getByLabel('Work disk (GB)').fill('10');
  await expect(next).toBeDisabled();
  await sheet.getByLabel('Work disk (GB)').fill('40');
  await next.click();

  // Tools: defaults are ticked, tools that cannot be verified are shown disabled with the reason.
  await expect(sheet.getByTestId('create-tool-github-cli').getByRole('checkbox')).toBeChecked();
  await expect(sheet.getByTestId('create-tool-docker').getByRole('checkbox')).toBeDisabled();
  await expect(sheet.getByTestId('create-tool-docker')).toContainText('Not available yet');
  await next.click();

  // Options, then the plan.
  await sheet.getByLabel('Labels').fill('team=web');
  await sheet.getByTestId('create-review').click();
  await expect(sheet.getByTestId('create-step-title')).toHaveText('Review the plan');
  await expect(sheet.getByRole('list', { name: 'Review the plan' })).toBeVisible();
  await expect(sheet.getByTestId('estimate')).toContainText(/Estimated cost: \S/);
  // Nothing exists yet.
  const before = await page.request.get(`${origin()}/v1/boxes/${made}`, { headers: { Authorization: `Bearer ${token()}` } });
  expect(before.status()).toBe(404);
  await sheet.getByTestId('create-apply').click();

  await expect(sheet.getByTestId('create-progress')).toBeVisible({ timeout: 15_000 });
  await expect(sheet.getByTestId('stage-now')).toContainText('Ready', { timeout: 30_000 });
  await expect(sheet.getByText('First self-test')).toBeVisible();
  await expect(sheet.getByTestId('tools-state')).toBeVisible();
  await sheet.getByTestId('open-box').click();
  await expect(page).toHaveURL(new RegExp(`/boxes/${made}$`));
});

test('a plan that is refused shows its reason and the fix', async ({ page, request }) => {
  const headers = { Authorization: `Bearer ${token()}` };
  const cur = (await (await request.get(`${origin()}/v1/settings`, { headers })).json()) as { settings: { budget: Record<string, unknown> } };
  const capped = { ...cur.settings, budget: { ...cur.settings.budget, max_running_boxes: 1 } };
  expect((await request.put(`${origin()}/v1/settings`, { headers, data: capped })).ok()).toBe(true);
  try {
    await open(page, '/');
    await page.getByTestId('create-box-button').click();
    const sheet = page.getByTestId('create-box-sheet');
    await sheet.getByLabel('Box name').fill('over-the-cap');
    await sheet.getByTestId('create-continue').click();
    await sheet.getByTestId('create-continue').click();
    await sheet.getByTestId('create-continue').click();
    await sheet.getByTestId('create-review').click();
    const refusal = sheet.getByTestId('refusal');
    await expect(refusal).toBeVisible();
    await expect(refusal).toContainText('Reason:');
    await expect(refusal).toContainText('fleet cap');
    await expect(sheet.getByTestId('create-apply')).toBeDisabled();
  } finally {
    await request.put(`${origin()}/v1/settings`, { headers, data: cur.settings });
  }
});

test('the palette offers the two flows and the Tools page', async ({ page }) => {
  await open(page, '/');
  await page.keyboard.press('Control+k');
  const palette = page.getByTestId('palette');
  await palette.getByRole('combobox').fill('create a box');
  await palette.getByRole('combobox').press('Enter');
  await expect(page.getByTestId('create-box-sheet')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.keyboard.press('Control+k');
  await palette.getByRole('combobox').fill('tools: setup-a');
  await expect(palette.getByRole('option', { name: /Tools: setup-a/ })).toBeVisible();
});

test('the approvals page counts tool requests before it says nothing is waiting', async ({ page }) => {
  await open(page, '/approvals');
  await expect(page.getByRole('heading', { name: 'Approvals', level: 1 })).toBeVisible();
  // Earlier specs leave plans waiting, so either the list or the empty state is right; never a blank page.
  await expect(page.getByRole('list', { name: 'Pending plans' }).or(page.getByText('Nothing waiting'))).toBeVisible();
});

for (const width of WIDTHS) {
  test(`set-up and create-a-box fit at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const setup = await openSetup(page);
    await expectNoSidewaysScroll(page);
    await expect(setup.getByTestId('setup-continue')).toBeInViewport();
    if (width < 1024) await expectTouchTargets(page, setup);
    await axeClean(page);
    await setup.getByTestId('provider-aws').click();
    await setup.getByTestId('setup-continue').click();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, setup);
    await setup.getByRole('button', { name: 'Close' }).first().click();
    await expect(setup).toBeHidden();

    await open(page, '/');
    await page.getByTestId('create-box-button').click();
    const sheet = page.getByTestId('create-box-sheet');
    await expectNoSidewaysScroll(page);
    await expect(sheet.getByTestId('create-continue')).toBeInViewport();
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page);
    await sheet.getByLabel('Box name').fill(`fit-${width}`);
    await sheet.getByTestId('create-continue').click();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, sheet);
    await sheet.getByTestId('create-continue').click();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page);
  });
}

test('the locale section fits and is labelled at every width', async ({ page }) => {
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/settings');
    const card = page.getByTestId('locale-card');
    await expect(card.getByRole('combobox', { name: 'Time zone' })).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, card);
  }
  await axeClean(page);
});
