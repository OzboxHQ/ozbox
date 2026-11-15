import { expect, test, type Page } from '@playwright/test';
import { applyPlan } from './apply';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// The demo provider simulates installs (instantly here, OZBOX_SIM_SPEED=0), so these tests change nothing real.

// These tests use boxes of their own, made here, so nothing an earlier spec did to the seeded boxes matters.
test.beforeAll(async ({ request }) => {
  const headers = { Authorization: `Bearer ${new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '')}` };
  const base = new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
  const run = async (operation: unknown) => {
    const plan = await request.post(`${base}/v1/plans`, { headers, data: { operation } });
    const body = (await plan.json()) as { plan_id: string };
    const done = await applyPlan(request, base, headers, { plan_id: body.plan_id });
    expect(done.ok()).toBe(true);
  };
  for (const name of ['tools-a', 'tools-b', 'tools-p']) {
    await run({ op: 'create', spec: { name, size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} } });
  }
  await run({ op: 'pause', name: 'tools-p' });
});

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;

async function finishJob(page: Page) {
  const sheet = page.getByTestId('tool-job-sheet');
  await expect(sheet.getByTestId('tool-job-state')).toHaveText('Done.');
  await sheet.getByRole('button', { name: 'Close' }).first().click();
  await expect(sheet).toBeHidden();
}

test('the Tools page lists groups, searches, and marks what is not available yet', async ({ page }) => {
  await open(page, '/boxes/tools-a/tools');
  await expect(page.getByRole('heading', { name: 'Tools', level: 1 })).toBeVisible();
  for (const g of ['Editors', 'AI agents', 'Languages']) await expect(page.getByRole('heading', { name: g })).toBeVisible();
  // A tool whose source could not be verified is shown with its reason and cannot be ticked.
  const docker = page.getByTestId('tool-docker');
  await expect(docker.getByText('Not available yet')).toBeVisible();
  await expect(docker.getByText(/fingerprint/)).toBeVisible();
  await expect(docker.getByRole('checkbox')).toHaveCount(0);
  // The defaults are marked, and tools say how they update.
  await expect(page.getByTestId('tool-github-cli').getByText('Default')).toBeVisible();
  await expect(page.getByTestId('tool-pnpm').getByText('Updates itself')).toBeVisible();
  await page.getByLabel('Search tools').fill('neovim');
  await expect(page.getByTestId('tool-neovim')).toBeVisible();
  await expect(page.getByTestId('tool-pnpm')).toHaveCount(0);
  await page.getByLabel('Search tools').fill('zzzz nothing');
  await expect(page.getByText('No tool matches that search.')).toBeVisible();
});

test('pick a bundle, review the plan, apply, and see it installed; then remove one', async ({ page }) => {
  await open(page, '/boxes/tools-a/tools');
  await page.getByTestId('bundle-ai-agents').click();
  await expect(page.getByTestId('selection-bar')).toContainText('selected');
  await page.getByRole('button', { name: 'Review plan' }).click();
  const plan = page.getByTestId('tool-plan-sheet');
  await expect(plan.getByText('Node.js 22')).toBeVisible(); // a dependency added to the plan
  await expect(plan.getByText(/needed by/).first()).toBeVisible();
  await expect(plan.getByText(/to download/)).toBeVisible();
  // Nothing has changed yet.
  await expect(page.getByTestId('tool-status-codex')).toHaveText('Not installed');
  await plan.getByRole('button', { name: 'Apply' }).click();
  await finishJob(page);
  await expect(page.getByTestId('tool-status-codex')).toContainText('Installed');
  await expect(page.getByTestId('selection-bar')).toHaveCount(0);

  await page.getByRole('button', { name: 'Remove Codex CLI' }).click();
  const confirm = page.getByRole('alertdialog');
  await expect(confirm).toContainText('Remove Codex CLI?');
  await confirm.getByRole('button', { name: 'Remove' }).click();
  await finishJob(page);
  await expect(page.getByTestId('tool-status-codex')).toHaveText('Not installed');
  // A tool another tool needs is refused with the reason, not removed.
  await page.getByRole('button', { name: 'Remove Node.js 22' }).click();
  await expect(page.getByText(/is needed by/)).toBeVisible();
});

test('an agent can ask for a tool, and only the owner approving installs it', async ({ page }) => {
  const res = await page.request.post(`${origin()}/v1/boxes/tools-a/tools/requests`, {
    headers: { Authorization: `Bearer ${token()}` },
    data: { tool: 'jq', reason: 'to read the build output', agent: 'claude-1' },
  });
  expect(res.status()).toBe(201);
  await open(page, '/approvals');
  const list = page.getByTestId('tool-requests');
  await expect(list).toContainText('claude-1 asked for jq on tools-a');
  await expect(list).toContainText('to read the build output');
  await open(page, '/boxes/tools-a/tools');
  await expect(page.getByTestId('tool-status-jq')).toHaveText('Not installed');
  await open(page, '/approvals');
  await page.getByTestId('tool-requests').getByRole('button', { name: 'Approve once' }).click();
  await expect(page.getByTestId('tool-requests')).toHaveCount(0);
  await open(page, '/boxes/tools-a/tools');
  await expect(page.getByTestId('tool-status-jq')).toContainText('Installed');
});

test('save the box as a profile, then create a box from it and install its tools', async ({ page }) => {
  await open(page, '/boxes/tools-a/tools');
  await page.getByRole('button', { name: 'Save this box as a profile' }).click();
  const save = page.getByTestId('save-profile-sheet');
  await save.getByLabel('Profile name').fill('Bad Name');
  await save.getByRole('button', { name: 'Save' }).click();
  await expect(save.getByRole('alert')).toBeVisible();
  await save.getByLabel('Profile name').fill('web-setup');
  await save.getByLabel('Description (optional)').fill('My web box');
  await save.getByRole('button', { name: 'Save' }).click();
  await expect(save).toBeHidden();
  const card = page.getByTestId('profile-web-setup');
  await expect(card).toContainText('My web box');

  await card.getByRole('button', { name: 'Create a box from web-setup' }).click();
  const create = page.getByTestId('create-from-profile-sheet');
  await create.getByLabel('Box name').fill('Bad Name');
  await create.getByRole('button', { name: 'Review the plan' }).click();
  await expect(create.getByRole('alert')).toBeVisible();
  await create.getByLabel('Box name').fill('echo');
  await create.getByRole('button', { name: 'Review the plan' }).click();
  const review = page.getByTestId('plan-sheet');
  await expect(review).toContainText('echo');
  await review.getByRole('button', { name: 'Apply' }).click();
  // The new box opens on its Tools page; the server installs the profile's tools itself once the box answers, so they
  // appear without anyone pressing install (the demo provider installs instantly).
  await expect(page).toHaveURL(/\/boxes\/echo\/tools$/);
  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId('tool-status-jq')).toContainText('Installed', { timeout: 2000 });
  }).toPass({ timeout: 40_000 });
  await expect(page.getByTestId('pending-banner')).toHaveCount(0);
});

test('a paused box says so instead of showing tools', async ({ page }) => {
  await open(page, '/boxes/tools-p/tools');
  await expect(page.getByText('Resume this box to see and change its tools.')).toBeVisible();
});

for (const width of WIDTHS) {
  test(`the Tools page and its sheets fit at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/boxes/tools-b/tools');
    await expect(page.getByTestId('tools-view')).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByTestId('tools-view'));
    await page.getByTestId('bundle-web').click();
    await expectNoSidewaysScroll(page);
    await page.getByRole('button', { name: 'Review plan' }).click();
    const plan = page.getByTestId('tool-plan-sheet');
    await expect(plan.getByRole('button', { name: 'Apply' })).toBeInViewport();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, plan);
    await plan.getByRole('button', { name: 'Close' }).first().click();
  });
}
