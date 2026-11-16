import { applyPlan } from './apply';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Backups on the demo provider: the fleet policy in Settings (the repository credentials are write-only), then a box's
// Backups tab: back up now to the provider and to the repository, restore (to a new box, over /work, into a folder),
// delete. Each width has boxes of its own, destroyed afterwards. Nothing here reaches a real cloud or a real repository:
// the demo box's restic is an in-memory stand-in.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

const PASSWORD = 'correct-horse-battery';
const ACCESS = 'AKIAEXAMPLE';
const SECRET = 'sekrit-key-value';

async function makeBox(request: APIRequestContext, name: string) {
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers: headers(),
    data: { operation: { op: 'create', spec: { name, size: 'S', work_disk_gb: 50, image: null, region: null, from_snapshot: null, labels: {} } } },
  });
  const body = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers(), { plan_id: body.plan_id })).ok()).toBe(true);
}

async function removeBox(request: APIRequestContext, name: string) {
  const plan = await request.post(`${origin()}/v1/plans`, { headers: headers(), data: { operation: { op: 'destroy', name, final_snapshot: false } } });
  if (!plan.ok()) return; // never made
  const body = (await plan.json()) as { plan_id: string };
  await applyPlan(request, origin(), headers(), { plan_id: body.plan_id, confirm_name: name });
}

/** The policy every other spec expects: nothing scheduled, no repository. */
async function resetPolicy(request: APIRequestContext) {
  await request.put(`${origin()}/v1/backups/settings`, {
    headers: headers(),
    data: { schedule: { kind: 'off', time: '02:00', weekday: 6 }, retention: { keep_daily: 7, keep_weekly: 4, keep_monthly: 6 }, provider_snapshots: true, restic: null, catch_up_hours: 12, overrides: {} },
  });
}

async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function apply(page: Page, width: number, risk: 'normal' | 'high', typed?: string) {
  const plan = page.getByTestId('plan-sheet');
  await expect(plan.getByRole('list', { name: 'Changes' })).toBeVisible();
  await expectNoSidewaysScroll(page);
  if (risk === 'high') {
    const button = plan.getByRole('button', { name: 'Apply, cannot be undone' });
    await expect(button).toBeDisabled();
    await plan.getByLabel(/Type .* to confirm/).fill(typed ?? '');
    await expect(button).toBeEnabled();
    await button.click();
  } else {
    const button = plan.getByRole('button', { name: 'Apply', exact: true });
    await expect(button).toBeInViewport();
    if (width < 1024) expect((await button.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(43.5);
    await button.click();
  }
  await expect(plan.getByRole('status').filter({ hasText: /is now|Nothing/ })).toBeVisible({ timeout: 20_000 });
  await plan.locator('form').getByRole('button', { name: 'Close' }).click();
  await expect(plan).toHaveCount(0);
}

for (const width of WIDTHS) {
  test(`backups at ${width}px: policy with write-only credentials, then back up, restore and delete`, async ({ page, request }, testInfo) => {
    // The demo box's repository is shared and remembers what an earlier attempt backed up, so a retry uses names of its own.
    const tag = testInfo.retry === 0 ? '' : `r${testInfo.retry}-`;
    const name = `bk-${tag}${width}`;
    const clone = `bk-copy-${tag}${width}`;
    const fromRepo = `bk-repo-${tag}${width}`;
    await resetPolicy(request);
    await makeBox(request, name);
    try {
      await page.setViewportSize({ width, height: 900 });

      // ---- Settings -> Backups ----
      await open(page, '/settings/backups');
      const policy = page.getByTestId('backups-policy');
      await expect(policy).toBeVisible();
      await expect(policy).toContainText('Off');
      await expectNoSidewaysScroll(page);
      await page.getByTestId('backups-edit').click();
      const sheet = page.getByTestId('backups-sheet');
      await expect(sheet.getByRole('heading', { name: 'Backup policy' })).toBeVisible();
      await sheet.locator('#bk-every').click();
      await page.getByRole('option', { name: 'Every day' }).click();
      await sheet.getByLabel('At (your clock, HH:MM)').fill('03:30');
      await sheet.getByLabel('Also back up to my own repository').click();
      await sheet.getByLabel('Location').fill('https://objects.example.com/bucket');
      await sheet.getByLabel('Repository password').fill(PASSWORD);
      await sheet.getByLabel('Access key id').fill(ACCESS);
      await sheet.getByLabel('Secret key').fill(SECRET);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, 'backups-sheet');
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet).toHaveCount(0);
      await expect(policy).toContainText('Every day at 03:30');
      await expect(policy).toContainText('Your repository');
      await expect(page.getByTestId('backups-estimate')).toContainText(/estimate|Not estimated/i);
      await expect(page.getByTestId(`backups-row-${name}`)).toBeVisible();
      // the credentials are write-only: nothing on the page, and the form asks for a new one only to replace it
      for (const secret of [PASSWORD, ACCESS, SECRET]) await expect(page.locator('body')).not.toContainText(secret);
      await page.getByTestId('backups-edit').click();
      await expect(sheet.getByText(/Saved, write-only/).first()).toBeVisible();
      expect(await sheet.getByLabel('Repository password').inputValue()).toBe('');
      await sheet.getByRole('button', { name: 'Cancel' }).click();
      const fleet = await (await page.request.get(`${origin()}/v1/backups`, { headers: headers() })).text();
      for (const secret of [PASSWORD, ACCESS, SECRET]) expect(fleet).not.toContain(secret);

      // ---- the box's Backups tab ----
      await open(page, `/boxes/${name}`);
      await page.getByRole('tab', { name: 'Backups' }).click();
      const tab = page.getByTestId('backups-tab');
      await expect(tab.getByText('No backups yet')).toBeVisible();
      await expect(page.getByTestId('backups-next')).toContainText('Every day at 03:30');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, tab);
      await axeClean(page, 'backups-tab');

      // back up now: the provider's snapshot, planned first
      await page.getByTestId('backup-now').click();
      await page.getByRole('menuitem', { name: 'Provider snapshot' }).click();
      await expect(page.getByTestId('plan-sheet').getByRole('heading', { name: `Back up ${name}`, exact: false }).or(page.getByTestId('plan-sheet').getByRole('heading', { name: /Snapshot/ }))).toBeVisible();
      await apply(page, width, 'normal');
      const snapshotRow = tab.locator('[data-testid^="backup-fake-snap"]').first();
      await expect(snapshotRow).toBeVisible({ timeout: 15_000 });
      await expect(snapshotRow).toContainText('Provider snapshot');
      await expect(snapshotRow).toContainText('Taken by hand');

      // back up now: the repository. The plan says the credentials are put on the box first, and never shows them.
      await page.getByTestId('backup-now').click();
      await page.getByRole('menuitem', { name: 'To my repository' }).click();
      const plan = page.getByTestId('plan-sheet');
      await expect(plan.getByText(/Put the repository credentials on/)).toBeVisible();
      await expect(plan.getByText(/Back up \/work of .* to the repository, encrypted/)).toBeVisible();
      for (const secret of [PASSWORD, ACCESS, SECRET]) await expect(plan).not.toContainText(secret);
      if (width < 1024) await expectTouchTargets(page, plan);
      await axeClean(page, 'plan-sheet');
      await apply(page, width, 'normal');
      const repoRow = tab.locator('li', { hasText: 'Repository' }).filter({ hasText: 'Complete' }).first();
      await expect(repoRow).toBeVisible({ timeout: 20_000 });
      await expect(tab.getByTestId('backups-last')).toBeVisible();

      // restore the repository backup into a folder beside the files
      await repoRow.getByRole('button', { name: /^Restore…/ }).click();
      const restore = page.getByTestId('restore-sheet');
      await expect(restore.getByTestId('restore-folder')).toBeVisible();
      await expect(restore.getByTestId('restore-in_place')).toBeVisible();
      // a repository backup can also go into a new box, in one plan
      await expect(restore.getByTestId('restore-new_box')).toBeVisible();
      if (width < 1024) await expectTouchTargets(page, restore);
      await axeClean(page, 'restore-sheet');
      await restore.getByRole('button', { name: 'Review plan' }).click();
      await expect(page.getByTestId('plan-sheet').getByText(/into \/work\/restored-/)).toBeVisible();
      await apply(page, width, 'normal');

      // restore the repository backup into a new box: one plan that creates it, hands it the credentials, restores, checks
      await repoRow.getByRole('button', { name: /^Restore…/ }).click();
      await restore.getByTestId('restore-new_box').click();
      await restore.getByLabel('Name of the new box').fill(fromRepo);
      await restore.getByRole('button', { name: 'Review plan' }).click();
      const toNew = page.getByTestId('plan-sheet');
      await expect(toNew.getByText(/over the empty \/work of/)).toBeVisible();
      await expect(toNew.getByText(/Put the repository credentials on/)).toBeVisible();
      for (const secret of [PASSWORD, ACCESS, SECRET]) await expect(toNew).not.toContainText(secret);
      await apply(page, width, 'normal');
      const repoMade = await page.request.get(`${origin()}/v1/boxes/${fromRepo}`, { headers: headers() });
      expect(repoMade.ok()).toBe(true);

      // restore the snapshot to a new box
      await snapshotRow.getByRole('button', { name: /^Restore…/ }).click();
      await expect(restore.getByTestId('restore-new_box')).toBeVisible();
      await restore.getByLabel('Name of the new box').fill('Bad Name');
      await restore.getByRole('button', { name: 'Review plan' }).click();
      await expect(restore.getByRole('alert')).toContainText('lowercase letters');
      await restore.getByLabel('Name of the new box').fill(clone);
      await restore.getByRole('button', { name: 'Review plan' }).click();
      await expect(page.getByTestId('plan-sheet').getByText(/restored from snapshot fake-snap/)).toBeVisible();
      await apply(page, width, 'normal');
      const made = await page.request.get(`${origin()}/v1/boxes/${clone}`, { headers: headers() });
      expect(made.ok()).toBe(true);

      // replace /work of this box: the name is typed, and the plan says the current state is kept first
      await snapshotRow.getByRole('button', { name: /^Restore…/ }).click();
      await restore.getByTestId('restore-in_place').click();
      await restore.getByRole('button', { name: 'Review plan' }).click();
      const inPlace = page.getByTestId('plan-sheet');
      await expect(inPlace.getByText(/Snapshot .* as it is now/)).toBeVisible();
      await expect(inPlace.getByText(/Replace the \/work disk of/)).toBeVisible();
      await apply(page, width, 'high', name);
      await expect(tab.locator('[data-testid^="backup-fake-snap"]')).toHaveCount(2, { timeout: 15_000 });

      // delete a snapshot: high risk, name typed, then it is gone
      const before = await tab.locator('[data-testid^="backup-fake-snap"]').count();
      await tab.locator('[data-testid^="backup-fake-snap"]').first().getByRole('button', { name: /^Delete…/ }).click();
      await expect(page.getByTestId('plan-sheet').getByText(/Delete snapshot .* It cannot be brought back/)).toBeVisible();
      await apply(page, width, 'high', name);
      await expect(tab.locator('[data-testid^="backup-fake-snap"]')).toHaveCount(before - 1, { timeout: 15_000 });
      await expectNoSidewaysScroll(page);
    } finally {
      await removeBox(request, fromRepo);
      await removeBox(request, clone);
      await removeBox(request, name);
      await resetPolicy(request);
    }
  });
}

for (const width of WIDTHS) {
  test(`turning a box's backups off at ${width}px: the dialog says what stops, then the box holds no credentials and its schedule is off`, async ({ page, request }, testInfo) => {
    const tag = testInfo.retry === 0 ? '' : `r${testInfo.retry}-`;
    const name = `bk-off-${tag}${width}`;
    await resetPolicy(request);
    await makeBox(request, name);
    try {
      await page.setViewportSize({ width, height: 900 });
      for (const [secret, value] of [['restic-password', PASSWORD], ['restic-access-key', ACCESS], ['restic-secret-key', SECRET]] as const) {
        expect((await request.put(`${origin()}/v1/secrets/${secret}`, { headers: headers(), data: { value } })).ok()).toBe(true);
      }
      const policy = {
        schedule: { kind: 'daily', time: '03:30', weekday: 6 },
        retention: { keep_daily: 7, keep_weekly: 4, keep_monthly: 6 },
        provider_snapshots: true,
        restic: { kind: 's3', location: 'https://objects.example.com/bucket' },
        catch_up_hours: 12,
        overrides: {},
      };
      expect((await request.put(`${origin()}/v1/backups/settings`, { headers: headers(), data: policy })).ok()).toBe(true);
      expect((await request.post(`${origin()}/v1/boxes/${name}/backups/credentials`, { headers: headers() })).ok()).toBe(true);

      await open(page, `/boxes/${name}`);
      await page.getByRole('tab', { name: 'Backups' }).click();
      const tab = page.getByTestId('backups-tab');
      await expect(page.getByTestId('backups-next')).toContainText('Every day at 03:30');
      await expectNoSidewaysScroll(page);

      // cancelling changes nothing
      await page.getByTestId('turn-off-backups').click();
      const dialog = page.getByRole('alertdialog');
      await expect(dialog).toContainText(`Turn off backups on ${name}?`);
      await expect(dialog).toContainText('repository credentials are removed from the box');
      await expect(dialog).toContainText('Backups already made stay where they are');
      if (width < 1024) await expectTouchTargets(page, dialog);
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId('backups-turned-off')).toHaveCount(0);

      // confirming does it, and the page says so after a reload (the record, not the still-mounted state)
      await page.getByTestId('turn-off-backups').click();
      await page.getByRole('alertdialog').getByRole('button', { name: 'Turn off' }).click();
      await expect(page.getByTestId('backups-turned-off')).toBeVisible({ timeout: 15_000 });
      await open(page, `/boxes/${name}`);
      await page.getByRole('tab', { name: 'Backups' }).click();
      await expect(page.getByTestId('backups-turned-off')).toBeVisible();
      await expect(page.getByTestId('backups-next')).toContainText('No schedule for this box');
      await expect(page.getByTestId('turn-off-backups')).toHaveCount(0);
      await expect(tab.getByTestId('send-credentials')).toBeVisible();
      await expectNoSidewaysScroll(page);
      await axeClean(page, 'backups-tab');
      const list = (await (await request.get(`${origin()}/v1/boxes/${name}/backups`, { headers: headers() })).json()) as { restic: { configured_on_box: boolean }; turned_off: boolean };
      expect(list.restic.configured_on_box).toBe(false);
      expect(list.turned_off).toBe(true);
    } finally {
      await removeBox(request, name);
      await resetPolicy(request);
    }
  });
}
