import { applyPlan } from './apply';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Upgrading a box to a newer image, on the demo provider: options, plan, apply, then the box's self-test. Each width
// has a running box of its own, so nothing another spec did to the seeded boxes matters, and the runs do not depend on
// each other, and it is destroyed afterwards so the shared server is left as it was found.
// Nothing here reaches a real cloud.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;

async function makeBox(request: APIRequestContext, name: string, labels: Record<string, string> = {}) {
  const headers = { Authorization: `Bearer ${token()}` };
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers,
    data: {
      operation: {
        op: 'create',
        spec: {
          name,
          size: 'S',
          work_disk_gb: 50,
          image: null,
          region: null,
          from_snapshot: null,
          labels,
        },
      },
    },
  });
  const body = (await plan.json()) as { plan_id: string };
  expect(
    (
      await applyPlan(request, origin(), headers, { plan_id: body.plan_id })
    ).ok(),
  ).toBe(true);
}

async function removeBox(request: APIRequestContext, name: string) {
  const headers = { Authorization: `Bearer ${token()}` };
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers,
    data: { operation: { op: 'destroy', name, final_snapshot: false } },
  });
  const body = (await plan.json()) as { plan_id: string };
  await applyPlan(request, origin(), headers, { plan_id: body.plan_id, confirm_name: name });
}

/** A running box of this test's own, destroyed when the test ends, whatever happened in it. */
async function withBox(request: APIRequestContext, name: string, labels: Record<string, string>, body: () => Promise<void>) {
  await makeBox(request, name, labels);
  try {
    await body();
  } finally {
    await removeBox(request, name);
  }
}

/** Axe on the sheet only: the box page behind it has its own checks, and its tab strip is not this change. */
async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function openUpgrade(page: Page, name: string) {
  await open(page, `/boxes/${name}`);
  await page.getByRole('button', { name: 'More actions' }).click();
  await page.getByRole('menuitem', { name: 'Upgrade…' }).click();
  const sheet = page.getByTestId('upgrade-sheet');
  await expect(sheet.getByRole('heading', { name: `Upgrade ${name}` })).toBeVisible();
  return sheet;
}

for (const width of WIDTHS) {
  test(`upgrade at ${width}px: options, plan, apply, then the self-test`, async ({ page, request }) => {
    const name = `upg-${width}`;
    await withBox(request, name, {}, async () => {
      await page.setViewportSize({ width, height: 900 });
      const sheet = await openUpgrade(page, name);

      // what the box runs and what is newest, and the honest word about the signature
      await expect(sheet.getByTestId('image-current')).toHaveText('Not reported');
      await expect(sheet.getByTestId('image-latest')).toContainText('fake-image-2026.12.0');
      await expect(sheet.getByText('A newer image is available.')).toBeHidden(); // the current image is not known, so it is not claimed
      // the demo provider has no signed releases, so the sheet says nothing about a signature
      await expect(sheet.getByTestId('image-signature')).toHaveCount(0);
      await expect(sheet.getByText(/goes offline while the box restarts/)).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, 'upgrade-sheet');

      await sheet.getByRole('button', { name: 'Review plan' }).click();
      const plan = page.getByTestId('plan-sheet');
      await expect(plan.getByRole('heading', { name: `Upgrade ${name}` })).toBeVisible();
      const changes = plan.getByRole('list', { name: 'Changes' });
      await expect(changes.getByText(/Replace the system disk of .* the \/work disk is NOT touched/)).toBeVisible();
      await expect(changes.getByText(/Keep the \/work disk/)).toBeVisible();
      await expectNoSidewaysScroll(page);
      // nothing has happened yet: the box still reports no image
      const before = await page.request.get(`${origin()}/v1/boxes/${name}`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      expect(((await before.json()) as { spec: { image: string | null } }).spec.image).toBeNull();
      const apply = plan.getByRole('button', { name: 'Apply', exact: true });
      await expect(apply).toBeInViewport();
      if (width < 1024) expect((await apply.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(43.5);
      await apply.click();

      // the change is made, then the page waits for the box and shows its own self-test
      await expect(plan.getByText(`${name} is now running.`)).toBeVisible();
      const follow = plan.getByTestId('upgrade-followup');
      await expect(follow.getByText(/Work in progress:/)).toBeVisible();
      await expect(follow.getByText('Self-test passed.')).toBeVisible();
      await expect(follow.getByRole('list', { name: 'Checks' }).getByText('work disk mounted')).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, plan);
      await axeClean(page, 'plan-sheet');
      await plan.locator('form').getByRole('button', { name: 'Close' }).click();

      // the same again: the box now reports its image, and there is nothing newer
      const again = await openUpgrade(page, name);
      await expect(again.getByTestId('image-current')).toHaveText('fake-image-2026.12.0');
      await expect(again.getByText('Already the newest image.')).toBeVisible();
      await again.getByRole('button', { name: 'Review plan' }).click();
      await expect(page.getByTestId('plan-sheet').getByText(/Nothing to do/)).toBeVisible();
      await expect(page.getByTestId('plan-sheet').getByRole('button', { name: 'Apply', exact: true })).toHaveCount(0);
    });
  });
}

test('a failed self-test after an upgrade is shown with its failing step, never as a pass', async ({ page, request }) => {
  await withBox(request, 'upg-fail', { sim_profile: 'failing' }, async () => {
    await page.setViewportSize({ width: 1440, height: 900 });
    const sheet = await openUpgrade(page, 'upg-fail');
    await sheet.getByRole('button', { name: 'Review plan' }).click();
    const plan = page.getByTestId('plan-sheet');
    await plan.getByRole('button', { name: 'Apply', exact: true }).click();
    const follow = plan.getByTestId('upgrade-followup');
    await expect(follow.getByText('Self-test failed. See the failed step below.')).toBeVisible();
    await expect(follow.getByText('Failed step: tunnels up.')).toBeVisible();
    await expect(follow.getByText('Self-test passed.')).toHaveCount(0);
  });
});

test('an image id with a space is refused before any plan is asked for', async ({ page, request }) => {
  await withBox(request, 'upg-space', {}, async () => {
    await page.setViewportSize({ width: 390, height: 800 });
    const sheet = await openUpgrade(page, 'upg-space');
    await sheet.getByLabel('Image id (optional)').fill('fake image');
    await sheet.getByRole('button', { name: 'Review plan' }).click();
    await expect(sheet.getByRole('alert')).toContainText('An image id has no spaces.');
    await expect(page.getByTestId('plan-sheet')).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// A box whose machine was removed in the middle of an upgrade (the demo provider can be told to refuse the next
// machine), and an image whose release signature could not be verified (the demo provider can be told its newest image
// is unsigned). Both edit the demo provider's state file, which the running server reads on every request.

function statePath(): string {
  return join(dirname(process.env['OZBOX_E2E_PIDFILE'] ?? ''), 'state', 'state.json');
}

function patchState(change: Record<string, unknown>) {
  const v = JSON.parse(readFileSync(statePath(), 'utf8')) as Record<string, unknown>;
  writeFileSync(statePath(), JSON.stringify({ ...v, ...change }));
}

/** Upgrade a running box while the demo provider refuses the new machine: it ends up listed as `instance_missing`. */
async function strand(request: APIRequestContext, name: string) {
  const headers = { Authorization: `Bearer ${token()}` };
  patchState({ refuse_next_create: true });
  const plan = (await (await request.post(`${origin()}/v1/plans`, { headers, data: { operation: { op: 'upgrade', name, image: 'fake-image-2' } } })).json()) as { plan_id: string };
  const applied = await applyPlan(request, origin(), headers, { plan_id: plan.plan_id });
  expect(applied.ok(), 'the refused machine fails the upgrade').toBe(false);
  const box = (await (await request.get(`${origin()}/v1/boxes/${name}`, { headers })).json()) as { state: string };
  expect(box.state).toBe('instance_missing');
}

for (const width of WIDTHS) {
  test(`a box with no machine at ${width}px: the hint, one primary action, nothing else, then finishing`, async ({ page, request }) => {
    const name = `miss-${width}`;
    await withBox(request, name, {}, async () => {
      await strand(request, name);
      await page.setViewportSize({ width, height: 900 });

      // the list says so, and offers the one thing that works
      await open(page, '/boxes');
      // phones show cards and wider windows a table: the visible one is the one a person sees
      await expect(page.locator('[data-testid="missing-note"]:visible').filter({ hasText: 'The machine is missing and /work is kept. Finish the upgrade.' })).toHaveCount(1);
      await expectNoSidewaysScroll(page);

      await open(page, `/boxes/${name}`);
      await expect(page.getByText('Machine missing').first()).toBeVisible();
      await expect(page.getByTestId('missing-hint')).toHaveText('The machine is missing and /work is kept. Finish the upgrade.');
      const finish = page.getByRole('button', { name: 'Finish the upgrade' });
      await expect(finish).toBeInViewport();
      await expect(page.getByRole('button', { name: 'Destroy…' })).toBeVisible();
      // every other action is gone
      for (const gone of ['Pause', 'Resume', 'More actions']) await expect(page.getByRole('button', { name: gone })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Open IDE' })).toHaveCount(0);
      await expectNoSidewaysScroll(page);
      if (width < 1024) {
        for (const b of [finish, page.getByRole('button', { name: 'Destroy…' })]) expect((await b.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(43.5);
      }
      const r = await axeScan(page, '[data-testid="missing-hint"]');
      expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);

      // the row menu offers only Open, Finish and Destroy
      await open(page, '/boxes');
      await page.locator(`button[aria-label="Actions for ${name}"]:visible`).click();
      await expect(page.getByRole('menuitem', { name: 'Finish upgrade…' })).toBeVisible({ timeout: 15_000 });
      for (const gone of ['Pause', 'Resume', 'Snapshot', 'Resize…', 'Upgrade…']) await expect(page.getByRole('menuitem', { name: gone, exact: true })).toHaveCount(0);
      await page.keyboard.press('Escape');

      // finishing: the sheet is in finish mode and defaults to the image the upgrade was going to
      await open(page, `/boxes/${name}`);
      await page.getByRole('button', { name: 'Finish the upgrade' }).click();
      const sheet = page.getByTestId('upgrade-sheet');
      await expect(sheet.getByRole('heading', { name: `Finish the upgrade of ${name}` })).toBeVisible();
      await expect(sheet.getByText('Leave empty to finish with the image the upgrade was going to (fake-image-2).')).toBeVisible();
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, 'upgrade-sheet');
      await sheet.getByRole('button', { name: 'Review plan' }).click();
      const plan = page.getByTestId('plan-sheet');
      await expect(plan.getByText(/Create a new machine for .* from image fake-image-2/)).toBeVisible();
      await plan.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(plan.getByText(`${name} is now running.`)).toBeVisible();
      await plan.locator('form').getByRole('button', { name: 'Close' }).click();
      await expect(page.getByTestId('missing-hint')).toHaveCount(0);
    });
  });
}

test('a box with no machine can be destroyed from its page, with the name typed and the plan naming /work', async ({ page, request }) => {
  const name = 'miss-destroy';
  await makeBox(request, name);
  await strand(request, name);
  await page.setViewportSize({ width: 390, height: 800 });
  await open(page, `/boxes/${name}`);
  await page.getByRole('button', { name: 'Destroy…' }).click();
  const sheet = page.getByTestId('destroy-sheet');
  await expect(sheet.getByText(/The machine is already missing\. This deletes the \/work volume/)).toBeVisible();
  await sheet.getByLabel('Keep a final snapshot of /work').uncheck();
  await sheet.getByRole('button', { name: 'Review plan' }).click();
  const plan = page.getByTestId('plan-sheet');
  await expect(plan.getByText(/Delete the \/work volume of miss-destroy/)).toBeVisible();
  await expect(plan.getByText(/Ask for a final snapshot to keep a copy first/)).toBeVisible();
  const apply = plan.getByRole('button', { name: /Apply/ });
  await expect(apply).toBeDisabled();
  await plan.getByLabel(/Type .*miss-destroy/).fill(name);
  await apply.click();
  await expect(plan.getByText(`${name} was destroyed.`)).toBeVisible();
  const after = await request.get(`${origin()}/v1/boxes/${name}`, { headers: { Authorization: `Bearer ${token()}` } });
  expect(after.status()).toBe(404);
});

test('an image whose signature could not be verified is refused with its reason, and goes ahead only when asked for by name', async ({ page, request }) => {
  await withBox(request, 'upg-unsigned', {}, async () => {
    patchState({ unsigned_images: true });
    try {
      await page.setViewportSize({ width: 390, height: 900 });
      const sheet = await openUpgrade(page, 'upg-unsigned');
      await expect(sheet.getByTestId('image-signature')).toContainText('Release signature NOT verified: the sandbox\'s newest image is marked unsigned');
      await sheet.getByRole('button', { name: 'Review plan' }).click();

      // refused while planning: the sheet comes back with the reason and an override that is off
      const refused = page.getByTestId('upgrade-sheet');
      await expect(refused.getByTestId('image-refused')).toContainText('This image was refused');
      // the reason is the server's own, said in the page's words: never the command's flag
      await expect(refused.getByTestId('image-refused')).toContainText('could not be verified as a signed Oz release');
      await expect(refused.getByTestId('image-refused')).not.toContainText('--allow-unverified-image');
      const allow = refused.getByRole('checkbox', { name: 'Upgrade anyway to an unverified image' });
      await expect(allow).not.toBeChecked();
      await expect(page.getByTestId('plan-sheet')).toHaveCount(0);
      await expectTouchTargets(page, refused);
      await axeClean(page, 'upgrade-sheet');
      // asking again without the box ticked is refused again, and nothing is planned
      await refused.getByRole('button', { name: 'Review plan' }).click();
      await expect(page.getByTestId('upgrade-sheet').getByTestId('image-refused')).toBeVisible();
      await expect(page.getByTestId('plan-sheet')).toHaveCount(0);

      await page.getByTestId('upgrade-sheet').getByRole('checkbox', { name: 'Upgrade anyway to an unverified image' }).check();
      await page.getByTestId('upgrade-sheet').getByRole('button', { name: 'Review plan' }).click();
      const plan = page.getByTestId('plan-sheet');
      await expect(plan.getByText(/WARNING/)).toBeVisible();
      await expect(plan.getByRole('button', { name: 'Apply', exact: true })).toBeVisible();
    } finally {
      patchState({ unsigned_images: false });
    }
  });
});
