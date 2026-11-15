import { expect, test } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

test('the command palette finds an action, and the action still shows its plan first', async ({ page }) => {
  await open(page);
  await expect(page.getByRole('heading', { name: 'Fleet', level: 1 })).toBeVisible();
  await page.keyboard.press('Control+k');
  const palette = page.getByTestId('palette');
  await expect(palette).toBeVisible();
  await palette.getByRole('combobox').fill('snapshot charlie');
  await palette.getByRole('combobox').press('Enter');
  const sheet = page.getByTestId('plan-sheet');
  await expect(sheet.getByRole('heading', { name: 'Snapshot charlie' })).toBeVisible();
  await sheet.getByRole('button', { name: 'Cancel' }).click();
  // the cancelled plan is waiting in the approvals inbox and in the activity list, and nothing changed
  await open(page, '/approvals');
  await expect(page.getByRole('list', { name: 'Pending plans' }).getByText('charlie').first()).toBeVisible();
  await open(page, '/activity');
  await expect(page.getByText('plan snapshot').locator('visible=true').first()).toBeVisible();
  await expect(page.getByText('proposed, nothing changed').locator('visible=true').first()).toBeVisible();
});

test('a high-risk plan in approvals is marked as needing a passkey', async ({ page }) => {
  await open(page, '/boxes/charlie');
  await page.getByRole('button', { name: 'More actions' }).click();
  await page.getByRole('menuitem', { name: 'Destroy…' }).click();
  await page.getByTestId('destroy-sheet').getByRole('button', { name: 'Review plan' }).click();
  await page.getByTestId('plan-sheet').getByRole('button', { name: 'Cancel' }).click();
  await open(page, '/approvals');
  await expect(page.getByText('Needs passkey').first()).toBeVisible();
});

test('the old Runs address lands on Tasks, which is the one place for a run', async ({ page }) => {
  await open(page, '/runs');
  await expect(page).toHaveURL(/\/tasks(\?|#|$)/);
  await expect(page.getByRole('heading', { name: 'Tasks', level: 1 })).toBeVisible();
  await expect(page.getByText('Simulated').first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Runs', exact: true })).toHaveCount(0);
});

test('activity exports a CSV', async ({ page }) => {
  await open(page, '/activity');
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export CSV' }).click();
  expect((await download).suggestedFilename()).toBe('ozbox-activity.csv');
});

test('budget settings validate in a sheet', async ({ page }) => {
  await open(page, '/settings/budgets');
  await page.getByRole('button', { name: 'Edit' }).click();
  const sheet = page.getByTestId('budget-sheet');
  await sheet.getByLabel('Monthly budget in USD (optional)').fill('lots');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert')).toBeVisible();
});

test('without a domain the IDE button is off and says why', async ({ page }) => {
  await open(page, '/boxes/charlie');
  await expect(page.getByRole('button', { name: 'Open IDE' })).toBeDisabled();
  await expect(page.getByText(/No domain is configured/)).toBeVisible();
});

test('Open in… is off with its reason until the box has a tunnel', async ({ page }) => {
  await open(page, '/boxes/charlie');
  await expect(page.getByRole('button', { name: 'Open in…' })).toBeDisabled();
  await expect(page.getByText('No SSH route yet: this box needs a configured domain and tunnel.')).toBeVisible();
});

test('navigation: a menu sheet on a phone, an icon rail from tablet width', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await open(page);
  await expect(page.getByRole('complementary', { name: 'Primary' })).toBeHidden();
  await page.getByRole('button', { name: 'Open menu' }).click();
  const menu = page.getByRole('dialog');
  // a bottom sheet: it slides in, so wait for it to settle against the bottom edge
  await expect
    .poll(async () => {
      const b = await menu.boundingBox();
      return b ? Math.round(b.y + b.height) : null;
    })
    .toBe(800);
  // Runs is part of Tasks now: the menu has no Runs entry, and Tasks opens from it
  await expect(menu.getByRole('link', { name: 'Runs', exact: true })).toHaveCount(0);
  await menu.getByRole('link', { name: 'Tasks' }).click();
  await expect(page.getByRole('heading', { name: 'Tasks', level: 1 })).toBeVisible();
  await page.setViewportSize({ width: 820, height: 900 });
  await expect(page.getByRole('complementary', { name: 'Primary' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open menu' })).toBeHidden();
});

test('the app is installable and its worker never caches API data', async ({ page, request }) => {
  await open(page);
  const origin = new URL(page.url()).origin;
  const manifest = await request.get(`${origin}/manifest.webmanifest`);
  expect(manifest.ok()).toBe(true);
  const sw = await request.get(`${origin}/sw.js`);
  expect(sw.headers()['cache-control']).toContain('no-store');
  expect(await sw.text()).toContain("startsWith('/v1/')");
});

test('a change in one tab shows up in another without a reload', async ({ page, context }) => {
  const other = await context.newPage();
  await open(other, '/boxes');
  await expect(other.getByRole('table', { name: 'Boxes' }).getByRole('row', { name: /delta/ }).getByText('Paused')).toBeVisible();
  await open(page, '/boxes/delta');
  await page.getByRole('button', { name: 'Resume' }).click();
  await page.getByTestId('plan-sheet').getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(page.getByTestId('plan-sheet').getByText('delta is now running.')).toBeVisible();
  await expect(other.getByRole('table', { name: 'Boxes' }).getByRole('row', { name: /delta/ }).getByText('Running')).toBeVisible({ timeout: 8000 });
});

for (const width of WIDTHS) {
  test(`every page at ${width}px: no sideways scroll${width < 1024 ? ', 44px targets' : ''}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ['/tasks', '/approvals', '/usage', '/activity', '/settings', '/settings/providers', '/settings/budgets', '/settings/defaults', '/settings/members', '/boxes/charlie', '/boxes']) {
      await open(page, path);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      await page.waitForTimeout(300);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('main'));
    }
  });
}
