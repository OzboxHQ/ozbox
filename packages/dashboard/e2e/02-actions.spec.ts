import { expect, test } from '@playwright/test';

import { open } from './fixtures';

test('pause goes plan, confirm, applied', async ({ page }) => {
  await open(page, '/boxes/alpha');
  await page.getByRole('button', { name: 'Pause' }).click();
  const sheet = page.getByTestId('plan-sheet');
  await expect(sheet.getByRole('heading', { name: 'Pause alpha' })).toBeVisible();
  // the plan lists every change with its risk, and nothing has happened yet
  await expect(sheet.getByRole('list', { name: 'Changes' }).getByRole('listitem').first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Resume' })).toHaveCount(0);
  await sheet.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(sheet.getByText('alpha is now paused.')).toBeVisible();
  await sheet.locator('form').getByRole('button', { name: 'Close' }).click();
  await expect(page.getByRole('button', { name: 'Resume' })).toBeVisible();
});

test('destroy needs the typed name', async ({ page }) => {
  await open(page, '/boxes/bravo');
  await page.getByRole('button', { name: 'More actions' }).click();
  await page.getByRole('menuitem', { name: 'Destroy…' }).click();
  await page.getByTestId('destroy-sheet').getByRole('button', { name: 'Review plan' }).click();
  const sheet = page.getByTestId('plan-sheet');
  const apply = sheet.getByRole('button', { name: /Apply, cannot be undone/ });
  await expect(apply).toBeDisabled();
  await sheet.getByLabel(/Type bravo to confirm/).fill('brav');
  await expect(apply).toBeDisabled();
  await sheet.getByLabel(/Type bravo to confirm/).fill('bravo');
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect(sheet.getByText('bravo was destroyed.')).toBeVisible();
  await sheet.locator('form').getByRole('button', { name: 'Close' }).click();
  await expect(page).toHaveURL(/\/boxes$/);
  await expect(page.getByRole('link', { name: 'bravo' })).toHaveCount(0);
});

test('resize is a form that validates, then a plan', async ({ page }) => {
  await open(page, '/boxes/charlie');
  await page.getByRole('button', { name: 'More actions' }).click();
  await page.getByRole('menuitem', { name: 'Resize…' }).click();
  const form = page.getByTestId('resize-sheet');
  await form.getByRole('button', { name: 'Review plan' }).click();
  await expect(form.getByRole('alert')).toBeVisible();
});

test('on a phone the plan is a bottom sheet with Apply visible in the footer', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await open(page, '/boxes/charlie');
  await page.getByRole('button', { name: 'Pause' }).click();
  const sheet = page.getByTestId('plan-sheet');
  await expect(sheet).toBeVisible();
  // the sheet slides in and grows when the plan arrives: wait for it to settle against the bottom edge
  await expect
    .poll(async () => {
      const b = await sheet.boundingBox();
      return b ? [Math.round(b.x), Math.round(b.width), Math.round(b.y + b.height)] : null;
    })
    .toEqual([0, 390, 800]);
  const apply = sheet.getByRole('button', { name: 'Apply', exact: true });
  await expect(apply).toBeInViewport();
  const a = await apply.boundingBox();
  expect(a?.height ?? 0).toBeGreaterThanOrEqual(43.5);
});
