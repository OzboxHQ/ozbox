import { expect, test } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

test('fleet cards render with simulated bars and cost as a dash', async ({ page }) => {
  await open(page);
  await expect(page.getByRole('heading', { name: 'Fleet', level: 1 })).toBeVisible();
  const cards = page.getByRole('list', { name: 'Boxes' }).getByRole('listitem');
  await expect(cards).toHaveCount(4);
  const alpha = cards.filter({ hasText: 'alpha' });
  await expect(alpha.getByText('Simulated')).toBeVisible();
  await expect(alpha.getByRole('progressbar', { name: 'CPU' })).toBeVisible();
  await expect(alpha.getByText('—').first()).toBeVisible();
  // the access token is gone from the address bar
  expect(page.url()).not.toContain('token');
});

test('a card opens the box page', async ({ page }) => {
  await open(page);
  await page.getByRole('link', { name: 'charlie' }).first().click();
  await expect(page.getByRole('heading', { name: 'charlie', level: 1 })).toBeVisible();
});

test('no serious accessibility violations on the fleet page', async ({ page }) => {
  await open(page);
  await expect(page.getByRole('list', { name: 'Boxes' })).toBeVisible();
  const r = await axeScan(page);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
});

for (const width of WIDTHS) {
  test(`fleet and boxes at ${width}px: no sideways scroll${width < 1024 ? ', 44px targets' : ''}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ['', '/boxes']) {
      await open(page, path);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      await page.waitForTimeout(300);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('body'));
    }
  });
}
