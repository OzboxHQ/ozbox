import { expect, test } from '@playwright/test';

import { expectNoSidewaysScroll, open, WIDTHS } from './fixtures';

// What this server is (`/v1/info`) decides what every page offers, so a page waits for it. One dropped request must not leave a
// half page for good: the dashboard asks again by itself, and when it still has no answer it says so and offers Try again,
// never showing the parts that depend on it as if they were allowed or denied.
const FAIL = JSON.stringify({ code: 'internal', message: 'injected info failure' });

for (const width of WIDTHS) {
  test(`one failed /v1/info is asked again by itself and the page comes up whole at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    let asked = 0;
    await page.route('**/v1/info', (route) => {
      asked += 1;
      if (asked === 1) return route.fulfill({ status: 500, contentType: 'application/json', body: FAIL });
      return route.continue();
    });
    await open(page, '/costs/bill');
    await expect(page.getByRole('heading', { name: 'Bill', level: 1 })).toBeVisible();
    // the page that waits on /v1/info gets it on the second ask, with no error shown on the way
    await expect(page.getByRole('button', { name: 'Read the bill now' })).toBeVisible({ timeout: 15_000 });
    expect(asked).toBeGreaterThanOrEqual(2);
    await expect(page.getByTestId('load-error')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });
}

test('when /v1/info keeps failing the page says so, shows nothing that depends on it, and Try again brings it back', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await page.route('**/v1/info', (route) => route.fulfill({ status: 400, contentType: 'application/json', body: FAIL }));
  await open(page, '/costs/bill');
  const error = page.getByTestId('load-error');
  await expect(error).toContainText('injected info failure');
  await expect(page.getByRole('button', { name: 'Read the bill now' })).toHaveCount(0);
  await expect(page.getByTestId('orphans-card')).toHaveCount(0);
  await page.unroute('**/v1/info');
  await error.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByTestId('load-error')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Read the bill now' })).toBeVisible();
});

test('a /v1/info that is never answered is given up on and asked again, so the page does not wait for ever', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  let asked = 0;
  await page.route('**/v1/info', (route) => {
    asked += 1;
    // the first ask is held and never answered (a lost response); later asks go through
    if (asked === 1) return undefined;
    return route.continue();
  });
  await open(page, '/costs/bill');
  await expect(page.getByRole('button', { name: 'Read the bill now' })).toBeVisible({ timeout: 20_000 });
  expect(asked).toBeGreaterThanOrEqual(2);
  await expect(page.getByTestId('load-error')).toHaveCount(0);
});
