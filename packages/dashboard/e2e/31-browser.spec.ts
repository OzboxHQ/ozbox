
import { expect, test, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The Browser page on the demo provider: the empty state, the settings round trip (reloaded to prove it was kept), and the
// open sheet. The live leg (a real Chromium on this machine, the take-over and the replay) runs only where one is installed and
// OZBOX_E2E_BROWSER=1 says so; CI's browser-e2e job covers the worker itself against the local test site.

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

for (const width of WIDTHS) {
  test(`browser page at ${width}px: nothing open, settings are kept, the open sheet fits`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/browser');
    await expect(page.getByRole('heading', { name: 'Browser', level: 1 })).toBeVisible();
    await expect(page.getByText('No browser is open')).toBeVisible();
    await expectNoSidewaysScroll(page);
    await axeClean(page, 'main');

    // settings: change a limit, save, reload the page, and it is still there
    await page.getByRole('button', { name: 'Browsing settings' }).click();
    const sheet = page.getByTestId('browser-settings-sheet');
    await expect(sheet).toBeVisible();
    const minutes = sheet.getByLabel('Most minutes in one task');
    await minutes.fill(String(40 + (width % 7)));
    await sheet.getByRole('button', { name: 'Save settings' }).click();
    await expect(page.getByText('Settings saved.')).toBeVisible();
    await page.reload();
    await page.getByRole('button', { name: 'Browsing settings' }).click();
    await expect(page.getByTestId('browser-settings-sheet').getByLabel('Most minutes in one task')).toHaveValue(String(40 + (width % 7)));
    await page.keyboard.press('Escape');

    await page.getByRole('button', { name: 'Open a browser' }).click();
    const opener = page.getByTestId('browser-open-sheet');
    await expect(opener).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, opener);
    await axeClean(page, '[data-testid="browser-open-sheet"]');
  });
}

test('browser page: a real browser can be opened, taken over, handed back, closed and replayed', async ({ page }) => {
  test.skip(process.env['OZBOX_E2E_BROWSER'] !== '1', 'needs a Chromium on this machine (OZBOX_E2E_BROWSER=1)');
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, '/browser');
  await page.getByRole('button', { name: 'Open a browser' }).click();
  await page.getByTestId('browser-open-sheet').getByRole('button', { name: 'Open', exact: true }).click();
  const live = page.getByTestId('browser-live-sheet');
  await expect(live).toBeVisible({ timeout: 60_000 });
  await expect(live.getByTestId('browser-control')).toHaveAttribute('data-control', 'agent', { timeout: 30_000 });
  await live.getByRole('button', { name: 'Take over' }).click();
  await expect(live.getByTestId('browser-control')).toHaveAttribute('data-control', 'person');
  await live.getByRole('button', { name: 'Hand back' }).click();
  await expect(live.getByTestId('browser-control')).toHaveAttribute('data-control', 'agent');
  await page.keyboard.press('Escape');
  await page.getByTestId('browser-live-list').getByRole('button', { name: 'Close' }).first().click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Close browser' }).click();
  await expect(page.getByTestId('browser-recordings').getByTestId('browser-session').first()).toBeVisible({ timeout: 30_000 });
  await page.getByTestId('browser-recordings').getByRole('button', { name: 'Replay' }).first().click();
  await expect(page.getByTestId('browser-replay-sheet')).toBeVisible();
});
