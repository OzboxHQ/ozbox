import { expect, test, type Page } from '@playwright/test';

import { expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// ADR 0040: a box's dashboard that manages the fleet says, on every page that shows the fleet, what each change needs (a
// change window from your own computer, then your passkey for that exact plan). Nothing in a released build turns this mode on
// yet (the credential holder is not built), so the server's answer is stood in for here; the plan-then-apply flow with the
// passkey is covered by the unit tests of `applyWithGates` and the server's own end-to-end test.
const WIDTHS = [390, 820, 1440] as const;

async function asManaged(page: Page): Promise<void> {
  await page.route('**/v1/info', async (route) => {
    const res = await route.fetch();
    const info = (await res.json()) as Record<string, unknown>;
    await route.fulfill({ response: res, json: { ...info, fleet: { mode: 'managed', connected: true, demo: false, changes_need: ['change_window', 'owner_passkey'] } } });
  });
}

for (const width of WIDTHS) {
  test(`managed fleet notice at ${width}px: on the fleet pages, in view, no sideways scroll`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await asManaged(page);
    for (const path of ['', '/boxes']) {
      await open(page, path);
      const notice = page.getByTestId('fleet-managed');
      await expect(notice).toBeVisible();
      await expect(notice).toContainText('Managed from this box');
      await expect(notice).toContainText('change window');
      await expect(page.getByTestId('demo-banner')).toHaveCount(0);
      await expect(page.getByTestId('fleet-not-connected')).toHaveCount(0);
      const box = await notice.boundingBox();
      expect(box && box.y + box.height <= 900).toBeTruthy();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('main'));
    }
  });
}
