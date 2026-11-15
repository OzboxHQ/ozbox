import { expect, test } from '@playwright/test';

import { expectNoSidewaysScroll, open } from './fixtures';

// The simulated provider is a demo: every page says so, so made-up boxes are never taken for a real fleet.
const WIDTHS = [390, 820, 1440] as const;

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;

test('the server marks the simulated provider as demo data', async ({ request }) => {
  const r = await request.get(`${origin()}/v1/info`, { headers: { Authorization: `Bearer ${token()}` } });
  const info = (await r.json()) as { fleet: { mode: string; demo: boolean } };
  expect(info.fleet.mode).toBe('demo');
  expect(info.fleet.demo).toBe(true);
});

for (const width of WIDTHS) {
  test(`demo banner at ${width}px: on every page, in view, no sideways scroll`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ['', '/boxes', '/costs/bill', '/tasks']) {
      await open(page, path);
      const banner = page.getByTestId('demo-banner');
      await expect(banner).toBeVisible();
      await expect(banner).toContainText('Demo data');
      await expect(banner).toContainText('Made-up');
      // the banner is inside the first screen, not below the fold
      const box = await banner.boundingBox();
      expect(box && box.y + box.height <= 900).toBeTruthy();
      await expectNoSidewaysScroll(page);
      // a demo is never described as a fleet that is not connected
      await expect(page.getByTestId('fleet-not-connected')).toHaveCount(0);
    }
  });
}
