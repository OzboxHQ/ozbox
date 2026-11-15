import { expect, test } from '@playwright/test';

import { WIDTHS, open } from './fixtures';
import { expectHonestPage } from './honesty';
import { ROUTE_SAMPLES } from '../src/lib/route-samples';

// X3, tier A: on the simulated provider EVERY page of the dashboard (every Route, every settings section) says its data is
// demo data, and shows no blank, loading-forever or `undefined` state. The server here is the fake one, so this proves the
// contract on the laptop's demo; `e2e-real/b-02-every-route-this-box.spec.ts` proves its other half on a real this-box server.
for (const width of WIDTHS) {
  test(`every route at ${width}px is honest demo data`, async ({ page }) => {
    test.setTimeout(240_000);
    await page.setViewportSize({ width, height: 900 });
    for (const s of ROUTE_SAMPLES) {
      const path = s.path('alpha');
      await open(page, path);
      await expectHonestPage(page, `${path} at ${width}px`, { demo: true });
    }
    expect(ROUTE_SAMPLES.length).toBeGreaterThan(28);
  });
}
