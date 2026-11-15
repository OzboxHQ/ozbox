
import { expect, test } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// One-click Ollama: on a box without a GPU, Oz Box picks the model that fits and shows the plan before anything is
// fetched. This spec only reads the plan and cancels, so it changes nothing and leaves nothing for another spec.

for (const width of WIDTHS) {
  test(`local AI at ${width}px: Ollama on a box without a GPU shows a plan that fits the box before downloading`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/settings/models');
    const one = page.getByTestId('local-oneclick');
    await one.scrollIntoViewIfNeeded();
    await expect(one).toContainText('Set up Ollama on any box');
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, one);
    await one.getByRole('button', { name: 'Set up Ollama here' }).click();
    const sheet = page.getByTestId('local-plan-sheet');
    await expect(sheet).toBeVisible();
    await expect(sheet.getByTestId('local-plan-size')).toContainText('Download: about');
    await expect(sheet).toContainText('Memory: needs about');
    const r = await axeScan(page, '[data-testid="local-plan-sheet"]');
    expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
    await sheet.getByRole('button', { name: 'Cancel' }).click();
    await expect(sheet).toHaveCount(0);
  });
}
