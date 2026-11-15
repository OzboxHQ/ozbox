import { expect, type Page } from '@playwright/test';

import { expectNoSidewaysScroll } from './fixtures';

/** What a page must never show a person: a value that was never computed, spelled out as text. */
const LEAKS = /\b(undefined|NaN)\b|\[object Object\]/;

/** Waits until no skeleton is left, or fails: a page that never stops loading hides an error behind a placeholder. */
export async function expectSettled(page: Page, what: string): Promise<void> {
  await expect
    .poll(async () => page.locator('main .animate-pulse, [aria-busy="true"]').count(), { message: `${what} never stopped loading`, timeout: 12_000 })
    .toBe(0);
}

/**
 * The honesty contract of every page (G7, X3), at the width the page is open at:
 * - it shows something, not a blank main area;
 * - it leaks no `undefined`, `NaN` or `[object Object]` where a value should be;
 * - it does not scroll sideways;
 * - it says whether its data is made up (the demo banner) or says nothing of the kind, as `demo` says.
 */
export async function expectHonestPage(page: Page, what: string, opts: { demo: boolean }): Promise<void> {
  const main = page.locator('#main');
  await expect(main, `${what}: no main area`).toBeVisible();
  await expectSettled(page, what);
  const text = (await main.innerText()).trim();
  expect(text.length, `${what}: the page is blank`).toBeGreaterThan(8);
  const leak = LEAKS.exec(text);
  expect(leak, `${what}: shows "${leak?.[0] ?? ''}"`).toBeNull();
  await expectNoSidewaysScroll(page);
  const banner = page.getByTestId('demo-banner');
  if (opts.demo) {
    await expect(banner, `${what}: demo data with no banner`).toBeVisible();
    await expect(page.getByTestId('fleet-not-connected'), `${what}: a demo is not "not connected"`).toHaveCount(0);
  } else {
    await expect(banner, `${what}: real data under a demo banner`).toHaveCount(0);
  }
}
