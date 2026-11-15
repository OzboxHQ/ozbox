import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// G7 R1, tier B: the Fleet, Boxes and Box pages of a REAL this-box dashboard (a real ozboxd, a real `ozbox serve`, signed in).
// Each page asserts its honesty state: the fleet is "not connected", cost says so, a box that cannot report usage is named
// with the reason (the daemon samples /proc, which only Linux has), and nothing is made up.
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;
const live = process.platform === 'linux';

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4183, signIn: true });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: s.origin, code: s.code, stop: async () => undefined });
});
test.afterAll(async () => {
  await s?.stop();
});

async function expectBoxHonesty(): Promise<void> {
  if (live) {
    await expect(page.getByTestId('unreachable-note')).toHaveCount(0);
  } else {
    // no /proc here: the box is named as not reachable, with the server's reason, never shown with empty bars
    await expect(page.getByTestId('unreachable-note')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('unreachable-note')).toContainText(s.box);
  }
}

for (const w of WIDTHS) {
  test(`Fleet on a box says the fleet is not connected and shows its own box at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/`);
    await expect(page.getByRole('heading', { name: 'Fleet', level: 1 })).toBeVisible();
    await expect(page.getByTestId('fleet-not-connected')).toBeVisible();
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expect(page.getByRole('link', { name: s.box }).first()).toBeVisible({ timeout: 15_000 });
    // cost is not a made-up figure and not a bare dash: it says why
    await expect(page.getByText('Cost this month').locator('xpath=..')).toContainText('Fleet not connected');
    await expect(page.getByTestId('cost-error')).toHaveCount(0);
    await expectBoxHonesty();
    await expectNoSidewaysScroll(page);
  });

  test(`Needs you agrees with the box's own self-test at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    const r = await page.request.get(`${s.origin}/v1/boxes/${s.box}/selftest`);
    await page.goto(`${s.origin}/`);
    const needs = page.getByRole('region', { name: 'Needs you' });
    await expect(needs).toBeVisible();
    if (r.status() !== 200) {
      // the box could not be asked: no self-test result is claimed either way
      await expect(needs).not.toContainText('self-test failed');
      return;
    }
    const failing = ((await r.json()) as { result: { checks: { outcome: string }[] } }).result.checks.some((c) => c.outcome === 'fail');
    if (failing) await expect(needs).toContainText('the self-test failed', { timeout: 20_000 });
    else await expect(needs).not.toContainText('self-test failed');
  });

  test(`Boxes has a Create button that says the fleet is not connected at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes`);
    const create = page.getByTestId('create-box-button');
    await expect(create).toBeVisible();
    if (w < 1024) {
      const b = await create.boundingBox();
      expect(b?.height ?? 0, 'touch target').toBeGreaterThanOrEqual(43.5);
    }
    await expect(page.getByRole('link', { name: s.box }).first()).toBeVisible({ timeout: 15_000 });
    await create.click();
    await expect(page.getByTestId('fleet-not-connected-sheet')).toBeVisible();
    await page.keyboard.press('Escape');
    await expectBoxHonesty();
    await expectNoSidewaysScroll(page);
  });

  test(`Box shows live usage or says why not, and its cost says not connected at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes/${s.box}`);
    await expect(page.getByRole('heading', { name: s.box, level: 1 })).toBeVisible();
    await expect(page.getByText('Cost this month').locator('xpath=..')).toContainText('Fleet not connected');
    if (live) {
      await expect(page.getByLabel('CPU').first()).toBeVisible({ timeout: 20_000 });
      await expect(page.getByText('needs the box agent')).toHaveCount(0);
    } else {
      await expect(page.getByText('Usage could not be read')).toBeVisible({ timeout: 20_000 });
    }
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });
}

test('a GET of the box SSH details never writes a key', async () => {
  const r = await page.request.get(`${s.origin}/v1/boxes/${s.box}/ssh`);
  // a box with no tunnel domain has no route (409); either way nothing was written to the SSH folder
  expect([200, 409]).toContain(r.status());
  expect(existsSync(join(s.dir, '.ssh', 'ozbox_ed25519'))).toBe(false);
});
