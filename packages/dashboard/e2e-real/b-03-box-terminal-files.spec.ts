import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// Tier B: Files and the Terminal of a this-box dashboard reach the REAL daemon, not a demo. The terminal's shell starts in the
// daemon's /work (a made-up one would start in a temp folder named ozbox-demo-...), and what the dashboard writes is on the
// box's disk where the daemon's own file service put it.
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4182, signIn: true });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: s.origin, code: s.code, stop: async () => undefined });
});
test.afterAll(async () => {
  await s?.stop();
});

for (const w of WIDTHS) {
  test(`the terminal is the box's own shell at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes/${s.box}/terminal`);
    await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
    await expectNoSidewaysScroll(page);
    await page.getByTestId('terminal-screen').click();
    await page.keyboard.type(`echo g7-$((6*7))-${w}; pwd; echo in-box-${w} > ./from-terminal-${w}.txt`);
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('terminal-screen')).toContainText(`g7-42-${w}`, { timeout: 10_000 });
    // the daemon's work folder is where the shell started, and what it wrote is on the box's disk
    await expect.poll(() => existsSync(join(s.work, `from-terminal-${w}.txt`)), { message: 'the terminal did not write into the box work folder' }).toBe(true);
    expect(readFileSync(join(s.work, `from-terminal-${w}.txt`), 'utf8').trim()).toBe(`in-box-${w}`);
    await expect(page.getByTestId('terminal-screen')).not.toContainText('ozbox-demo');
  });

  test(`files shows the box's real files and an upload lands on its disk at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes/${s.box}/files`);
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'projects', exact: true })).toBeVisible({ timeout: 15_000 });
    await expectNoSidewaysScroll(page);
    await page.getByRole('button', { name: 'projects', exact: true }).click();
    await expect(page.getByRole('button', { name: 'hello-g7.txt', exact: true })).toBeVisible();
    const name = `up-${w}.txt`;
    await page.locator('input[type="file"]').setInputFiles({ name, mimeType: 'text/plain', buffer: Buffer.from(`uploaded at ${w}\n`) });
    await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
    await expect.poll(() => existsSync(join(s.work, 'projects', name)), { message: 'the upload is not on the box disk' }).toBe(true);
    expect(readFileSync(join(s.work, 'projects', name), 'utf8')).toBe(`uploaded at ${w}\n`);
    // and no demo files are offered
    await page.goto(`${s.origin}/boxes/${s.box}/files`);
    await expect(page.getByText('welcome.txt')).toHaveCount(0);
  });
}
