import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';

// The browser terminal against the demo box (a real shell on this computer), signed in, at the four widths.
test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(4176, ['dev'], 5);
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
});

test.afterAll(() => server.stop());

for (const w of WIDTHS) {
  test(`typing in the terminal echoes through the box at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(server.origin + '/boxes/dev/terminal');
    await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
    await expectNoSidewaysScroll(page);
    await page.getByTestId('terminal-screen').click();
    await page.keyboard.type(`echo ozbox-$((20+22))-${w}`);
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('terminal-screen')).toContainText(`ozbox-42-${w}`, { timeout: 10_000 });
    if (w < 1024) {
      // the key bar is there for a phone or tablet, with thumb-sized buttons
      await expect(page.getByTestId('terminal-keys')).toBeVisible();
      await expectTouchTargets(page, page.getByTestId('terminal'));
      await page.getByRole('button', { name: 'Ctrl' }).click();
      await expect(page.getByRole('button', { name: 'Ctrl' })).toHaveAttribute('aria-pressed', 'true');
    } else {
      await expect(page.getByTestId('terminal-keys')).toBeHidden();
    }
  });
}

test('the shell ending shows it, and Reconnect opens a new one', async () => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(server.origin + '/boxes/dev/terminal');
  await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
  await page.getByTestId('terminal-screen').click();
  await page.keyboard.type('exit');
  await page.keyboard.press('Enter');
  await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'ended', { timeout: 10_000 });
  await page.getByRole('button', { name: 'Reconnect' }).click();
  await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
});

test('a terminal needs the sign-in: without the cookie the API refuses', async ({ request }) => {
  const res = await request.post(server.origin + '/v1/boxes/dev/terminal', { data: {}, headers: { Origin: server.origin } });
  expect(res.status()).toBe(401);
});
