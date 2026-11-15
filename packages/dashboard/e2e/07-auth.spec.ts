import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';

// Sign-in on a shared machine, in one real browser with a virtual authenticator. The steps depend on each other
// (the passkey made in the first is used by the later ones), so they run in order.
test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(4175, ['doomed']);
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
});

test.afterAll(() => server.stop());

test('a signed-out visitor sees the sign-in page at every width, and the API refuses them', async () => {
  for (const w of WIDTHS) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(server.origin + '/');
    await expect(page.getByRole('heading', { name: 'Sign in to Oz Box' })).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (w < 1024) await expectTouchTargets(page, page.getByRole('main'));
  }
  const res = await page.request.get(server.origin + '/v1/boxes');
  expect(res.status()).toBe(401);
  // a request from another site is refused before anything else
  const cross = await page.request.post(server.origin + '/auth/passkey/login/options', { headers: { Origin: 'https://evil.example' }, data: {} });
  expect(cross.status()).toBe(403);
});

test('the setup code enrols a first passkey and signs in', async () => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
  await expect(page.getByTestId('terminal')).toHaveCount(0);
});

test('signing out, then in again with the passkey', async () => {
  await page.getByRole('button', { name: 'Session menu' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to Oz Box' })).toBeVisible();
  expect((await page.request.get(server.origin + '/v1/boxes')).status()).toBe(401);
  await page.getByTestId('passkey-signin').click();
  await expect(page.getByRole('button', { name: 'Session menu' })).toBeVisible();
});

test('the account page lists the passkey and where you are signed in', async () => {
  await page.goto(server.origin + '/account');
  await expect(page.getByRole('heading', { name: 'Account' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Passkeys' })).toBeVisible();
  await expect(page.getByText('Passkey 1')).toBeVisible();
  await expect(page.getByText('This browser')).toBeVisible();
  await expectNoSidewaysScroll(page);
});

test('a change without the dashboard’s CSRF token is refused', async () => {
  const status = await page.evaluate(() => fetch('/v1/plans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then((r) => r.status));
  expect(status).toBe(403);
});

test('destroying a box asks for the passkey again once the confirmation has lapsed', async () => {
  await page.waitForTimeout(4000); // the step-up window in this setup is three seconds
  await page.goto(server.origin + '/boxes/doomed');
  await page.getByRole('button', { name: 'More actions' }).click();
  await page.getByRole('menuitem', { name: 'Destroy…' }).click();
  await page.getByTestId('destroy-sheet').getByRole('button', { name: 'Review plan' }).click();
  const sheet = page.getByTestId('plan-sheet');
  await sheet.getByLabel(/Type doomed to confirm/).fill('doomed');
  await sheet.getByRole('button', { name: /Apply, cannot be undone/ }).click();
  const stepUp = page.getByTestId('step-up');
  await expect(stepUp.getByRole('heading', { name: 'Confirm it is you' })).toBeVisible();
  await page.getByTestId('step-up-confirm').click();
  await expect(sheet.getByText('doomed was destroyed.')).toBeVisible();
});
