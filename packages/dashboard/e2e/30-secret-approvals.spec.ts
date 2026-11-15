import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';
import { callSocket, startSecretsService } from './secrets-service-fixture';

// Settings, Secret approvals, against a real secrets service on temporary sockets and a dashboard behind a sign-in with a
// virtual authenticator. It owns both (its own sockets, its own port, its own state), so it depends on no other spec's
// boxes. The values imported here are fake.

test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let service: Awaited<ReturnType<typeof startSecretsService>>;
let page: Page;
let code = '';

test.beforeAll(async ({ browser }) => {
  service = await startSecretsService();
  // a long step-up window: the lapse of one is proved in 07-auth and in the server's own tests, and here it would make the
  // steps depend on how long the others took
  server = await startAuthServer(4190, ['alpha'], 5, undefined, service.env, undefined, service.setupCode);
  const ctx = await browser.newContext();
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: server.origin });
  page = await ctx.newPage();
  await addVirtualAuthenticator(page);
});

test.afterAll(async () => {
  await server?.stop();
  service?.stop();
});

const importReq = (approval: string) => ({
  op: 'import',
  project: 'web',
  env: 'staging',
  approval,
  lines: [{ name: 'API_KEY', value: 'PLAYWRIGHT_SENTINEL_APPROVAL_VALUE' }],
});

test('the section is reachable, says no second factor is recorded yet, and has no code to show', async () => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
  await page.goto(`${server.origin}/settings/secret-approvals`);
  await expect(page.getByTestId('secret-approvals-section')).toBeVisible();
  await expect(page.getByTestId('approval-recent-empty')).toBeVisible();
  await expect(page.getByTestId('approval-code')).toHaveCount(0);
});

test('a fresh passkey makes a code that is shown once, with what it is for and when it ends, and can be copied', async () => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${server.origin}/settings/secret-approvals`);
  await page.getByLabel('Project').fill('web');
  await page.getByLabel('Environment').fill('staging');
  await page.getByTestId('approval-create').click();
  const sheet = page.getByTestId('approval-sheet');
  await expect(sheet).toBeVisible();
  const text = (await sheet.getByTestId('approval-code').textContent()) ?? '';
  expect(text).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/);
  code = text;
  await expect(sheet.getByTestId('approval-for')).toContainText('Import keys');
  await expect(sheet.getByTestId('approval-for')).toContainText('web / staging');
  await expect(sheet.getByTestId('approval-expiry')).toHaveText(/^[0-4]:[0-5]\d$/);
  await sheet.getByTestId('approval-copy').click();
  await expect(page.getByText('Code copied').first()).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(code);
  await sheet.getByTestId('approval-done').click();
  await expect(sheet).toBeHidden();
  // never shown again: not on the page, and a reload finds nothing to ask for it with
  expect(await page.content()).not.toContain(code);
  await page.reload();
  await expect(page.getByTestId('approval-recent')).toBeVisible();
  expect(await page.content()).not.toContain(code);
});

// An import is no longer handed to the import socket: it arrives sealed on the ingress route from the owner's computer, and
// what the service does with it is proved in the Rust tests, not here: `secrets_service` (`with_a_second_factor_enrolled_a_key_
// import_and_a_declaration_need_an_approval_that_is_good_once`: refused without an approval, spent once with one),
// `the_import_socket_refuses_an_import_with_or_without_an_approval`, and `secrets_ingress` (a sealed request is opened,
// used once and only inside its window). So this spec asserts the refusal on the old route and that the page shows the
// approval as made and not used, and never a value or a code.
test('the import socket refuses an import, and the list shows the approval as made and not used', async () => {
  for (const approval of ['', code]) {
    const r = await callSocket(service.importSocket, importReq(approval));
    expect(r.ok).toBe(false);
    expect(r.error).toContain('not allowed on this socket');
  }
  await page.goto(`${server.origin}/settings/secret-approvals`);
  const rows = page.getByTestId('approval-recent').getByRole('row');
  await expect(page.getByTestId('secrets-enrolment')).toContainText('need an approval');
  await expect(rows.filter({ hasText: 'Made' })).toHaveCount(1);
  await expect(rows.filter({ hasText: 'Used' })).toHaveCount(0);
  // names and how, never a value or a code
  const html = await page.content();
  expect(html).not.toContain('PLAYWRIGHT_SENTINEL');
  expect(html).not.toContain(code);
});

test('a project that is not a name is refused here before anything is asked of the passkey', async () => {
  await page.goto(`${server.origin}/settings/secret-approvals`);
  await page.getByLabel('Project').fill('Not A Name');
  await page.getByLabel('Environment').fill('staging');
  await page.getByTestId('approval-create').click();
  await expect(page.getByRole('alert').first()).toContainText('lowercase letters');
  await expect(page.getByTestId('approval-sheet')).toHaveCount(0);
  await expect(page.getByTestId('step-up')).toHaveCount(0);
  // a scope with no project needs none: the form changes with the scope
  await page.getByTestId('approval-scope').click();
  await page.getByRole('option', { name: 'A tunnel token' }).click();
  await expect(page.getByLabel('Project')).toHaveCount(0);
  await expect(page.getByLabel('Which tunnel')).toBeVisible();
  // loosening a box's own guard is bound to the change: its code from the plan, checked here first
  await page.getByTestId('approval-scope').click();
  await page.getByRole('option', { name: "Loosening a box's own guard" }).click();
  await expect(page.getByLabel('Which guard')).toBeVisible();
  await page.getByLabel('Change code').fill('not-a-digest');
  await page.getByTestId('approval-create').click();
  await expect(page.getByRole('alert').first()).toContainText('change code');
  await expect(page.getByTestId('step-up')).toHaveCount(0);
});

for (const w of WIDTHS) {
  test(`at ${w}px the page fits, the form and the sheet are reachable and every control is a touch target`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${server.origin}/settings/secret-approvals`);
    await expect(page.getByTestId('approval-create')).toBeVisible();
    // text wraps differently once the webfont is in, which moves the button: measure after the fonts settle
    await page.evaluate(() => document.fonts.ready);
    await expectNoSidewaysScroll(page);
    await expect(page.getByTestId('approval-create')).toBeInViewport({ ratio: 0 });
    if (w < 1024) await expectTouchTargets(page, page.getByRole('main'));
    await page.getByLabel('Project').fill('web');
    await page.getByLabel('Environment').fill('staging');
    await page.getByTestId('approval-create').click();
    const sheet = page.getByTestId('approval-sheet');
    await expect(sheet).toBeVisible({ timeout: 30_000 });
    // the code and both actions are inside the window without scrolling the page
    await expect(sheet.getByTestId('approval-code')).toBeInViewport();
    await expect(sheet.getByTestId('approval-done')).toBeInViewport();
    await expectNoSidewaysScroll(page);
    if (w < 1024) await expectTouchTargets(page, sheet);
    await sheet.getByTestId('approval-done').click();
    await expect(sheet).toBeHidden();
  });
}
