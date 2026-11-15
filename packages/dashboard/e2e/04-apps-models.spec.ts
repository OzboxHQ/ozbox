import { expect, test, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// The secret store here is memory (OZBOX_SECRET_STORE=memory), and nothing in these tests sends a message to an
// outside service: a test alert, a Telegram pairing and a model test all reach out, so they are only checked up to
// the point before the request leaves.

async function waitSheetClosed(page: Page, testid: string) {
  await expect(page.getByTestId(testid)).toBeHidden();
}

test('Apps and alerts lists every channel and keeps secrets write-only', async ({ page }) => {
  await open(page, '/settings/apps');
  await expect(page.getByRole('heading', { name: 'Alert channels' })).toBeVisible();
  for (const id of ['email', 'telegram', 'slack', 'webhooks']) await expect(page.getByTestId(`app-${id}`)).toBeVisible();
  await expect(page.getByTestId('apps-note')).toContainText('never shown again');
  const email = page.getByTestId('app-email');
  await expect(email.getByText('Not connected')).toBeVisible();
  await expect(email.getByRole('button', { name: 'Send test alert' })).toBeDisabled();

  await email.getByRole('button', { name: 'Set up' }).click();
  const sheet = page.getByTestId('email-sheet');
  await sheet.getByLabel('Send from').fill('alerts@example.com');
  await sheet.getByLabel('Send to (separate addresses with commas)').fill('not an address');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  await sheet.getByLabel('Send to (separate addresses with commas)').fill('me@example.com, you@example.com');
  const key = sheet.getByLabel('Provider API key');
  await expect(key).toHaveAttribute('type', 'password');
  await expect(key).toHaveAttribute('autocomplete', 'off');
  await key.fill('re_PLAYWRIGHT_SENTINEL');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await waitSheetClosed(page, 'email-sheet');
  await expect(email.getByText('Connected')).toBeVisible();

  // reopening shows an empty, password-typed field and says a key is saved; the value is on no page
  await email.getByRole('button', { name: 'Edit' }).click();
  await expect(sheet.getByLabel('Provider API key')).toHaveValue('');
  await expect(sheet.getByText('A key is saved.')).toBeVisible();
  await sheet.getByRole('button', { name: 'Cancel' }).click();
  expect(await page.content()).not.toContain('PLAYWRIGHT_SENTINEL');
  const u = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const token = u.hash.replace('#token=', '');
  for (const path of ['/v1/settings', '/v1/apps', '/v1/secrets', '/v1/activity']) {
    const res = await page.request.get(`${u.origin}${path}`, { headers: { Authorization: `Bearer ${token}` } });
    expect(await res.text(), path).not.toContain('PLAYWRIGHT_SENTINEL');
  }
});

test('Telegram setup is guided and pairing waits for a token', async ({ page }) => {
  await open(page, '/settings/apps');
  const tg = page.getByTestId('app-telegram');
  await expect(tg.getByText('BotFather').first()).toBeVisible();
  await expect(tg.getByRole('button', { name: 'Pair a chat' })).toBeDisabled();
  await expect(tg.getByRole('button', { name: 'Send test alert' })).toBeDisabled();
  await tg.getByRole('button', { name: 'Add bot token' }).click();
  const sheet = page.getByTestId('telegram-token-sheet');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert')).toBeVisible(); // an empty token is refused in the form
  await sheet.getByLabel('Bot token').fill('123456:FAKE-TOKEN-FOR-TESTS');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await waitSheetClosed(page, 'telegram-token-sheet');
  await expect(tg.getByRole('button', { name: 'Pair a chat' })).toBeEnabled();
  await tg.getByRole('button', { name: 'Remove token' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
  await expect(tg.getByRole('button', { name: 'Add bot token' })).toBeVisible();
});

test('Slack and a signed webhook are added and removed', async ({ page }) => {
  await open(page, '/settings/apps');
  const slack = page.getByTestId('app-slack');
  await slack.getByRole('button', { name: 'Set up' }).click();
  await page.getByTestId('slack-sheet').getByLabel('Incoming webhook address').fill('https://hooks.example.com/T000/B000');
  await page.getByTestId('slack-sheet').getByRole('button', { name: 'Save' }).click();
  await waitSheetClosed(page, 'slack-sheet');
  await expect(slack.getByText('Connected')).toBeVisible();

  const hooks = page.getByTestId('app-webhooks');
  await hooks.getByRole('button', { name: 'Add webhook' }).click();
  const sheet = page.getByTestId('webhook-sheet');
  await sheet.getByLabel('Label').fill('CI hook');
  await sheet.getByLabel('Address').fill('http://insecure.example.com/x');
  await sheet.getByLabel('Signing secret').fill('short');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  await sheet.getByLabel('Address').fill('https://hooks.example.com/in');
  await sheet.getByRole('button', { name: 'Generate a secret' }).click();
  await expect(sheet.getByLabel('Signing secret')).toHaveAttribute('type', 'text'); // shown once, to copy
  await expect(sheet.getByText('Copy it now')).toBeVisible();
  await sheet.getByRole('button', { name: 'Save' }).click();
  await waitSheetClosed(page, 'webhook-sheet');
  const row = hooks.getByRole('listitem').filter({ hasText: 'CI hook' });
  await expect(row.getByText('hooks.example.com')).toBeVisible();
  await expect(row.getByText('Connected')).toBeVisible();
  await row.getByRole('button', { name: 'Remove' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
  await expect(hooks.getByText('No webhook yet.')).toBeVisible();
});

test('Models: add a provider, set defaults, and a connection test asks first', async ({ page }) => {
  await open(page, '/settings/models');
  await expect(page.getByRole('heading', { name: 'Model providers' })).toBeVisible();
  await expect(page.getByTestId('models-note')).toContainText('write-only');
  await page.getByRole('button', { name: 'Add provider' }).click();
  const sheet = page.getByTestId('provider-sheet');
  await sheet.getByLabel('Name').fill('Main');
  await sheet.getByLabel('API key').fill('sk-PLAYWRIGHT-MODEL-SENTINEL');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  const card = page.getByTestId('provider-main');
  await expect(card.getByText('Key saved')).toBeVisible();

  await page.getByTestId('model-defaults').getByRole('button', { name: 'Edit' }).click();
  const d = page.getByTestId('defaults-models-sheet');
  await d.getByLabel('Provider').first().click();
  await page.getByRole('option', { name: 'Main' }).click();
  await d.getByLabel('Model name').first().fill('some-model-1');
  await d.getByRole('button', { name: 'Save' }).click();
  await expect(d).toBeHidden();
  await expect(page.getByTestId('model-defaults').getByText('Main · some-model-1')).toBeVisible();

  // the test is explicit about cost, and cancelling sends nothing
  await card.getByRole('button', { name: 'Send a test message' }).click();
  const confirm = page.getByRole('alertdialog');
  await expect(confirm).toContainText('can cost a fraction of a cent');
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByTestId('model-test-result')).toHaveCount(0);
  expect(await page.content()).not.toContain('PLAYWRIGHT-MODEL-SENTINEL');
});

test('a local endpoint needs its own switch to use http', async ({ page }) => {
  await open(page, '/settings/models');
  await page.getByRole('button', { name: 'Add provider' }).click();
  const sheet = page.getByTestId('provider-sheet');
  await sheet.getByLabel('Provider type').click();
  await page.getByRole('option', { name: 'OpenAI-compatible endpoint' }).click();
  await sheet.getByLabel('Name').fill('Local server');
  await sheet.getByLabel('Endpoint address').fill('http://localhost:11434/v1');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toContainText('https://');
  await sheet.getByLabel('This endpoint is my own server (this computer or a private network address)').check();
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  await expect(page.getByTestId('provider-local-server').getByText('No key')).toBeVisible();
});

test('the cost estimate says what it is built from', async ({ page }) => {
  await open(page, '/usage');
  const card = page.getByTestId('cost-card');
  await expect(card).toBeVisible();
  await expect(card.getByText('(estimate)').first()).toBeVisible();
  await expect(card.getByTestId('cost-source')).not.toBeEmpty();
  await expect(card).toContainText('not the provider bill');
});

for (const width of WIDTHS) {
  test(`Apps and Models at ${width}px: no sideways scroll${width < 1024 ? ', 44px targets' : ''}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of ['/settings/apps', '/settings/models']) {
      await open(page, path);
      await expect(page.locator('main h1')).toBeVisible();
      await page.waitForTimeout(300);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('main'));
    }
    await open(page, '/settings/apps');
    await page.getByTestId('app-webhooks').getByRole('button', { name: 'Add webhook' }).click();
    const sheet = page.getByTestId('webhook-sheet');
    await expect(sheet.getByRole('button', { name: 'Save' })).toBeInViewport();
    await expectNoSidewaysScroll(page);
  });
}
