import { expect, test } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// G7 R7, tier A (the demo provider): Settings says what is real. Providers asks the provider and says Demo, never "Connected";
// Backups and local AI say their data is the demo's, and the backups copy no longer claims a box is asked; General names the
// provider as a demo; the command palette reaches every Settings section. The injected failures (page.route) cover only an
// answer the demo cannot give on demand, and only check the WORDING: the real server's own answers are asserted without a mock
// in the first test and in each test beside it.
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const headers = () => ({ Authorization: `Bearer ${token()}` });

test('the real server says its provider is a demo, and that its backups and local AI are simulated', async ({ request }) => {
  const get = async (path: string) => (await request.get(`${origin()}${path}`, { headers: headers() })).json() as Promise<Record<string, unknown>>;
  const check = await get('/v1/provider/check');
  expect(check['mode']).toBe('demo');
  expect(check['provider']).toBe('fake');
  expect(check['ok']).toBe(true);
  expect(check['boxes']).toBeGreaterThan(0);
  expect((await get('/v1/backups'))['source']).toBe('simulated');
  expect((await get('/v1/boxes/alpha/backups'))['source']).toBe('simulated');
  expect(String(((await get('/v1/info'))['fleet'] as { mode: string }).mode)).toBe('demo');
});

for (const width of WIDTHS) {
  test.describe(`Settings at ${width}px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
    });

    test('Providers says Demo, not Connected, and shows no fixed rows', async ({ page }) => {
      await open(page, '/settings/providers');
      const status = page.getByTestId('provider-status');
      await expect(status).toHaveAttribute('data-state', 'demo', { timeout: 15_000 });
      await expect(page.getByTestId('provider-badge')).toHaveText('Demo');
      await expect(page.getByTestId('provider-note')).toContainText('demo provider');
      await expect(page.getByTestId('provider-card')).not.toContainText('Connected');
      // the two rows that were fixed text are gone; what is shown is read from the provider
      await expect(page.getByText('Permission check')).toHaveCount(0);
      await expect(page.getByText('Not available yet')).toHaveCount(0);
      await expect(page.getByText('Boxes it lists')).toBeVisible();
      await expect(page.getByTestId('demo-banner')).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.getByTestId('provider-card'));
    });

    test('Check now asks the provider again, and a provider that refuses is said in words', async ({ page }) => {
      await open(page, '/settings/providers');
      await expect(page.getByTestId('provider-status')).toHaveAttribute('data-state', 'demo', { timeout: 15_000 });
      // a real second question, answered by the real server
      const asked = page.waitForResponse((r) => r.url().includes('/v1/provider/check') && r.status() === 200);
      await page.getByTestId('provider-recheck').click();
      expect((await (await asked).json()).mode).toBe('demo');
      // the one injected answer: a real account whose credentials were refused (the demo cannot be made to refuse)
      await page.route('**/v1/provider/check', (r) => r.fulfill({ json: { mode: 'connected', provider: 'aws', ok: false, boxes: null, searched: ['eu-west-1'], error: 'the credentials were refused', checked_ms: Date.now(), took_ms: 4 } }));
      await page.getByTestId('provider-recheck').click();
      await expect(page.getByTestId('provider-status')).toHaveAttribute('data-state', 'failed');
      await expect(page.getByTestId('provider-badge')).toHaveText('Not answering');
      await expect(page.getByTestId('provider-error')).toContainText('credentials were refused');
      await expect(page.getByTestId('provider-card')).not.toContainText('Connected');
      await expect(page.getByText('eu-west-1')).toBeVisible();
      await expectNoSidewaysScroll(page);
    });

    test('Providers says so when the question could not be asked, instead of Connected', async ({ page }) => {
      await page.route('**/v1/provider/check', (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the server could not ask' }) }));
      await open(page, '/settings/providers');
      await expect(page.getByTestId('provider-status')).toHaveAttribute('data-state', 'unknown', { timeout: 15_000 });
      await expect(page.getByTestId('provider-error')).toContainText('could not ask');
      await expect(page.getByTestId('provider-card')).not.toContainText('Connected');
    });

    test('General names the provider as a demo', async ({ page }) => {
      await open(page, '/settings');
      await expect(page.getByText('fake · Demo')).toBeVisible({ timeout: 15_000 });
      await expectNoSidewaysScroll(page);
    });

    test('Backups says its data is the demo\'s, and does not claim a box is asked', async ({ page }) => {
      await open(page, '/settings/backups');
      const note = page.getByTestId('backups-source-note');
      await expect(note).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('backups-source-badge')).toHaveText('Simulated');
      await expect(note).toContainText('Nothing is backed up');
      const who = page.getByTestId('backups-who-runs');
      await expect(who).toContainText('demo provider');
      await expect(who).not.toContainText('asks the box');
      await expect(page.getByTestId('demo-banner')).toBeVisible();
      await expectNoSidewaysScroll(page);
    });

    test('a box\'s Backups tab says its snapshots are simulated', async ({ page }) => {
      await open(page, '/boxes/alpha');
      await page.getByRole('tab', { name: 'Backups' }).click();
      await expect(page.getByTestId('backups-source-note')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('backups-source-badge')).toHaveText('Simulated');
      await expectNoSidewaysScroll(page);
    });

    test('Models says the local AI is simulated', async ({ page }) => {
      await open(page, '/settings/models');
      const card = page.getByTestId('model-local-ai');
      await expect(card).toBeVisible({ timeout: 15_000 });
      await expect(card.getByTestId('local-ai-source-note')).toBeVisible();
      await expect(card.getByTestId('local-ai-source-badge')).toHaveText('Simulated');
      await expect(card.getByTestId('local-ai-source-note')).toContainText('Nothing is installed or downloaded');
      await expectNoSidewaysScroll(page);
    });

    test('the command palette reaches every Settings section', async ({ page }) => {
      await open(page, '/');
      for (const [query, href] of [
        ['settings backups', '/settings/backups'],
        ['dashboard access', '/settings/access'],
        ['approval policy', '/settings/approvals'],
        ['secret approvals', '/settings/secret-approvals'],
        ['settings general', '/settings'],
      ] as const) {
        await page.keyboard.press('Control+k');
        const palette = page.getByTestId('palette');
        await expect(palette).toBeVisible();
        await palette.getByRole('combobox').fill(query);
        await expect(palette.getByRole('option').first()).toBeVisible();
        await palette.getByRole('combobox').press('Enter');
        await expect(page).toHaveURL(new RegExp(`${href.replace('/', '\\/')}(#.*)?$`));
        await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
      }
    });
  });
}
