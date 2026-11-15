import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// G7 R7, tier B: Settings of a REAL this-box dashboard (a real ozboxd, a real `ozbox serve`, signed in). Nothing is mocked.
// Providers says "This box" and never "Connected"; the fleet-only Backups and Box defaults say the fleet is not connected;
// Budgets and Members are read and written; loosening the approval policy needs a passkey, and a fresh one is accepted. The
// refusal on a box with no sign-in needs a real box's marker files, which a laptop lacks: it is a Rust test and a tier C item.
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4261, signIn: true });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: s.origin, code: s.code, stop: async () => undefined });
});
test.afterAll(async () => {
  await s?.stop();
});

async function api(method: string, path: string, body?: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  return page.evaluate(
    async ([m, p, b]) => {
      const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
      const res = await fetch(p as string, { method: m as string, headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, ...(b === undefined ? {} : { body: JSON.stringify(b) }) });
      return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, unknown> };
    },
    [method, path, body] as const,
  );
}

test('the API says this is a box that checked itself, with no demo and no simulated backups', async () => {
  const check = await api('GET', '/v1/provider/check');
  expect(check.status).toBe(200);
  expect(check.body['mode']).toBe('this_box');
  expect(check.body['provider']).toBe('thisbox');
  expect(check.body['ok']).toBe(true);
  expect(check.body['boxes']).toBe(1);
  // the fleet's backups are not here to be asked about
  const backups = await api('GET', '/v1/backups');
  expect(backups.status).toBeGreaterThanOrEqual(400);
  expect(backups.body['code']).toBe('fleet_not_connected');
});

test('a passkey shown a moment ago is enough to loosen the approval policy on a box, and what it saves is kept', async () => {
  await page.goto(`${s.origin}/settings`);
  const policy = (await api('GET', '/v1/approval-policy')).body;
  const loose = await api('PUT', '/v1/approval-policy', { ...policy, allow_requester: true, ask: [] });
  expect(loose.status).toBe(200);
  expect((await api('GET', '/v1/approval-policy')).body['ask']).toEqual([]);
  // put it back, which asks for more and so needs nothing
  expect((await api('PUT', '/v1/approval-policy', policy)).status).toBe(200);
  expect((await api('GET', '/v1/approval-policy')).body['ask']).toEqual(policy['ask']);
});

for (const w of WIDTHS) {
  test.describe(`Settings of a real box at ${w}px`, () => {
    test.beforeEach(async () => {
      await page.setViewportSize({ width: w, height: 900 });
    });

    test('Providers says This box, never Connected, and General names the provider', async () => {
      await page.goto(`${s.origin}/settings/providers`);
      await expect(page.getByTestId('provider-status')).toHaveAttribute('data-state', 'this_box', { timeout: 15_000 });
      await expect(page.getByTestId('provider-badge')).toHaveText('This box');
      await expect(page.getByTestId('provider-note')).toContainText('no cloud account');
      await expect(page.getByTestId('provider-card')).not.toContainText('Connected');
      await expect(page.getByTestId('demo-banner')).toHaveCount(0);
      await expectNoSidewaysScroll(page);
      await page.goto(`${s.origin}/settings`);
      await expect(page.getByText('thisbox · This box')).toBeVisible({ timeout: 15_000 });
    });

    test('Backups says the fleet is not connected, and no backups note claims a demo', async () => {
      await page.goto(`${s.origin}/settings/backups`);
      await expect(page.getByTestId('fleet-not-connected')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('backups-source-note')).toHaveCount(0);
      await expect(page.getByTestId('demo-banner')).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    });

    test('Models shows no simulated note, and the palette reaches Backups', async () => {
      await page.goto(`${s.origin}/settings/models`);
      await expect(page.getByTestId('model-local-ai')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('local-ai-source-note')).toHaveCount(0);
      await page.keyboard.press('Control+k');
      const palette = page.getByTestId('palette');
      await palette.getByRole('combobox').fill('settings backups');
      await palette.getByRole('combobox').press('Enter');
      await expect(page).toHaveURL(/\/settings\/backups$/);
    });

    test('Budgets keeps what is saved after a reload', async () => {
      const usd = String(100 + WIDTHS.indexOf(w));
      await page.goto(`${s.origin}/settings/budgets`);
      await page.getByRole('button', { name: 'Edit' }).click();
      await page.getByLabel('Monthly budget in USD (optional)').fill(usd);
      await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
      await expect(page.getByText('Budget saved').first()).toBeVisible({ timeout: 15_000 });
      await page.reload();
      await expect(page.getByTestId('budget-note')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByText(usd, { exact: true }).first()).toBeVisible();
      expect(JSON.stringify((await api('GET', '/v1/settings')).body)).toContain(usd);
      await expectNoSidewaysScroll(page);
    });

    test('Box defaults say the fleet is not connected instead of a form that cannot save', async () => {
      await page.goto(`${s.origin}/settings/defaults`);
      await expect(page.getByTestId('fleet-not-connected')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByRole('button', { name: 'Edit' })).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    });

    test('Members lists the signed-in owner with their role', async () => {
      await page.goto(`${s.origin}/settings/members`);
      await expect(page.getByTestId('members-local')).toHaveCount(0);
      await expect(page.getByText('Owner', { exact: false }).first()).toBeVisible({ timeout: 15_000 });
      await expectNoSidewaysScroll(page);
    });

    test('Secret approvals loads and says what a box has, not a blank page', async () => {
      await page.goto(`${s.origin}/settings/secret-approvals`);
      await expect(page.getByTestId('secret-approvals-section').or(page.getByRole('alert')).or(page.getByText(/not available/i)).first()).toBeVisible({ timeout: 15_000 });
      expect(await page.locator('#main').innerText()).not.toMatch(/\b(undefined|NaN)\b|\[object Object\]/);
      await expectNoSidewaysScroll(page);
    });
  });
}
