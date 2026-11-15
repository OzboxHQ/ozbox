import { expect, test, type Locator, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets } from './fixtures';

// G7 R7, tier A (a REAL `ozbox serve` behind a sign-in, a virtual authenticator, a three-second step-up window): replacing the
// tunnel token and LOOSENING the approval policy or the spend limits need a passkey shown a moment ago. The server refuses
// without one (asserted on the API with no page involved), and the page asks for the passkey instead of showing a bare error.
// Nothing here is mocked. The tunnel token is fake and nothing starts a tunnel.
test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(4251, ['alpha'], 0.05);
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
});
test.afterAll(async () => {
  await server?.stop();
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

/** Let the three-second window lapse, so the next change meets a passkey that is no longer fresh. */
const lapse = () => page.waitForTimeout(3500);

/** Confirm with the passkey whenever it is asked for, until `done` shows (a retry can meet a window that lapsed again on a slow machine). */
async function settle(done: Locator): Promise<void> {
  const confirm = page.getByTestId('step-up-confirm');
  for (let i = 0; i < 30; i++) {
    if (await done.isVisible().catch(() => false)) return;
    // the button is disabled while a passkey is being checked: skip that round rather than wait for it
    if ((await confirm.isVisible().catch(() => false)) && (await confirm.isEnabled({ timeout: 500 }).catch(() => false))) await confirm.click({ timeout: 2_000 }).catch(() => undefined);
    await page.waitForTimeout(300);
  }
  await expect(done).toBeVisible();
}

test('the server refuses a token change, a loosened policy and a raised limit without a fresh passkey, and allows what asks for more', async () => {
  await page.goto(`${server.origin}/settings`);
  const policy = (await api('GET', '/v1/approval-policy')).body;
  await lapse();
  // replacing the tunnel token: refused, in the code the page answers
  const token = await api('PUT', '/v1/secrets/tunnel-token-cloudflare', { value: 'PLAYWRIGHT_SENTINEL_TOKEN' });
  expect(token.status).toBe(403);
  expect(token.body['code']).toBe('step_up_required');
  // loosening the policy: refused, and nothing changed
  const loose = await api('PUT', '/v1/approval-policy', { ...policy, ask: [], step_up: [] });
  expect(loose.status).toBe(403);
  expect(loose.body['code']).toBe('step_up_required');
  expect((await api('GET', '/v1/approval-policy')).body['ask']).toEqual(policy['ask']);
  // tightening, or an expiry that stays within 8 hours, needs nothing
  const tighter = await api('PUT', '/v1/approval-policy', { ...policy, expiry_s: 3600 });
  expect(tighter.status).toBe(200);
  expect((await api('PUT', '/v1/approval-policy', { ...policy, expiry_s: 8 * 3600 })).status).toBe(200);
  // an expiry raised PAST 8 hours keeps a stale request approvable for longer, so it is a loosening (owner decision D16)
  await lapse();
  const longer = await api('PUT', '/v1/approval-policy', { ...policy, expiry_s: 9 * 3600 });
  expect(longer.status).toBe(403);
  expect(longer.body['code']).toBe('step_up_required');
  expect((await api('GET', '/v1/approval-policy')).body['expiry_s']).toBe(8 * 3600);
  // a first spend limit is not a loosening; raising or removing it is
  expect((await api('PUT', '/v1/spend-caps', { fleet_monthly_cents: 5000 })).status).toBe(200);
  await lapse();
  const raised = await api('PUT', '/v1/spend-caps', { fleet_monthly_cents: 9000 });
  expect(raised.status).toBe(403);
  expect(raised.body['code']).toBe('step_up_required');
  expect((await api('PUT', '/v1/spend-caps', { fleet_monthly_cents: null })).status).toBe(403);
  expect((await api('PUT', '/v1/spend-caps', { fleet_monthly_cents: 4000 })).status).toBe(200);
  expect(JSON.stringify((await api('GET', '/v1/spend-caps')).body)).toContain('4000');
  // a model provider's monthly cap is the third limit: a first cap and a lower one are fine, a higher one or none is refused
  const current = (await api('GET', '/v1/settings')).body['settings'] as { models: { providers: Record<string, unknown>[] } };
  const withCap = (cap: number | null) => ({ ...current, models: { ...current.models, providers: [{ id: 'pw-model', kind: 'openai', label: 'PW', base_url: null, local_endpoint: false, monthly_cap_usd: cap }] } });
  expect((await api('PUT', '/v1/settings', withCap(50))).status).toBe(200);
  expect((await api('PUT', '/v1/settings', withCap(20))).status).toBe(200);
  await lapse();
  const modelRaised = await api('PUT', '/v1/settings', withCap(90));
  expect(modelRaised.status).toBe(403);
  expect(modelRaised.body['code']).toBe('step_up_required');
  expect((await api('PUT', '/v1/settings', withCap(null))).status).toBe(403);
  expect(JSON.stringify((await api('GET', '/v1/settings')).body)).toContain('"monthly_cap_usd":20');
});

for (const width of WIDTHS) {
  test.describe(`at ${width}px`, () => {
    test.beforeEach(async () => {
      await page.setViewportSize({ width, height: 900 });
    });

    test('saving a tunnel token asks for the passkey instead of failing', async () => {
      await page.goto(`${server.origin}/settings/access`);
      await expect(page.getByTestId('access-section')).toBeVisible();
      await lapse();
      await page.getByTestId('access-setup-cloudflare').click();
      const sheet = page.getByTestId('access-guide-cloudflare');
      await sheet.getByLabel('Public address', { exact: true }).fill(`https://ozbox-${width}.example.com`);
      await sheet.getByLabel('Tunnel token', { exact: true }).fill('PLAYWRIGHT_SENTINEL_TUNNEL_TOKEN');
      await sheet.getByRole('button', { name: 'Save tunnel' }).click();
      // the passkey is asked for; the error the server answers with is not what the person sees
      const stepUp = page.getByTestId('step-up');
      await expect(stepUp.getByRole('heading', { name: 'Confirm it is you' })).toBeVisible();
      await expect(sheet.getByRole('alert')).toHaveCount(0);
      if (width < 1024) await expectTouchTargets(page, stepUp);
      await page.getByTestId('step-up-confirm').click();
      // With the passkey shown, the token is stored and the save goes on to the address, which a sign-in at
      // http://localhost cannot give to any tunnel: THAT refusal is what is left on screen, not "confirm with your passkey".
      const refused = sheet.getByRole('alert').filter({ hasText: 'has to serve that same address' });
      await settle(refused);
      await expect(sheet.getByRole('alert').filter({ hasText: 'passkey' })).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    });

    test('loosening the approval policy says so in the review, asks for the passkey, and is kept; asking for more does not ask', async () => {
      await page.goto(`${server.origin}/settings/approvals`);
      await page.getByRole('button', { name: 'Edit approvals' }).click();
      const sheet = page.getByTestId('policy-sheet');
      // stop asking about one kind of action: that is a loosening
      const kind = sheet.locator('#pa-ask_command');
      await expect(kind).toBeChecked();
      await kind.click();
      await sheet.getByRole('button', { name: 'Review changes' }).click();
      await expect(sheet.getByTestId('policy-loosens')).toContainText('asks for your passkey');
      await lapse();
      await sheet.getByRole('button', { name: 'Save changes' }).click();
      const stepUp = page.getByTestId('step-up');
      await expect(stepUp.getByRole('heading', { name: 'Confirm it is you' })).toBeVisible();
      await page.getByTestId('step-up-confirm').click();
      await settle(page.getByText('Saved.').first());
      await page.reload();
      expect((await api('GET', '/v1/approval-policy')).body['ask']).not.toContain('ask_command');
      // putting it back asks for more than before, so it needs no passkey: no prompt even after the window lapsed
      await lapse();
      await page.getByRole('button', { name: 'Edit approvals' }).click();
      await page.getByTestId('policy-sheet').locator('#pa-ask_command').click();
      await page.getByTestId('policy-sheet').getByRole('button', { name: 'Review changes' }).click();
      await expect(page.getByTestId('policy-loosens')).toHaveCount(0);
      await page.getByTestId('policy-sheet').getByRole('button', { name: 'Save changes' }).click();
      await expect(page.getByText('Saved.').first()).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('step-up')).toHaveCount(0);
      expect((await api('GET', '/v1/approval-policy')).body['ask']).toContain('ask_command');
      await expectNoSidewaysScroll(page);
    });

    test('raising a spend limit says so, asks for the passkey and is kept', async () => {
      // every width raises the limit a little more than the one before it, so each is a loosening
      const dollars = 100 + WIDTHS.indexOf(width) * 10;
      await page.goto(`${server.origin}/settings/approvals`);
      await page.getByRole('button', { name: 'Edit limits' }).click();
      const sheet = page.getByTestId('caps-sheet');
      await sheet.getByLabel('Whole fleet, per month (US dollars)').fill(String(dollars));
      await expect(sheet.getByTestId('caps-loosens')).toBeVisible();
      await lapse();
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(page.getByTestId('step-up').getByRole('heading', { name: 'Confirm it is you' })).toBeVisible();
      await page.getByTestId('step-up-confirm').click();
      await settle(page.getByText('Saved.').first());
      expect(JSON.stringify((await api('GET', '/v1/spend-caps')).body)).toContain(String(dollars * 100));
      await expectNoSidewaysScroll(page);
    });
  });
}
