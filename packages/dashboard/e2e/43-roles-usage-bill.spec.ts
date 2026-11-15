import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';

// G7 R6, X8: Usage, Bill and Activity offer a role only what it may do, against a signed-in server (a virtual authenticator;
// no route is mocked). What a role may do is the server's table (`serve/roles.rs`): a suggestion's apply is a change to a box,
// reading the bill and scanning for forgotten resources are a use of the account, and the activity is read by anyone. The page
// and the server must agree, so each case also asks the server.
const PEOPLE = '[[users]]\nid = "owner"\nlabel = "Owner"\n\n[[users]]\nid = "friend"\nlabel = "Friend"\n\n[[users]]\nid = "watcher"\nlabel = "Watcher"\nrole = "viewer"\n';

async function api(page: Page, method: string, path: string, body?: unknown): Promise<{ status: number; body: { code?: string } }> {
  return page.evaluate(
    async ([m, p, b]) => {
      const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
      const res = await fetch(p as string, { method: m as string, headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, ...(b === undefined ? {} : { body: JSON.stringify(b) }) });
      return { status: res.status, body: (await res.json().catch(() => ({}))) as { code?: string } };
    },
    [method, path, body] as const,
  );
}

test.describe('a viewer', () => {
  test.describe.configure({ mode: 'serial' });
  let server: AuthServer;
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    server = await startAuthServer(4199, ['alpha'], 5, undefined, {}, PEOPLE);
    page = await (await browser.newContext()).newPage();
    await addVirtualAuthenticator(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await firstSignIn(page, server, 'watcher');
  });
  test.afterAll(() => server.stop());

  test('is offered no suggestion to apply and no bill to read, and is told why, at every width', async () => {
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/usage');
      const card = page.getByTestId('suggestions');
      await expect(card.getByTestId('cannot-note')).toContainText('a viewer cannot change a box');
      await expect(card.getByRole('button', { name: /^Review (resize|pause)/ })).toHaveCount(0);
      await page.goto(server.origin + '/costs/bill');
      await expect(page.getByRole('heading', { name: 'Bill', level: 1 })).toBeVisible();
      await expect(page.getByTestId('cannot-note').first()).toContainText('a viewer cannot ask the provider for the bill');
      await expect(page.getByRole('button', { name: 'Read the bill now' })).toHaveCount(0);
      await expect(page.getByRole('button', { name: /^Scan/ })).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    }
  });

  test('is refused by the server what the page does not offer', async () => {
    for (const [m, p] of [
      ['POST', '/v1/cost/bill/refresh'],
      ['POST', '/v1/cost/orphans/scan'],
      ['POST', '/v1/cost/refresh'],
      ['POST', '/v1/plans'],
    ] as const) {
      const r = await api(page, m, p, {});
      expect([r.status, r.body.code], `${m} ${p}`).toEqual([403, 'role_forbidden']);
    }
    // and reads everything it is shown
    for (const p of ['/v1/usage?range=1m', '/v1/suggestions', '/v1/activity', '/v1/cost/bill']) expect((await api(page, 'GET', p)).status, p).toBe(200);
  });

  test('reads the activity list, and sees who did each thing', async () => {
    await page.goto(server.origin + '/activity');
    await expect(page.getByTestId('activity-since-start')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export CSV' })).toBeVisible();
  });
});

test.describe('a member', () => {
  test.describe.configure({ mode: 'serial' });
  let server: AuthServer;
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    server = await startAuthServer(4200, ['alpha'], 5, undefined, {}, PEOPLE);
    page = await (await browser.newContext()).newPage();
    await addVirtualAuthenticator(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await firstSignIn(page, server, 'friend');
  });
  test.afterAll(() => server.stop());

  test('may read the bill and scan for forgotten resources, but not delete what a scan finds', async () => {
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/costs/bill');
      await expect(page.getByRole('button', { name: 'Read the bill now' })).toBeVisible();
      await expect(page.getByTestId('orphans-card').getByRole('button', { name: /^Scan/ })).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (w < 1024) await expectTouchTargets(page, page.getByTestId('orphans-card'));
    }
    const del = await api(page, 'POST', '/v1/cost/orphans/apply', {});
    expect([del.status, del.body.code]).toEqual([403, 'role_forbidden']);
    expect((await api(page, 'POST', '/v1/cost/orphans/scan', {})).status).not.toBe(403);
  });

  test('is named in Activity as the person who did it, not as this computer', async () => {
    const planned = await api(page, 'POST', '/v1/plans', { operation: { op: 'pause', name: 'alpha' } });
    expect(planned.status).toBe(200);
    const feed = await page.evaluate(async () => (await (await fetch('/v1/activity')).json()) as { entries: { actor: string; action: string }[] });
    const mine = feed.entries.filter((e) => e.action === 'plan pause');
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((e) => e.actor === 'friend')).toBe(true);
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/activity');
      await expect(page.getByText('friend').locator('visible=true').first()).toBeVisible();
      await expect(page.getByText('this computer')).toHaveCount(0);
      await expect(page.getByText('access link')).toHaveCount(0);
    }
  });
});
