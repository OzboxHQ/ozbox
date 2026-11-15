import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';

// Roles (ADR 0039), in real browsers with a virtual authenticator: who the first person is, what an owner can change and
// how, and what a member and a viewer are offered. Each describe block has its own dashboard and its own sign-in, and its
// steps depend on each other, so they run in order. The server refuses what a role may not do on every request (the Rust
// tests cover every route); these specs prove the page matches it and the round trip survives a reload.

const PEOPLE = '[[users]]\nid = "owner"\nlabel = "Owner"\n\n[[users]]\nid = "friend"\nlabel = "Friend"\n\n[[users]]\nid = "watcher"\nlabel = "Watcher"\nrole = "viewer"\n';

async function api(page: Page, method: string, path: string, body?: unknown): Promise<{ status: number; body: { code?: string; message?: string } }> {
  return page.evaluate(
    async ([m, p, b]) => {
      const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
      const res = await fetch(p as string, { method: m as string, headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, ...(b === undefined ? {} : { body: JSON.stringify(b) }) });
      return { status: res.status, body: (await res.json().catch(() => ({}))) as { code?: string; message?: string } };
    },
    [method, path, body] as const,
  );
}

test.describe('the owner', () => {
  test.describe.configure({ mode: 'serial' });
  let server: AuthServer;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    server = await startAuthServer(4192, ['alpha'], 5, undefined, {}, PEOPLE);
    page = await (await browser.newContext()).newPage();
    await addVirtualAuthenticator(page);
  });
  test.afterAll(() => server.stop());

  test('the first person to sign in is the owner and may do everything', async () => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await firstSignIn(page, server);
    await page.goto(server.origin + '/account');
    await expect(page.getByTestId('my-role')).toHaveText('Your role: Owner');
    // the settings and the browser's settings are open to them
    await page.goto(server.origin + '/browser');
    await expect(page.getByRole('button', { name: 'Browsing settings' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Open a browser' })).toBeVisible();
    await page.goto(server.origin + '/settings');
    await expect(page.getByTestId('read-only-notice')).toHaveCount(0);
  });

  test('the people card lists everyone with a role, at every width', async () => {
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/account');
      const card = page.getByTestId('people-card');
      await expect(card).toBeVisible();
      await expect(card.getByTestId('person-owner')).toContainText('Owner');
      await expect(card.getByTestId('person-friend')).toContainText('Friend');
      await expect(card.getByTestId('person-watcher')).toContainText('Watcher');
      await expect(card.getByTestId('role-friend')).toContainText('Member');
      await expect(card.getByTestId('role-watcher')).toContainText('Viewer');
      await expectNoSidewaysScroll(page);
      if (w < 1024) await expectTouchTargets(page, card);
    }
  });

  test('changing a role asks for the passkey, is kept after a reload, and the last owner cannot step down', async () => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(server.origin + '/account');
    await page.getByTestId('role-friend').click();
    await page.getByRole('option', { name: 'Viewer' }).click();
    // a passkey shown a moment ago is enough; if that window has lapsed the page asks for one, and either ends the same way
    const confirm = page.getByTestId('step-up-confirm');
    await expect(page.getByText('Role changed').or(confirm)).toBeVisible();
    if (await confirm.isVisible()) await confirm.click();
    await expect(page.getByText('Role changed')).toBeVisible();
    await page.reload();
    await expect(page.getByTestId('role-friend')).toContainText('Viewer');
    // the only owner cannot be made a member: the server keeps one
    const refused = await api(page, 'PUT', '/v1/people/owner/role', { role: 'member' });
    expect(refused.status).toBe(409);
    expect(refused.body.code).toBe('last_owner');
    // and the change is in the audit log
    const audit = await page.evaluate(async () => JSON.stringify(await (await fetch('/v1/audit?limit=100')).json()));
    expect(audit).toContain('person.role');
  });
});

test.describe('a viewer', () => {
  test.describe.configure({ mode: 'serial' });
  let server: AuthServer;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    server = await startAuthServer(4193, ['alpha'], 5, undefined, {}, PEOPLE);
    page = await (await browser.newContext()).newPage();
    await addVirtualAuthenticator(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await firstSignIn(page, server, 'watcher');
  });
  test.afterAll(() => server.stop());

  test('is told browser sessions are not for them, at every width', async () => {
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/browser');
      await expect(page.getByTestId('browser-no-access')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Open a browser' })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Browsing settings' })).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    }
    const looked = await api(page, 'GET', '/v1/browser/sessions');
    expect(looked.status).toBe(403);
    expect(looked.body.code).toBe('role_forbidden');
    expect(looked.body.message).toContain('a viewer cannot watch a browser session');
  });

  test('can look at the fleet and the runs, and cannot start one or approve', async () => {
    await page.goto(server.origin + '/tasks');
    await expect(page.getByRole('button', { name: 'New task' })).toBeDisabled();
    // the page says why, instead of leaving a dead button
    await expect(page.getByTestId('cannot-note')).toContainText('a viewer cannot start runs');
    expect((await api(page, 'GET', '/v1/boxes')).status).toBe(200);
    expect((await api(page, 'GET', '/v1/runs')).status).not.toBe(403);
    const started = await api(page, 'POST', '/v1/tasks', {});
    expect([started.status, started.body.code]).toEqual([403, 'role_forbidden']);
    const approved = await api(page, 'POST', '/v1/approval-requests/x/approve', {});
    expect([approved.status, approved.body.code]).toEqual([403, 'role_forbidden']);
  });

  test('is offered no write control on Chat, Schedules or Triggers, and the server refuses the same acts', async () => {
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/chat');
      await expect(page.getByTestId('read-only-notice')).toBeVisible();
      await expect(page.getByTestId('chat-composer')).toBeDisabled();
      await expect(page.getByRole('button', { name: 'Send' })).toBeDisabled();
      await page.goto(server.origin + '/schedules');
      await expect(page.getByTestId('cannot-note')).toContainText('a viewer cannot start runs');
      await expect(page.getByRole('button', { name: 'New schedule' }).first()).toBeDisabled();
      await page.goto(server.origin + '/triggers');
      await expect(page.getByTestId('cannot-note')).toContainText('a viewer cannot start runs');
      await expect(page.getByRole('button', { name: 'New trigger' }).first()).toBeDisabled();
      await expectNoSidewaysScroll(page);
    }
    for (const [method, path, body] of [
      ['POST', '/v1/chat/messages', { text: 'hello' }],
      ['POST', '/v1/schedules', {}],
      ['POST', '/v1/triggers', {}],
    ] as const) {
      const r = await api(page, method, path, body);
      expect([r.status, r.body.code], path).toEqual([403, 'role_forbidden']);
    }
  });

  test('is not offered the files or the terminal of a box', async () => {
    for (const path of ['/boxes/alpha/files', '/boxes/alpha/terminal']) {
      await page.goto(server.origin + path);
      await expect(page.getByTestId('cannot-note')).toContainText('a viewer cannot use a terminal, the files or the IDE of a box');
    }
    const files = await api(page, 'GET', '/v1/boxes/alpha/files/list?path=%2Fwork');
    expect([files.status, files.body.code]).toEqual([403, 'role_forbidden']);
    const term = await api(page, 'POST', '/v1/boxes/alpha/terminal', { cols: 80, rows: 24 });
    expect([term.status, term.body.code]).toEqual([403, 'role_forbidden']);
  });

  test('sees the settings and the permissions read-only, and cannot change a role', async () => {
    await page.goto(server.origin + '/settings');
    await expect(page.getByTestId('read-only-notice')).toContainText('signed in as a viewer');
    await expect(page.getByTestId('read-only-scope')).toHaveAttribute('disabled', '');
    await page.goto(server.origin + '/permissions');
    await expect(page.getByTestId('read-only-notice')).toBeVisible();
    await page.goto(server.origin + '/account');
    await expect(page.getByTestId('my-role')).toHaveText('Your role: Viewer');
    // a badge, not a control
    await expect(page.getByTestId('role-owner')).toHaveText('Owner');
    await expect(page.getByTestId('people-card').getByRole('combobox')).toHaveCount(0);
    const changed = await api(page, 'PUT', '/v1/people/watcher/role', { role: 'owner' });
    expect([changed.status, changed.body.code]).toEqual([403, 'role_forbidden']);
    // how people sign in is an owner's: no forms for it, and the server refuses the request that sidesteps the page
    await expect(page.getByRole('button', { name: 'Set up GitHub' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Set up Google' })).toHaveCount(0);
    const provider = await api(page, 'PUT', '/auth/config/github', { client_id: 'Iv1.attacker' });
    expect([provider.status, provider.body.code]).toEqual([403, 'role_forbidden']);
  });
});

test.describe('a member', () => {
  test.describe.configure({ mode: 'serial' });
  let server: AuthServer;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    server = await startAuthServer(4194, ['alpha'], 5, undefined, {}, PEOPLE);
    page = await (await browser.newContext()).newPage();
    await addVirtualAuthenticator(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await firstSignIn(page, server, 'friend');
  });
  test.afterAll(() => server.stop());

  test('may watch and open a browser, but not change its settings', async () => {
    for (const w of WIDTHS) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(server.origin + '/browser');
      await expect(page.getByRole('button', { name: 'Open a browser' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Browsing settings' })).toHaveCount(0);
      await expectNoSidewaysScroll(page);
    }
    expect((await api(page, 'GET', '/v1/browser/sessions')).status).not.toBe(403);
    const settings = await api(page, 'PUT', '/v1/browser/settings', { settings: {} });
    expect([settings.status, settings.body.code]).toEqual([403, 'role_forbidden']);
    expect(settings.body.message).toContain('a member cannot change settings');
  });

  test('may start runs, and finds the settings and the permissions read-only', async () => {
    await page.goto(server.origin + '/tasks');
    await expect(page.getByRole('button', { name: 'New task' })).toBeEnabled();
    await page.goto(server.origin + '/settings');
    await expect(page.getByTestId('read-only-notice')).toBeVisible();
    await page.goto(server.origin + '/permissions');
    await expect(page.getByTestId('read-only-notice')).toBeVisible();
    const grant = await api(page, 'POST', '/v1/permissions/grants', {});
    expect([grant.status, grant.body.code]).toEqual([403, 'role_forbidden']);
  });

  test('sees who has which role but cannot change one', async () => {
    await page.goto(server.origin + '/account');
    await expect(page.getByTestId('my-role')).toHaveText('Your role: Member');
    await expect(page.getByTestId('people-card').getByRole('combobox')).toHaveCount(0);
    await expect(page.getByTestId('role-friend')).toHaveText('Member');
  });
});
