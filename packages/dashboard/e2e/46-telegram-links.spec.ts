import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';

// Telegram links and delegations (ADR 0050, phase P1), tier A: a dashboard behind a passkey sign-in with a virtual authenticator,
// and the server's own stand-in for Telegram (OZBOX_DEMO_TELEGRAM=1), which speaks the Bot API on the server's HTTP client. A
// person opens a pairing window with a passkey, the "phone" writes /link, the person types the code back, and one more passkey
// confirms the link and converse on a box. Everything after that is what the bridge does with a real link. Nothing leaves this
// machine and the token is a fixture, not a real one.

test.describe.configure({ mode: 'serial' });

const PORT = 4197;
const PHONE = 4_000_000_001;
const TOKEN = '7000000002:FAKE-sentinel-token-not-real';

let server: AuthServer;
let page: Page;

// The server's JSON is read by path in these specs; its shape is the server's, not a type here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function api(p: Page, method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
  return p.evaluate(
    async ([m, path, b]) => {
      const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
      const res = await fetch(path as string, { method: m as string, headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, ...(b === undefined ? {} : { body: JSON.stringify(b) }) });
      return { status: res.status, body: await res.json().catch(() => null) };
    },
    [method, path, body] as const,
  );
}

const botSaid = async (): Promise<string[]> => ((await api(page, 'GET', '/v1/demo/telegram/sent')).body.sent as { chat_id: number; text: string }[]).filter((m) => m.chat_id === PHONE).map((m) => m.text);
const phoneWrites = (text: string) => api(page, 'POST', '/v1/demo/telegram/message', { chat_id: PHONE, text, name: 'Ada' });

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(PORT, ['alpha'], 5, `http://localhost:${PORT}`, { OZBOX_DEMO_TELEGRAM: '1', OZBOX_TELEGRAM_API_BASE: '' });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
});

test.afterAll(async () => {
  await server?.stop();
});

test('Settings, Apps marks Telegram Preview, shows what a chat can and cannot do, and the guided steps', async () => {
  await page.goto(`${server.origin}/settings/apps`);
  const tg = page.getByTestId('app-telegram');
  await expect(tg.getByTestId('tg-preview-note')).toContainText('Preview');
  await expect(tg.getByText('BotFather').first()).toBeVisible();
  // the table every message is read against, from the server's own copy
  const acts = tg.getByTestId('tg-acts');
  await expect(acts.getByTestId('tg-act-refused.approve')).toContainText('Refused');
  await expect(acts.getByTestId('tg-act-refused.stop')).toContainText('/stop');
  await expect(acts.getByTestId('tg-act-converse')).toContainText('Chat delegation');
  await expect(acts.getByTestId('tg-act-box.resume')).toContainText('Not in this release');
  await expect(acts.getByTestId('tg-act-run')).toContainText('Not in this release');
  await expect(tg.getByTestId('telegram-notify-only')).toBeVisible();
  // the bot token is saved write-only, and Telegram is switched on
  await tg.getByRole('button', { name: 'Add bot token' }).click();
  const sheet = page.getByTestId('telegram-token-sheet');
  await sheet.getByLabel('Bot token').fill(TOKEN);
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  await tg.locator('#tg-on').click();
  await expect(tg.getByRole('button', { name: 'Link an account' })).toBeEnabled();
  // nothing shows the token, in the page or in what the server answers
  expect(await page.content()).not.toContain('FAKE-sentinel');
  for (const p of ['/v1/settings', '/v1/apps', '/v1/telegram', '/v1/activity']) expect(JSON.stringify((await api(page, 'GET', p)).body), p).not.toContain('FAKE-sentinel');
});

test('a person links an account with two passkeys, delegates converse to a box, and the phone can talk to an agent', async () => {
  await page.goto(`${server.origin}/account`);
  const card = page.getByTestId('tg-links-card');
  await expect(card.getByTestId('tg-preview-badge')).toBeVisible();
  await expect(card.getByTestId('tg-no-links')).toBeVisible();
  await card.getByTestId('tg-link-open').click();
  const sheet = page.getByTestId('tg-link-sheet');
  // step 1: the window needs a passkey; until it is open the bot says nothing to anyone
  await phoneWrites('/link');
  await page.waitForTimeout(1500);
  expect(await botSaid()).toEqual([]);
  await sheet.getByTestId('tg-open-window').click();
  await expect(sheet.getByTestId('tg-step2')).toContainText('@oz_demo_bot');
  // step 2: the phone writes /link and the bot answers with a code
  await phoneWrites('/link');
  await expect(sheet.getByTestId('tg-window-state')).toContainText('The bot answered', { timeout: 30_000 });
  const code = (await botSaid()).map((t) => /Your code is ([A-Z0-9]{8})/.exec(t)?.[1]).find(Boolean) ?? '';
  expect(code).toHaveLength(8);
  await sheet.getByTestId('tg-code').fill(code);
  await sheet.getByTestId('tg-check-code').click();
  // step 3: the account the bot saw is shown, and one passkey confirms the link and converse on alpha
  await expect(sheet.getByTestId('tg-account')).toContainText('…0001');
  await expect(sheet.getByTestId('tg-account')).toContainText('Ada');
  await sheet.getByTestId('tg-enable-chat').click();
  await sheet.getByTestId('tg-box-alpha').click();
  await sheet.getByTestId('tg-confirm-link').click();
  await expect(sheet).toBeHidden({ timeout: 30_000 });
  const row = card.getByTestId(/^tg-link-/).first();
  await expect(row.getByTestId('tg-link-state')).toHaveText('Active');
  await expect(row.getByTestId('tg-delegation')).toContainText('alpha: Active');
  // the chat is told, and now talks to an agent on alpha
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('Linked as')), { timeout: 30_000 }).toBe(true);
  await phoneWrites('/new alpha fix the parser');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('Started t1 on alpha')), { timeout: 30_000 }).toBe(true);
  // it never approves, denies, stops or raises a limit, and it says so
  for (const w of ['/stop', '/budget +5', '/approve', '/secret list', '/box destroy alpha']) await phoneWrites(w);
  await expect.poll(async () => (await botSaid()).filter((t) => /never|dashboard/.test(t)).length, { timeout: 30_000 }).toBeGreaterThanOrEqual(5);
  const tasks = await api(page, 'GET', '/v1/tasks');
  expect(JSON.stringify(tasks.body)).not.toContain('"state":"cancelled"');
  // a box it was not delegated is a link to the dashboard, and the link's host is named
  await phoneWrites('/new bravo nope');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('/go#')), { timeout: 30_000 }).toBe(true);
});

test('with chat delegated on alpha the phone follows a session, gets its answers, and attaches to a terminal agent only where a chat app may', async () => {
  // the session the earlier test started answers, and every plain message after it is the next turn of the same conversation
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('Done: fix the parser')), { timeout: 40_000 }).toBe(true);
  await phoneWrites('and add the tests');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('Done: and add the tests')), { timeout: 40_000 }).toBe(true);
  expect((await api(page, 'GET', '/v1/tasks')).body.items.filter((t: { id: string }) => /^t\d+$/.test(t.id))).toHaveLength(1);
  // agents in terminals are listed, and a chat app never forces its way into one: that could answer the agent's own question
  await phoneWrites('/sessions alpha');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('alpha:%3') && t.includes('hooks, waiting')), { timeout: 30_000 }).toBe(true);
  await phoneWrites('/attach alpha:%3 force');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('does not type into an agent that is not waiting')), { timeout: 30_000 }).toBe(true);
  await phoneWrites('/attach alpha:%3');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('Experimental')), { timeout: 30_000 }).toBe(true);
  await phoneWrites('run the unit tests');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('alpha:%3:') && t.includes('Done: run the unit tests')), { timeout: 40_000 }).toBe(true);
  await phoneWrites('/detach');
});

test('lock reads only, a passkey lifts it, and unlink ends the link on the next message', async () => {
  await phoneWrites('/lock');
  await expect.poll(async () => (await botSaid()).some((t) => t.startsWith('Locked.')), { timeout: 30_000 }).toBe(true);
  await page.goto(`${server.origin}/account`);
  const row = page.getByTestId('tg-links-card').getByTestId(/^tg-link-/).first();
  await expect(row.getByTestId('tg-link-state')).toContainText('Locked');
  await phoneWrites('/new alpha while locked');
  await expect.poll(async () => (await botSaid()).some((t) => t.includes('link is locked')), { timeout: 30_000 }).toBe(true);
  await row.getByTestId('tg-unlock').click();
  await expect(row.getByTestId('tg-link-state')).toHaveText('Active', { timeout: 30_000 });
  // unlink from the dashboard: one confirmation, and the chat is not answered any more
  await row.getByTestId('tg-unlink').click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Unlink' }).click();
  await expect(page.getByTestId('tg-no-links')).toBeVisible({ timeout: 30_000 });
  const before = (await botSaid()).length;
  await phoneWrites('/fleet');
  await page.waitForTimeout(3000);
  expect((await botSaid()).length).toBe(before);
});

test('the Account page and the link sheet fit at three widths with touch targets on touch screens', async () => {
  for (const w of WIDTHS.filter((x) => x !== 1024)) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${server.origin}/account`);
    const card = page.getByTestId('tg-links-card');
    await expect(card).toBeVisible();
    await expectNoSidewaysScroll(page);
    await card.getByTestId('tg-link-open').click();
    const sheet = page.getByTestId('tg-link-sheet');
    await expect(sheet.getByTestId('tg-open-window')).toBeInViewport();
    if (w < 1024) await expectTouchTargets(page, sheet);
    await sheet.getByRole('button', { name: 'Close' }).first().click();
    await expect(sheet).toBeHidden();
  }
});
