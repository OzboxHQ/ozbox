import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { startFakeTelegram, type FakeTelegram } from '../e2e/fake-telegram';
import { startRealThisBox, type RealStack } from './real-stack';

// Telegram links (ADR 0050, phase P1), tier B: a REAL `ozboxd` and a REAL `ozbox serve` behind a passkey sign-in, talking real
// HTTP to a fake Telegram on a loopback port (`OZBOX_TELEGRAM_API_BASE`, accepted for a loopback address only). The pieces here
// are the Account page and Settings, Apps against the real server, the stops (409, a bot flag), and that a pointer link's token
// never appears in anything a tunnel in front of the dashboard would log: the address, the headers, the referrer. Tier B has no
// real phone: tier C is a person with a test bot.
test.describe.configure({ mode: 'serial' });

const PORT = 4281;
const PHONE = 4_000_000_001;
const TOKEN = '7000000002:FAKE-sentinel-token-not-real';

let fake: FakeTelegram;
let stack: RealStack;
let page: Page;
const seen: { url: string; referer: string | undefined }[] = [];

// The server's JSON is read by path in these specs; its shape is the server's, not a type here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function api(method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
  return page.evaluate(
    async ([m, p, b]) => {
      const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
      const res = await fetch(p as string, { method: m as string, headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, ...(b === undefined ? {} : { body: JSON.stringify(b) }) });
      return { status: res.status, body: await res.json().catch(() => null) };
    },
    [method, path, body] as const,
  );
}
const toPhone = () => fake.sent().filter((m) => m.chat === PHONE).map((m) => m.text);

test.beforeAll(async ({ browser }) => {
  fake = await startFakeTelegram();
  stack = await startRealThisBox({ port: PORT, signIn: true, person: 'alice', extraEnv: { OZBOX_TELEGRAM_API_BASE: fake.url } });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  page.on('request', (q) => void seen.push({ url: q.url(), referer: q.headers()['referer'] }));
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: stack.origin, code: stack.code, stop: async () => undefined }, 'alice');
});
test.afterAll(async () => {
  await stack?.stop();
  await fake?.close();
});

test('the guided setup on a real server: a token is saved, Telegram is switched on and the bridge reads the bot', async () => {
  await page.goto(`${stack.origin}/settings/apps`);
  const tg = page.getByTestId('app-telegram');
  expect(await api('GET', '/v1/apps').then((r) => r.body.telegram.demo)).toBe(false);
  await expect(page.getByTestId('telegram-demo-note')).toHaveCount(0);
  await expect(tg.getByTestId('tg-preview-note')).toContainText('Preview');
  await tg.getByRole('button', { name: 'Add bot token' }).click();
  await page.getByTestId('telegram-token-sheet').getByLabel('Bot token').fill(TOKEN);
  await page.getByTestId('telegram-token-sheet').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByTestId('telegram-token-sheet')).toBeHidden();
  await tg.locator('#tg-on').click();
  await expect(tg.getByRole('button', { name: 'Link an account' })).toBeEnabled();
  expect(await page.content()).not.toContain('FAKE-sentinel');
});

test('two passkeys link an account on the Account page, and a person who is not linked is never answered', async () => {
  // before a window is open the bot says nothing to anyone
  fake.say(PHONE, '/link');
  await page.waitForTimeout(2500);
  expect(toPhone()).toEqual([]);
  await page.goto(`${stack.origin}/account`);
  const card = page.getByTestId('tg-links-card');
  await card.getByTestId('tg-link-open').click();
  const sheet = page.getByTestId('tg-link-sheet');
  await sheet.getByTestId('tg-open-window').click();
  await expect(sheet.getByTestId('tg-step2')).toContainText('@oz_fleet_bot');
  fake.say(PHONE, '/link');
  await expect(sheet.getByTestId('tg-window-state')).toContainText('The bot answered', { timeout: 30_000 });
  const code = toPhone().map((t) => /Your code is ([A-Z0-9]{8})/.exec(t)?.[1]).find(Boolean) ?? '';
  expect(code).toHaveLength(8);
  await sheet.getByTestId('tg-code').fill(code);
  await sheet.getByTestId('tg-check-code').click();
  await expect(sheet.getByTestId('tg-account')).toContainText('…0001');
  await sheet.getByTestId('tg-confirm-link').click();
  await expect(sheet).toBeHidden({ timeout: 30_000 });
  const row = card.getByTestId(/^tg-link-/).first();
  await expect(row.getByTestId('tg-link-state')).toHaveText('Active');
  await expect(row.getByTestId('tg-no-delegation')).toBeVisible();
  await expect.poll(toPhone, { timeout: 30_000 }).toContain('Linked as My phone. Send /help to see what this chat can do.');
  // another Telegram account is a stranger: counted and never answered
  const before = fake.sent().length;
  fake.say(4_000_000_002, '/whoami');
  await page.waitForTimeout(3000);
  expect(fake.sent().length).toBe(before);
});

test('a link with no delegation reads, and a pointer link opens its page without the token ever leaving in an address or a header', async () => {
  fake.say(PHONE, '/whoami');
  await expect.poll(toPhone, { timeout: 30_000 }).toContainEqual(expect.stringContaining('It is allowed to read.'));
  fake.say(PHONE, '/new main-box try');
  await expect.poll(toPhone, { timeout: 30_000 }).toContainEqual(expect.stringContaining('/go#'));
  const message = toPhone().find((t) => t.includes('/go#')) ?? '';
  expect(message).toContain('localhost');
  const link = /(http:\/\/localhost:\d+\/go#[0-9a-f]{48})/.exec(message)?.[1] ?? '';
  expect(link).not.toBe('');
  const token = link.split('#')[1] ?? '';
  seen.length = 0;
  await page.goto(link);
  await expect(page).toHaveURL(`${stack.origin}/chat`, { timeout: 30_000 });
  // the address bar never keeps the fragment, and nothing the browser sent (what a tunnel would log) holds the token
  expect(page.url()).not.toContain('#');
  expect(JSON.stringify(seen.map((s) => [s.url.split('#')[0], s.referer?.split('#')[0] ?? '']))).not.toContain(token);
  // opening twice works: a preview or the in-app browser must not spend it
  await page.goto(link);
  await expect(page).toHaveURL(`${stack.origin}/chat`, { timeout: 30_000 });
  // and a lapsed or wrong token is one plain answer
  await page.goto(`${stack.origin}/go#${'0'.repeat(48)}`);
  await expect(page.getByTestId('go-failed')).toBeVisible();
  expect(page.url()).not.toContain('#');
});

test('a 409 stops the bridge with an alert and it stays stopped until an owner confirms; a flagged bot will not run', async () => {
  fake.conflicts(1);
  fake.say(PHONE, '/fleet');
  await page.goto(`${stack.origin}/account`);
  await expect(page.getByTestId('tg-halted')).toContainText('another program', { timeout: 30_000 });
  const polls = fake.calls().filter((c) => c.startsWith('getUpdates')).length;
  await page.waitForTimeout(3000);
  expect(fake.calls().filter((c) => c.startsWith('getUpdates')).length).toBe(polls);
  // the owner confirms, and the bridge goes on and answers the message that waited
  fake.flag('can_join_groups', true);
  await page.getByTestId('tg-resume').click();
  await expect(page.getByTestId('tg-halted')).toContainText('(can_join_groups)', { timeout: 30_000 });
  fake.flag('can_join_groups', false);
  await page.getByTestId('tg-resume').click();
  await expect(page.getByTestId('tg-halted')).toHaveCount(0, { timeout: 30_000 });
  await expect.poll(() => fake.sent().filter((m) => m.chat === PHONE).length, { timeout: 30_000 }).toBeGreaterThan(2);
  // every poll asked for messages only, with a thirty second wait
  const gets = fake.calls().filter((c) => c.startsWith('getUpdates'));
  expect(gets.every((c) => c.includes('timeout=30') && c.includes('allowed_updates=%5B%22message%22%5D'))).toBe(true);
  expect(JSON.stringify(fake.calls())).not.toContain('FAKE-sentinel');
});
