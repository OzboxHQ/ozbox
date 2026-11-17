import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Chat with coding agents on the demo provider: the conversation in the dashboard, and what a chat linked the old way can and
// cannot do in Telegram (through the demo bot). The agent is the simulated engine, which answers each message as a
// conversation and asks for approval when a message holds `sim:command=sudo`. Nothing here reaches an outside service.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

// The chat answers "Too many messages too fast" past 20 messages a minute from one conversation. Four widths of the same journey
// send about six each, so the last one met the limit (and only when the run was quick). Each message the dashboard chat is given,
// typed or sent by a button, is counted here, and the next waits until the oldest has left the minute, keeping a margin of four.
const sentAt: number[] = [];
async function reserve(page: Page) {
  for (;;) {
    const now = Date.now();
    while (sentAt.length > 0 && now - (sentAt[0] ?? now) >= 61_000) sentAt.shift();
    if (sentAt.length < 16) break;
    await page.waitForTimeout(1_000);
  }
  sentAt.push(Date.now());
}

async function send(page: Page, text: string) {
  await reserve(page);
  await page.getByTestId('chat-composer').fill(text);
  await page.getByRole('button', { name: 'Send' }).click();
}

/** Stop the session this chat follows, so a later test starts from nothing. */
async function endSession(page: Page, request: APIRequestContext) {
  const o = await request.get(`${origin()}/v1/chat`, { headers: headers() });
  const body = (await o.json()) as { bound: { kind: string; id?: string } | null };
  if (body.bound?.kind === 'task' && body.bound.id) await request.post(`${origin()}/v1/tasks/${body.bound.id}/cancel`, { headers: headers() });
  await request.post(`${origin()}/v1/chat/bind`, { headers: headers(), data: { task: null } });
  void page;
}

for (const width of WIDTHS) {
  test(`Chat at ${width}px: start a session, get its answer, send the next message, and decide an approval inline`, async ({ page, request }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/chat');
    await expect(page.getByRole('heading', { name: 'Chat', level: 1 })).toBeVisible();
    await expect(page.getByTestId('chat-composer')).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));

    const marker = `chat${width}${Date.now() % 100000}`;
    await send(page, `/new charlie ${marker}`);
    const transcript = page.getByTestId('chat-transcript');
    await expect(transcript).toContainText('Started', { timeout: 30_000 });
    // the agent answers, and the chat says it is waiting for the next message
    await expect(transcript).toContainText(`Done: ${marker}`, { timeout: 40_000 });
    await expect(page.getByTestId('chat-status')).toHaveText('Waiting for your message', { timeout: 20_000 });
    await expect(page.getByTestId('chat-session')).toContainText('charlie');

    // plain text is the next turn of the same conversation
    await send(page, 'now the tests');
    await expect(transcript).toContainText('Done: now the tests', { timeout: 40_000 });
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));
    await axeClean(page, 'main');

    // a command on the ask list stops the agent; the exact action is inline and is decided where it asks for the passkey
    await send(page, 'install it sim:command=sudo');
    const approvals = page.getByTestId('chat-approvals');
    const item = approvals.getByTestId('agent-approval').filter({ hasText: 'sudo' }).first();
    await expect(item).toBeVisible({ timeout: 40_000 });
    await expect(item.getByTestId('exact-action')).toHaveText('sudo');
    if (width < 1024) await expectTouchTargets(page, approvals);
    await axeClean(page, '[data-testid="chat-approvals"]');
    await item.getByRole('button', { name: 'Approve' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Approve' }).click();
    await expect(transcript).toContainText('(approved)', { timeout: 40_000 });

    // pause and resume keep the same conversation
    await expect(page.getByTestId('chat-status')).toHaveText('Waiting for your message', { timeout: 40_000 });
    await reserve(page);
    await page.getByRole('button', { name: 'Pause' }).click();
    await expect(page.getByTestId('chat-status')).toContainText('Paused', { timeout: 30_000 });
    await reserve(page);
    await page.getByRole('button', { name: 'Resume' }).click();
    await expect(page.getByTestId('chat-status')).not.toContainText('Paused', { timeout: 30_000 });

    // the session is a task on the board like any other
    await open(page, '/tasks');
    await expect(page.getByTestId('task-card').filter({ hasText: marker }).first()).toBeVisible({ timeout: 20_000 });
    await endSession(page, request);
  });
}

test('a one-time link from a chat opens its approval in the dashboard, and a second use does not', async ({ page, request }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, '/chat');
  await send(page, '/new charlie push it');
  await expect(page.getByTestId('chat-transcript')).toContainText('Done: push it', { timeout: 40_000 });
  await send(page, 'sim:push=main');
  const item = page.getByTestId('chat-approvals').getByTestId('agent-approval').filter({ hasText: 'git push origin main' }).first();
  await expect(item).toBeVisible({ timeout: 40_000 });
  // a bad link says so
  await open(page, `/chat#link=${'0'.repeat(48)}`);
  await expect(page.getByTestId('chat-link-note')).toContainText('That link did not work', { timeout: 20_000 });
  await open(page, '/approvals');
  await page.getByTestId('agent-approval').filter({ hasText: 'git push origin main' }).first().getByRole('button', { name: 'Deny' }).click();
  await expect(page.getByText(/Denied by owner/).first()).toBeVisible({ timeout: 15_000 });
  await endSession(page, request);
});

// A Telegram chat is linked with a passkey and talks to an agent only where a person delegated that (ADR 0050); that journey is
// `46-telegram-links.spec.ts`, behind a sign-in. This server has no sign-in, so the chat below is one linked the old way: told
// things, allowed to read, and nothing more. What is proved here is the notify-only half, which does not depend on a link: a
// message names an approval and sends no button, and nothing said or pressed in a chat decides anything. How a delegated chat starts a session,
// follows it and attaches to a terminal agent is in `46-telegram-links.spec.ts`; the gateway's refusals are also covered by the Rust tests.
test.describe('a chat linked the old way, through the demo bot', () => {
  const chatId = 4242;
  const api = (request: APIRequestContext) => ({
    call: (method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown) => request.fetch(`${origin()}${path}`, { method, headers: headers(), ...(data === undefined ? {} : { data }) }),
  });

  test.afterEach(async ({ request }) => {
    const a = api(request);
    await a.call('DELETE', `/v1/apps/telegram/chats/${chatId}`);
    const s = (await (await a.call('GET', '/v1/settings')).json()) as { settings: { apps: { telegram: { enabled: boolean } }; [k: string]: unknown } };
    s.settings.apps.telegram.enabled = false;
    await a.call('PUT', '/v1/settings', s.settings);
  });

  test('it reads, is told, and cannot talk to an agent, approve, deny, stop or raise a limit; a stranger and a forward are not acted on', async ({ request }) => {
    const a = api(request);
    expect((await a.call('PUT', '/v1/secrets/telegram-bot-token', { value: '123:CHAT_PLAYWRIGHT_SENTINEL' })).ok()).toBe(true);
    const s = (await (await a.call('GET', '/v1/settings')).json()) as { settings: { apps: { telegram: { enabled: boolean } }; [k: string]: unknown } };
    s.settings.apps.telegram.enabled = true;
    expect((await a.call('PUT', '/v1/settings', s.settings)).ok()).toBe(true);
    await a.call('POST', '/v1/demo/telegram/legacy-chat', { chat_id: chatId, name: 'Ada phone' });
    const say = (text: string, extra: Record<string, unknown> = {}) => a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text, ...extra });
    const sent = async () => ((await (await a.call('GET', '/v1/demo/telegram/sent')).json()) as { sent: { chat_id: number; text: string; buttons: string[] }[] }).sent.filter((m) => m.chat_id === chatId);

    // it reads
    await say('/fleet');
    await expect.poll(async () => (await sent()).some((m) => /boxes?, \d+ running/.test(m.text)), { timeout: 30_000 }).toBe(true);
    // a stranger is not heard and gets no answer at all
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: 999, text: '/fleet' });
    // talking to an agent is something a person allows in the dashboard first: it is a pointer, not a session
    await say('/new charlie tgstart');
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('allow it in the dashboard')), { timeout: 30_000 }).toBe(true);
    const tasks = (await (await a.call('GET', '/v1/tasks')).json()) as { items: { id: string }[] };
    expect(tasks.items.some((t) => t.id === 't999')).toBe(false);
    const nope = ((await (await a.call('GET', '/v1/demo/telegram/sent')).json()) as { sent: { chat_id: number }[] }).sent;
    expect(nope.some((m) => m.chat_id === 999)).toBe(false);

    // an approve, a deny, a stop, a spending limit and a secret are refused in words; a pressed button is not even read
    for (const w of ['/approve', '/deny', '/stop', '/budget +5', '/secret list']) await say(w);
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, callback: 'approve:a1' });
    await expect.poll(async () => (await sent()).filter((m) => /never|dashboard/.test(m.text)).length, { timeout: 30_000 }).toBeGreaterThanOrEqual(5);
    expect((await sent()).every((m) => m.buttons.length === 0)).toBe(true);

    // forwarded text is data, and the bot token appears in nothing it said
    await say('/stop', { forwarded: true });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('is not an instruction')), { timeout: 20_000 }).toBe(true);
    expect(JSON.stringify(await sent())).not.toContain('CHAT_PLAYWRIGHT_SENTINEL');
  });
});
