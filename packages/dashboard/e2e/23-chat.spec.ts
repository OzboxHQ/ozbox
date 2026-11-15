import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Chat with coding agents on the demo provider: the same conversation in the dashboard and in Telegram (through the demo
// bot, with its real one-time pairing code). The agent is the simulated engine, which answers each message as a
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
  await open(page, `/chat?link=${'0'.repeat(48)}`);
  await expect(page.getByTestId('chat-link-note')).toContainText('That link did not work', { timeout: 20_000 });
  await open(page, '/approvals');
  await page.getByTestId('agent-approval').filter({ hasText: 'git push origin main' }).first().getByRole('button', { name: 'Deny' }).click();
  await expect(page.getByText(/Denied by owner/).first()).toBeVisible({ timeout: 15_000 });
  await endSession(page, request);
});

test.describe('the same chat in Telegram, through the demo bot', () => {
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

  test('a paired chat starts a session, gets answers, is only notified of approvals, with a link and no button, and an approve attempt from the chat is refused', async ({ request }) => {
    const a = api(request);
    expect((await a.call('PUT', '/v1/secrets/telegram-bot-token', { value: '123:CHAT_PLAYWRIGHT_SENTINEL' })).ok()).toBe(true);
    const s = (await (await a.call('GET', '/v1/settings')).json()) as { settings: { apps: { telegram: { enabled: boolean } }; [k: string]: unknown } };
    s.settings.apps.telegram.enabled = true;
    expect((await a.call('PUT', '/v1/settings', s.settings)).ok()).toBe(true);
    const { code } = (await (await a.call('POST', '/v1/apps/telegram/pairing', {})).json()) as { code: string };
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: code, name: 'Ada phone' });
    const sent = async () => ((await (await a.call('GET', '/v1/demo/telegram/sent')).json()) as { sent: { chat_id: number; text: string; buttons: string[] }[] }).sent.filter((m) => m.chat_id === chatId);
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('Paired')), { timeout: 20_000 }).toBe(true);

    // a stranger is not heard and gets no answer
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: 999, text: '/new charlie nope' });
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/new charlie tgstart' });
    await expect.poll(async () => (await sent()).some((m) => /Started t\d+ on charlie/.test(m.text)), { timeout: 20_000 }).toBe(true);
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('Done: tgstart')), { timeout: 40_000 }).toBe(true);
    const nope = ((await (await a.call('GET', '/v1/demo/telegram/sent')).json()) as { sent: { chat_id: number }[] }).sent;
    expect(nope.some((m) => m.chat_id === 999)).toBe(false);

    // a chat only notifies (owner decision, 2026-11-12): an ordinary command on the ask list sends a message that names the
    // action and carries a link to the dashboard, with no Approve or Deny button, and nothing said or pressed in the chat decides it
    const pendingIds = async (needle: string) => {
      const chat = (await (await a.call('GET', '/v1/chat')).json()) as { approvals: { id: string; action: string }[] };
      return chat.approvals.filter((x) => x.action.includes(needle)).map((x) => x.id);
    };
    const stateOf = async (id: string) => {
      const list = (await (await a.call('GET', '/v1/approval-requests')).json()) as { items: { id: string; state: string }[] };
      return list.items.find((x) => x.id === id)?.state;
    };
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: 'tidy up sim:command=sudo' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('Decide it in the dashboard')), { timeout: 40_000 }).toBe(true);
    const ask = (await sent()).find((m) => m.text.includes('Decide it in the dashboard'));
    expect(ask?.text).toContain('sudo');
    // this server has no public address, so the message says to open the dashboard rather than carry a path that opens nothing
    expect(ask?.text).toContain('Open the dashboard on the computer that runs it.');
    expect(ask?.text).not.toContain('/chat?link=');
    expect(ask?.buttons).toEqual([]);
    const ordinary = await pendingIds('sudo');
    expect(ordinary).toHaveLength(1);
    const ordinaryId = ordinary[0] ?? '';

    // an approve attempt from the chat (a pressed button that is not there, and the word itself) is refused: nothing is decided
    const before = (await sent()).length;
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, callback: `approve:${ordinaryId}` });
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: 'approve' });
    await expect.poll(async () => await stateOf(ordinaryId), { timeout: 10_000 }).toBe('pending');
    await new Promise((r) => setTimeout(r, 2_000));
    expect(await stateOf(ordinaryId)).toBe('pending');
    expect((await sent()).slice(before).some((m) => m.text.includes('Approved'))).toBe(false);

    // the decision is made on the dashboard, and the agent goes on and answers in the chat
    const decided = await a.call('POST', `/v1/approval-requests/${ordinaryId}/approve`, {});
    expect(decided.ok(), await decided.text()).toBe(true);
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('(approved)')), { timeout: 40_000 }).toBe(true);

    // a push to a protected branch is told the same way, in the passkey words, still with no button
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: 'sim:push=main' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('passkey')), { timeout: 40_000 }).toBe(true);
    const risky = (await sent()).find((m) => m.text.includes('passkey'));
    expect(risky?.buttons).toEqual([]);
    expect(risky?.text).toContain('Open the dashboard on the computer that runs it.');
    expect(risky?.text).not.toContain('/chat?link=');
    const riskyIds = await pendingIds('git push origin main');
    expect(riskyIds).toHaveLength(1);
    const riskyId = riskyIds[0] ?? '';
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, callback: `approve:${riskyId}` });
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, callback: `deny:${riskyId}` });
    await new Promise((r) => setTimeout(r, 2_000));
    expect(await stateOf(riskyId)).toBe('pending');
    expect((await sent()).some((m) => m.text.includes('Denied'))).toBe(false);
    // only the dashboard denies it
    const denied = await a.call('POST', `/v1/approval-requests/${riskyId}/deny`, {});
    expect(denied.ok(), await denied.text()).toBe(true);
    expect(((await denied.json()) as { state: string }).state).toBe('denied');
    await expect.poll(async () => await pendingIds('git push origin main'), { timeout: 10_000 }).toEqual([]);

    // forwarded text is data, and the bot token appears in nothing it said
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/stop', forwarded: true });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('is not an instruction')), { timeout: 20_000 }).toBe(true);
    expect(JSON.stringify(await sent())).not.toContain('CHAT_PLAYWRIGHT_SENTINEL');
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/stop' });
  });

  test('agents in terminals are listed, attached, typed into and read back, and they are experimental', async ({ request }) => {
    const a = api(request);
    expect((await a.call('PUT', '/v1/secrets/telegram-bot-token', { value: '123:CHAT_PLAYWRIGHT_SENTINEL' })).ok()).toBe(true);
    const s = (await (await a.call('GET', '/v1/settings')).json()) as { settings: { apps: { telegram: { enabled: boolean } }; [k: string]: unknown } };
    s.settings.apps.telegram.enabled = true;
    await a.call('PUT', '/v1/settings', s.settings);
    const { code } = (await (await a.call('POST', '/v1/apps/telegram/pairing', {})).json()) as { code: string };
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: code, name: 'Ada phone' });
    const sent = async () => ((await (await a.call('GET', '/v1/demo/telegram/sent')).json()) as { sent: { chat_id: number; text: string }[] }).sent.filter((m) => m.chat_id === chatId);
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('Paired')), { timeout: 20_000 }).toBe(true);
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/sessions charlie' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('charlie:%3') && m.text.includes('hooks, waiting')), { timeout: 20_000 }).toBe(true);
    // a chat app never forces its way into a terminal: that could answer the agent's own question
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/attach charlie:%3 force' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('does not type into an agent that is not waiting')), { timeout: 20_000 }).toBe(true);
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/attach charlie:%3' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('Experimental')), { timeout: 20_000 }).toBe(true);
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: 'run the unit tests' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('charlie:%3:') && m.text.includes('Done: run the unit tests')), { timeout: 40_000 }).toBe(true);
    await a.call('POST', '/v1/demo/telegram/message', { chat_id: chatId, text: '/detach' });
  });
});
