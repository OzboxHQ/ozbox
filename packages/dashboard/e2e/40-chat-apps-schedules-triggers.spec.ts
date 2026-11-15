import { createHmac } from 'node:crypto';

import { expect, test, type APIRequestContext } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// G7 R4, tier A (the demo provider): Chat, Settings -> Apps, Schedules and Triggers. A chat app only notifies (it cannot stop a
// run, the server refuses it), the demo's Telegram says it is a demo, the chat says where its transcript lives, a new schedule
// or trigger runs on an engine a supervisor registers, and what a fired run DID is read from the run, not only the history row.
// The tests that use `page.route` inject a failure the demo server cannot produce on demand, and each is paired with an
// assertion against the real server (what it holds afterwards). Everything else is asserted against the real server, unmocked.
// a seeded demo box (the global setup makes alpha, bravo, charlie and delta)
const BOX = 'charlie';
const CHAT = 4343;
const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });
const call = (request: APIRequestContext, method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown) =>
  request.fetch(`${origin()}${path}`, { method, headers: headers(), ...(data === undefined ? {} : { data }) });
const json = async <T>(r: Awaited<ReturnType<typeof call>>): Promise<T> => (await r.json()) as T;

interface TaskRow {
  id: string;
  state: string;
  error: string | null;
  origin: { kind: string; id?: string };
}
const tasksFrom = async (request: APIRequestContext, kind: string, id: string): Promise<TaskRow[]> => {
  const list = await json<{ items: TaskRow[] }>(await call(request, 'GET', '/v1/tasks'));
  return list.items.filter((t) => t.origin.kind === kind && t.origin.id === id);
};

test('the real server says where chat, schedules and triggers come from, and where the transcript lives', async ({ request }) => {
  const chat = await json<{ source: string; runs_available: boolean; transcript: { kept: string; lines: number; visible_to: string } }>(await call(request, 'GET', '/v1/chat'));
  expect(chat.source).toBe('simulated');
  expect(chat.runs_available).toBe(true);
  expect(chat.transcript).toEqual({ kept: 'memory', lines: 200, visible_to: 'you' });
  expect((await json<{ source: string }>(await call(request, 'GET', '/v1/schedules'))).source).toBe('simulated');
  expect((await json<{ source: string }>(await call(request, 'GET', '/v1/triggers'))).source).toBe('simulated');
  expect((await json<{ telegram: { demo: boolean } }>(await call(request, 'GET', '/v1/apps'))).telegram.demo).toBe(true);
});

test('a new schedule or trigger runs on the engine a supervisor registers, and the old name is made current', async ({ request }) => {
  const made: { schedules: string[]; triggers: string[] } = { schedules: [], triggers: [] };
  try {
    const sched = async (extra: object) => {
      const r = await call(request, 'POST', '/v1/schedules', { name: `r4-eng-${made.schedules.length}`, when_text: 'every day at 3am UTC', prompt: 'Check.', target: { box_name: BOX }, ...extra });
      expect(r.ok(), await r.text()).toBe(true);
      const s = await json<{ id: string; engine: string }>(r);
      made.schedules.push(s.id);
      return s.engine;
    };
    expect(await sched({})).toBe('claude-code');
    expect(await sched({ engine: 'claude' })).toBe('claude-code');
    expect(await sched({ engine: 'fake' })).toBe('fake');
    const trig = async (extra: object) => {
      const r = await call(request, 'POST', '/v1/triggers', { name: `r4-eng-${made.triggers.length}`, template: 'Look at {{id}}.', target: { box_name: BOX }, ...extra });
      expect(r.ok(), await r.text()).toBe(true);
      const t = await json<{ id: string; engine: string }>(r);
      made.triggers.push(t.id);
      return t.engine;
    };
    expect(await trig({})).toBe('claude-code');
    expect(await trig({ engine: 'claude' })).toBe('claude-code');
  } finally {
    for (const id of made.schedules) await call(request, 'DELETE', `/v1/schedules/${id}`);
    for (const id of made.triggers) await call(request, 'DELETE', `/v1/triggers/${id}`);
  }
});

test('a fired schedule is judged by its run: the demo agent finishes it, and a schedule on an engine nobody set up fails in words', async ({ request }) => {
  const ids: string[] = [];
  try {
    const make = async (name: string, engine: string) => {
      const r = await call(request, 'POST', '/v1/schedules', { name, when_text: 'every day at 3am UTC', prompt: 'Check.', engine, target: { box_name: BOX } });
      expect(r.ok(), await r.text()).toBe(true);
      const id = (await json<{ id: string }>(r)).id;
      ids.push(id);
      return id;
    };
    const good = await make('r4-fire-fake', 'fake');
    const bad = await make('r4-fire-unset', 'claude-code');
    for (const id of [good, bad]) expect((await call(request, 'POST', `/v1/schedules/${id}/run-now`)).status()).toBe(202);
    // the RUN, not the history row: the task the schedule queued reaches its own end
    await expect.poll(async () => (await tasksFrom(request, 'schedule', good))[0]?.state, { timeout: 60_000 }).toMatch(/^(done|review)$/);
    await expect.poll(async () => (await tasksFrom(request, 'schedule', bad))[0]?.state, { timeout: 60_000 }).toBe('failed');
    expect((await tasksFrom(request, 'schedule', bad))[0]?.error).toBe('that engine is not set up');
    // and the history says the same, in the same words
    const hist = async (id: string) => (await json<{ runs: { status: string; detail: string }[] }>(await call(request, 'GET', `/v1/schedules/${id}/runs`))).runs;
    await expect.poll(async () => (await hist(good))[0]?.status, { timeout: 40_000 }).toBe('succeeded');
    await expect.poll(async () => (await hist(bad))[0]?.status, { timeout: 40_000 }).toBe('failed');
    expect((await hist(bad))[0]?.detail).toContain('not set up');
  } finally {
    for (const id of ids) await call(request, 'DELETE', `/v1/schedules/${id}`);
    for (const t of (await json<{ items: TaskRow[] }>(await call(request, 'GET', '/v1/tasks'))).items.filter((x) => x.origin.kind === 'schedule' && ['queued', 'running', 'needs_you'].includes(x.state))) {
      await call(request, 'POST', `/v1/tasks/${t.id}/cancel`);
    }
  }
});

test('a delivery to a trigger starts a run whose own end is read, not only the delivery row', async ({ request }) => {
  const made = await json<{ id: string; secret: string }>(await call(request, 'POST', '/v1/triggers', { name: 'r4-fire-trigger', scheme: 'github', engine: 'fake', template: 'Look at {{id}}.', target: { box_name: BOX }, results_to: ['alert'] }));
  try {
    const body = JSON.stringify({ id: 'r4-1' });
    const sig = `sha256=${createHmac('sha256', made.secret).update(body).digest('hex')}`;
    const res = await request.post(`${origin()}/hooks/${made.id}`, { data: body, headers: { 'content-type': 'application/json', 'x-hub-signature-256': sig, 'x-github-delivery': 'r4-delivery-1', 'x-github-event': 'push' } });
    expect(res.status()).toBeLessThan(300);
    await expect.poll(async () => (await tasksFrom(request, 'trigger', made.id))[0]?.state, { timeout: 60_000 }).toMatch(/^(done|review)$/);
  } finally {
    await call(request, 'DELETE', `/v1/triggers/${made.id}`);
  }
});

test('a chat app does not stop a run: /stop from Telegram is refused with a link and the run goes on', async ({ request }) => {
  expect((await call(request, 'PUT', '/v1/secrets/telegram-bot-token', { value: '123:R4_PLAYWRIGHT_SENTINEL' })).ok()).toBe(true);
  const getSettings = async () => (await json<{ settings: { apps: { telegram: { enabled: boolean } }; [k: string]: unknown } }>(await call(request, 'GET', '/v1/settings'))).settings;
  const s = await getSettings();
  s.apps.telegram.enabled = true;
  expect((await call(request, 'PUT', '/v1/settings', s)).ok()).toBe(true);
  const sent = async () => (await json<{ sent: { chat_id: number; text: string; buttons: string[] }[] }>(await call(request, 'GET', '/v1/demo/telegram/sent'))).sent.filter((m) => m.chat_id === CHAT);
  let taskId = '';
  try {
    const { code } = await json<{ code: string }>(await call(request, 'POST', '/v1/apps/telegram/pairing', {}));
    await call(request, 'POST', '/v1/demo/telegram/message', { chat_id: CHAT, text: code, name: 'R4 phone' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('Paired')), { timeout: 20_000 }).toBe(true);
    await call(request, 'POST', '/v1/demo/telegram/message', { chat_id: CHAT, text: `/new ${BOX} r4stop` });
    await expect.poll(async () => (await sent()).some((m) => /Started t\d+ on charlie/.test(m.text)), { timeout: 20_000 }).toBe(true);
    taskId = /Started (t\d+) on charlie/.exec((await sent()).find((m) => /Started t\d+ on charlie/.test(m.text))?.text ?? '')?.[1] ?? '';
    expect(taskId).not.toBe('');
    await call(request, 'POST', '/v1/demo/telegram/message', { chat_id: CHAT, text: '/stop' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('is stopped in the dashboard, not from a chat app')), { timeout: 20_000 }).toBe(true);
    await call(request, 'POST', '/v1/demo/telegram/message', { chat_id: CHAT, text: '/budget +5' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('cap is raised in the dashboard')), { timeout: 20_000 }).toBe(true);
    // no button anywhere, no word of /budget for a chat app, and no link that is only a path (this server has no public address)
    await call(request, 'POST', '/v1/demo/telegram/message', { chat_id: CHAT, text: '/help' });
    await expect.poll(async () => (await sent()).some((m) => m.text.includes('cannot approve, deny, stop')), { timeout: 20_000 }).toBe(true);
    expect((await sent()).every((m) => m.buttons.length === 0)).toBe(true);
    expect((await sent()).every((m) => !m.text.includes('/budget'))).toBe(true);
    expect((await sent()).every((m) => !/Open it there: \//.test(m.text))).toBe(true);
    expect((await sent()).some((m) => m.text.includes('Open the dashboard on the computer that runs it.'))).toBe(true);
    const t = (await json<{ items: TaskRow[] }>(await call(request, 'GET', '/v1/tasks'))).items.find((x) => x.id === taskId);
    expect(t?.state).not.toBe('cancelled');
  } finally {
    if (taskId) await call(request, 'POST', `/v1/tasks/${taskId}/cancel`);
    await call(request, 'POST', '/v1/chat/bind', { task: null });
    await call(request, 'DELETE', `/v1/apps/telegram/chats/${CHAT}`);
    const back = await getSettings();
    back.apps.telegram.enabled = false;
    await call(request, 'PUT', '/v1/settings', back);
  }
});

for (const width of WIDTHS) {
  test.describe(`Chat, Apps, Schedules and Triggers at ${width}px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
    });

    test('Chat says its agent is a demo and where its transcript is kept', async ({ page }) => {
      await open(page, '/chat');
      await expect(page.getByRole('heading', { name: 'Chat', level: 1 })).toBeVisible();
      await expect(page.getByTestId('chat-source-note')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('chat-source-badge')).toHaveText('Simulated');
      const note = page.getByTestId('chat-transcript-note');
      await expect(note).toContainText("dashboard's memory");
      await expect(note).toContainText('shown only to you');
      await expect(page.getByTestId('chat-no-runs')).toHaveCount(0);
      await expect(page.getByText('cannot approve, deny, stop or raise a spending limit').first()).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));
    });

    test('Chat says so when a refresh fails, and keeps what it had', async ({ page, request }) => {
      await open(page, '/chat');
      await expect(page.getByTestId('chat-transcript-note')).toBeVisible({ timeout: 15_000 });
      // real server first: it is up and answers
      expect((await call(request, 'GET', '/v1/chat')).ok()).toBe(true);
      // the one injected failure of this test: the chat overview that the page polls
      await page.route('**/v1/chat?**', (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the server did not answer' }) }));
      await expect(page.getByTestId('chat-stale')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('chat-transcript')).toBeVisible();
      await page.unroute('**/v1/chat?**');
      await expect(page.getByTestId('chat-stale')).toHaveCount(0, { timeout: 15_000 });
    });

    test('Apps labels the demo Telegram and says every chat app only notifies', async ({ page, request }) => {
      await open(page, '/settings/apps');
      const card = page.getByTestId('app-telegram');
      await expect(card).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('telegram-demo-badge')).toHaveText('Simulated');
      await expect(page.getByTestId('telegram-demo-note')).toContainText('not a real chat');
      await expect(page.getByTestId('telegram-notify-only')).toContainText('cannot approve, deny, stop or raise a spending limit');
      await expect(page.getByTestId('agent-chat-notify-only')).toContainText('cannot approve, deny, stop or raise a spending limit');
      // this demo server has no public address, so a chat app is sent words, and the card says why
      expect(((await json<{ public_url_set: boolean }>(await call(request, 'GET', '/v1/apps'))).public_url_set)).toBe(false);
      await expect(page.getByTestId('agent-chat-no-public-url')).toContainText('no public address');
      await expectNoSidewaysScroll(page);
    });

    test('removing a channel whose key cannot be deleted says so, keeps it off, and a second try finishes (real server checked)', async ({ page, request }) => {
      const url = 'https://hooks.slack.com/services/T000/B000/R4PLAYWRIGHTSENTINEL';
      expect((await call(request, 'PUT', '/v1/secrets/slack-webhook-url', { value: url })).ok()).toBe(true);
      const st = (await json<{ settings: { apps: { slack: { enabled: boolean } }; [k: string]: unknown } }>(await call(request, 'GET', '/v1/settings'))).settings;
      st.apps.slack.enabled = true;
      expect((await call(request, 'PUT', '/v1/settings', st)).ok()).toBe(true);
      try {
        await open(page, '/settings/apps');
        const card = page.getByTestId('app-slack');
        await expect(card.getByRole('button', { name: 'Remove' })).toBeVisible({ timeout: 15_000 });
        // the one injected failure: the secret store refuses the delete
        await page.route('**/v1/secrets/slack-webhook-url', (r) => (r.request().method() === 'DELETE' ? r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the secret store did not answer' }) }) : r.continue()));
        await card.getByRole('button', { name: 'Remove' }).click();
        await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
        await expect(page.getByText('are still stored').first()).toBeVisible({ timeout: 15_000 });
        // what the real server holds: turned off, key still there (a consistent, safe state, said in words)
        const apps = await json<{ slack: { enabled: boolean; configured: boolean } }>(await call(request, 'GET', '/v1/apps'));
        expect(apps.slack).toEqual({ enabled: false, configured: true });
        await page.unroute('**/v1/secrets/slack-webhook-url');
        await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
        await expect.poll(async () => (await json<{ slack: { configured: boolean } }>(await call(request, 'GET', '/v1/apps'))).slack.configured, { timeout: 15_000 }).toBe(false);
      } finally {
        await call(request, 'DELETE', '/v1/secrets/slack-webhook-url');
        const back = (await json<{ settings: { apps: { slack: { enabled: boolean } }; [k: string]: unknown } }>(await call(request, 'GET', '/v1/settings'))).settings;
        back.apps.slack.enabled = false;
        await call(request, 'PUT', '/v1/settings', back);
      }
    });

    test('Schedules says its runs use the demo agent, and a new schedule defaults to it', async ({ page }) => {
      await open(page, '/schedules');
      await expect(page.getByRole('heading', { name: 'Schedules', level: 1 })).toBeVisible();
      await expect(page.getByTestId('schedules-source-note')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('schedules-source-badge')).toHaveText('Simulated');
      await page.getByRole('button', { name: 'New schedule' }).first().click();
      const sheet = page.getByTestId('schedule-sheet');
      await expect(sheet.getByRole('combobox', { name: 'Agent' })).toHaveText('fake');
      await sheet.getByRole('combobox', { name: 'Agent' }).click();
      await expect(page.getByRole('option')).toHaveText(['fake', 'claude-code']);
      await expectNoSidewaysScroll(page);
    });

    test('Triggers says its runs use the demo agent, and a new trigger defaults to it', async ({ page }) => {
      await open(page, '/triggers');
      await expect(page.getByRole('heading', { name: 'Triggers', level: 1 })).toBeVisible();
      await expect(page.getByTestId('triggers-source-note')).toBeVisible({ timeout: 15_000 });
      await page.getByRole('button', { name: 'New trigger' }).first().click();
      const sheet = page.getByTestId('trigger-sheet');
      await expect(sheet.getByRole('combobox', { name: 'Agent' })).toHaveText('fake');
      await expectNoSidewaysScroll(page);
    });

    test('Schedules and Triggers say so when the list cannot be refreshed, keeping what they had', async ({ page, request }) => {
      for (const [path, api, key] of [['/schedules', '/v1/schedules', 'schedules'], ['/triggers', '/v1/triggers', 'triggers']] as const) {
        await open(page, path);
        await expect(page.getByTestId(`${key}-source-note`)).toBeVisible({ timeout: 15_000 });
        expect((await call(request, 'GET', api)).ok()).toBe(true);
        const pattern = `**${api}`;
        await page.route(pattern, (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the server did not answer' }) }));
        await expect(page.getByTestId(`${key}-stale`)).toBeVisible({ timeout: 20_000 });
        await page.unroute(pattern);
      }
    });
  });
}
