import { expect, test, type Locator, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The secret store here is memory, and nothing in these tests sends a message to an outside service: a "Send test
// alert" reaches a provider, so these tests stop before it. Credentials entered are fake.

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

test('every channel has its own card, and a text-message provider is set up write-only', async ({ page }) => {
  await open(page, '/settings/apps');
  for (const id of ['email', 'sms', 'telegram', 'slack', 'whatsapp', 'discord', 'teams', 'push', 'webhooks']) {
    await expect(page.getByTestId(id === 'webhooks' ? 'app-webhooks' : `app-${id}`)).toBeVisible();
  }
  const sms = page.getByTestId('app-sms');
  await expect(sms.getByText('Not connected')).toBeVisible();
  await expect(sms.getByRole('button', { name: 'Send test alert' })).toBeDisabled();
  await sms.getByRole('button', { name: 'Set up' }).click();
  const sheet = page.getByTestId('sms-sheet');
  await sheet.getByLabel('Send from').fill('not a number!');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  await sheet.getByLabel('Send from').fill('+15005550006');
  const sid = sheet.getByLabel('Account SID');
  await expect(sid).toHaveAttribute('type', 'password');
  await sid.fill('ACPLAYWRIGHTSENTINEL0001');
  await sheet.getByLabel('Auth token').fill('PLAYWRIGHT_SENTINEL_TOKEN');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  await expect(sms.getByText('Connected', { exact: false }).first()).toBeVisible();

  // Amazon SNS needs no pasted credential: the fields disappear and the note says why.
  await sms.getByRole('button', { name: 'Edit' }).click();
  await sheet.getByLabel('Provider').click();
  await page.getByRole('option', { name: 'Amazon SNS' }).click();
  await expect(sheet.getByLabel('Account SID')).toHaveCount(0);
  await expect(sheet.getByText('nothing to paste')).toBeVisible();
  await sheet.getByRole('button', { name: 'Cancel' }).click();

  expect(await page.content()).not.toContain('PLAYWRIGHT_SENTINEL');
  const u = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const token = u.hash.replace('#token=', '');
  for (const path of ['/v1/settings', '/v1/apps', '/v1/secrets', '/v1/activity']) {
    const res = await page.request.get(`${u.origin}${path}`, { headers: { Authorization: `Bearer ${token}` } });
    expect(await res.text(), path).not.toContain('PLAYWRIGHT_SENTINEL');
  }
});

test('Discord and Teams only accept their own addresses', async ({ page }) => {
  await open(page, '/settings/apps');
  const discord = page.getByTestId('app-discord');
  await discord.getByRole('button', { name: 'Set up' }).click();
  const sheet = page.getByTestId('discord-sheet');
  await sheet.getByLabel('Webhook address').fill('https://evil.example/api/webhooks/1/x');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  await sheet.getByLabel('Webhook address').fill('https://discord.com/api/webhooks/1/PLAYWRIGHT_SENTINEL');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  await expect(discord.getByText('Connected', { exact: false }).first()).toBeVisible();
  await discord.getByRole('button', { name: 'Remove' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
  await expect(discord.getByText('Not connected')).toBeVisible();
});

test('Routing: add a person, read what the rules mean, and remove them', async ({ page }) => {
  await open(page, '/settings/apps');
  const section = page.getByTestId('routing-section');
  await section.getByRole('button', { name: 'Add a person' }).click();
  const sheet = page.getByTestId('routing-sheet');
  await sheet.getByLabel('Short name').fill('Bad Name');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  await sheet.getByLabel('Short name').fill('ada');
  await sheet.getByLabel('Phone number for texts').fill('+2348012345678');
  // Fixed quiet hours, so the lines below do not depend on the fleet's settings.
  await sheet.getByLabel('Quiet from').fill('22:00');
  await sheet.getByLabel('Quiet until').fill('07:00');
  // The defaults, in plain words.
  const preview = sheet.getByTestId('routing-preview');
  await expect(preview).toContainText(/Urgent alerts at 2am .* time go to SMS, Telegram, and Push\./);
  await expect(preview).toContainText(/Normal alerts at 2pm .* time go to Telegram and Slack\./);
  await expect(preview).toContainText('held for the daily summary');
  // Taking the bypass away changes the 2am urgent line.
  await sheet.getByLabel('Urgent alerts break through quiet hours').click();
  await expect(preview).toContainText(/Urgent alerts at 2am .* are held for the daily summary/);
  await sheet.getByLabel('Urgent alerts break through quiet hours').click();
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();
  const row = section.getByTestId('routing-person-ada');
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Edit rules' }).click();
  await expect(sheet.getByLabel('Phone number for texts')).toHaveValue('+2348012345678');
  await sheet.getByRole('button', { name: 'Cancel' }).click();
  await row.getByRole('button', { name: 'Remove this person' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
  await expect(section.getByText('No one has routing rules yet.')).toBeVisible();
});

for (const width of WIDTHS) {
  test(`channels and routing at ${width}px: no sideways scroll${width < 1024 ? ', 44px targets' : ''}, accessible`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/settings/apps');
    await expect(page.getByTestId('routing-section')).toBeVisible();
    await page.waitForTimeout(300);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
    // The whole page content, recent alerts (with their red "Urgent" badge) included.
    await axeClean(page, 'main');

    // An earlier test in this file already set SMS up, so the button may read Edit.
    await page.getByTestId('app-sms').getByRole('button', { name: /^(Set up|Edit)$/ }).click();
    const sms = page.getByTestId('sms-sheet');
    await expect(sms.getByRole('button', { name: 'Save' })).toBeInViewport();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, sms);
    await sms.getByRole('button', { name: 'Cancel' }).click();

    await page.getByTestId('routing-section').getByRole('button', { name: 'Add a person' }).click();
    const sheet = page.getByTestId('routing-sheet');
    await expect(sheet.getByRole('button', { name: 'Save' })).toBeInViewport();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page, '[data-testid="routing-sheet"]');
    // schedules and triggers have their own rule: how their alerts reach this person
    const rule = sheet.getByTestId('routing-schedule-rule');
    await rule.scrollIntoViewIfNeeded();
    await expect(rule.getByRole('combobox', { name: 'How should these reach this person?' })).toContainText('The usual way for each alert');
    await rule.getByRole('combobox').click();
    await expect(page.getByRole('option', { name: 'Do not tell this person' })).toBeVisible();
    await page.keyboard.press('Escape');
  });
}

// ---------------------------------------------------------------------------------------------------------------
// Telegram linking, the background test send and what became of each alert.
//
// The demo server has a local stand-in for Telegram (OZBOX_DEMO_TELEGRAM=1 in global setup), so a chat is paired by
// saying the real one-time code to the demo bot. Nothing here reaches Telegram or any other outside service, and no
// person below has a phone number or an email address, so no text or mail could be sent even by mistake.

const base = () => new URL(process.env['OZBOX_E2E_URL'] ?? '');
const authHeader = () => ({ Authorization: `Bearer ${base().hash.replace('#token=', '')}` });

interface SettingsDoc {
  apps: { telegram: { enabled: boolean }; sms: { enabled: boolean; provider: string; from: string } };
  routing: { people: Record<string, unknown> };
  [k: string]: unknown;
}

function makeApi(page: Page) {
  const call = async (method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown) => {
    const res = await page.request.fetch(`${base().origin}${path}`, { method, headers: authHeader(), ...(data === undefined ? {} : { data }) });
    return res;
  };
  return {
    call,
    json: async <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown): Promise<T> => {
      const res = await call(method, path, data);
      expect(res.ok(), `${method} ${path} -> ${res.status()}`).toBe(true);
      return (await res.json()) as T;
    },
  };
}

type Api = ReturnType<typeof makeApi>;

const person = (over: Record<string, unknown> = {}) => ({
  time_zone: 'UTC',
  quiet_from: '00:00',
  quiet_to: '00:00', // equal ends: never quiet
  phone: null,
  whatsapp: null,
  emails: [],
  push: [],
  urgent: { channels: ['telegram'], bypass_quiet: true },
  normal: { channels: ['telegram'], bypass_quiet: false },
  digest: { enabled: false, time: '08:00', channels: [] },
  ...over,
});

/** The bot is on (a fake token, kept write-only) and exactly these people have routing rules. */
async function setUpTelegram(api: Api, people: Record<string, unknown>, sms = false) {
  expect((await api.call('PUT', '/v1/secrets/telegram-bot-token', { value: '123:PLAYWRIGHT_SENTINEL' })).ok()).toBe(true);
  if (sms) {
    expect((await api.call('PUT', '/v1/secrets/sms-account', { value: 'ACPLAYWRIGHTSENTINEL0002' })).ok()).toBe(true);
    expect((await api.call('PUT', '/v1/secrets/sms-secret', { value: 'PLAYWRIGHT_SENTINEL_TOKEN2' })).ok()).toBe(true);
  }
  const { settings } = await api.json<{ settings: SettingsDoc }>('GET', '/v1/settings');
  settings.apps.telegram.enabled = true;
  if (sms) settings.apps.sms = { ...settings.apps.sms, enabled: true, provider: 'twilio', from: '+15005550006' };
  settings.routing.people = people;
  const res = await api.call('PUT', '/v1/settings', settings);
  expect(res.ok(), await res.text()).toBe(true);
}

interface ChatDoc {
  id: number;
  name: string;
  person?: string | null;
}
const chatsOf = async (api: Api) => (await api.json<{ telegram: { chats: ChatDoc[] } }>('GET', '/v1/apps')).telegram.chats;

/**
 * Put a chat on the list that receives alerts, for a person. Linking a real account is a passkey flow of its own (see
 * `46-telegram-links.spec.ts`), which this token-mode server cannot do, so the demo bot's route puts the chat there the way a chat
 * linked before passkey links is: it is told things and reads, nothing more.
 */
async function pairChat(api: Api, who: string, chatId: number, name: string) {
  await api.json('POST', '/v1/demo/telegram/legacy-chat', { chat_id: chatId, name, person: who });
  await expect.poll(async () => (await chatsOf(api)).some((c) => c.id === chatId && c.person === who), { timeout: 20_000 }).toBe(true);
}

async function tidy(api: Api) {
  for (const c of await chatsOf(api)) await api.call('DELETE', `/v1/apps/telegram/chats/${c.id}`);
  const { settings } = await api.json<{ settings: SettingsDoc }>('GET', '/v1/settings');
  settings.routing.people = {};
  settings.apps.telegram.enabled = false;
  settings.apps.sms.enabled = false;
  await api.call('PUT', '/v1/settings', settings);
}

const HOUR = 60 * 60 * 1000;
const hhmm = (at: number) => new Date(at).toISOString().slice(11, 16);

test.describe('Telegram linking, the background test send and alert outcomes', () => {
  test.afterEach(async ({ page }) => {
    await tidy(makeApi(page));
  });

  for (const width of WIDTHS) {
    test(`a chat on the list for a person shows under their rules and on the Telegram card, and is unlinked, at ${width}px`, async ({ page }) => {
      const api = makeApi(page);
      const chatId = 7000 + width;
      await page.setViewportSize({ width, height: 900 });
      await setUpTelegram(api, { 'qa-tg': person() });
      await open(page, '/settings/apps');

      const row = page.getByTestId('routing-person-qa-tg');
      await row.getByRole('button', { name: 'Edit rules' }).click();
      const sheet = page.getByTestId('routing-sheet');
      const chats = sheet.getByTestId('routing-chats');
      await expect(chats.getByText('No chat is paired with the bot yet.')).toBeVisible();

      // Linking an account is the person's own, with their passkey: this sheet sends them to their Account page.
      const toAccount = chats.getByTestId('routing-chat-link-account');
      await expect(toAccount).toHaveAttribute('href', '/account');
      await expect(toAccount).toBeInViewport();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, sheet);

      // A chat that is on the list for this person (the demo bot's route stands in for the old pairing).
      await api.json('POST', '/v1/demo/telegram/legacy-chat', { chat_id: chatId, name: 'Ada phone', person: 'qa-tg' });
      await sheet.getByRole('button', { name: 'Cancel' }).click();
      await row.getByRole('button', { name: 'Edit rules' }).click();

      // It is ticked under this person's rules.
      const tick = chats.getByRole('checkbox', { name: 'Ada phone' });
      await expect(tick).toBeChecked();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, '[data-testid="routing-sheet"]');
      // The bot said hello in that chat.
      await expect.poll(async () => JSON.stringify((await api.json<{ sent: { chat_id: number }[] }>('GET', '/v1/demo/telegram/sent')).sent)).toContain(`"chat_id":${chatId}`);
      await sheet.getByRole('button', { name: 'Cancel' }).click();

      // The Telegram card lists it as theirs.
      const card = page.getByTestId('app-telegram');
      const listed = card.getByRole('list', { name: 'Paired chats' }).getByRole('listitem').filter({ hasText: 'Ada phone' });
      await expect(listed).toContainText(/Alerts for .*qa-tg/);

      // Unlink it from their rules: the card says it belongs to no one.
      await row.getByRole('button', { name: 'Edit rules' }).click();
      await tick.click();
      await expect(tick).not.toBeChecked();
      await sheet.getByRole('button', { name: 'Cancel' }).click();
      await expect(listed).toContainText('Not linked to a person');

      // Unpair it from the card.
      await listed.getByRole('button', { name: 'Unpair' }).click();
      await page.getByRole('alertdialog').getByRole('button', { name: 'Unpair' }).click();
      await expect(card.getByText('No chat is paired yet.')).toBeVisible();
      expect(await chatsOf(api)).toEqual([]);
      expect(await page.content()).not.toContain('PLAYWRIGHT_SENTINEL');
    });
  }

  test('Send test follows each channel: a paired chat is sent, a person with no phone is told why', async ({ page }) => {
    const api = makeApi(page);
    await setUpTelegram(api, { 'qa-tg': person() }, true);
    await pairChat(api, 'qa-tg', 7100, 'Ada phone');
    await open(page, '/settings/apps');

    // Telegram: the chat answers, and its line says Sent.
    const tg = page.getByTestId('app-telegram');
    await tg.getByRole('button', { name: 'Send test alert' }).click();
    const sent = tg.getByTestId('test-results').getByTestId('test-item');
    await expect(sent).toHaveCount(1);
    await expect(sent).toHaveAttribute('data-status', 'sent', { timeout: 20_000 });
    await expect(sent).toContainText('Telegram');

    // Text messages: the person has no number, so the line says Failed and why. Nothing leaves this computer.
    const sms = page.getByTestId('app-sms');
    await sms.getByRole('button', { name: 'Send test alert' }).click();
    const failed = sms.getByTestId('test-results').getByTestId('test-item');
    await expect(failed).toHaveAttribute('data-status', 'failed', { timeout: 20_000 });
    await expect(failed.getByTestId('test-detail')).toContainText('no phone number');
    await sms.getByTestId('test-results').getByRole('button', { name: 'Close' }).click();
    await expect(sms.getByTestId('test-results')).toHaveCount(0);

    // The run is a resource of its own: asking for it by id lists each channel, and an unknown id is not found.
    const started = await api.json<{ id: string; state: string; items: { status: string }[] }>('POST', '/v1/alerts/test', { channel: 'telegram', person: 'qa-tg', async: true });
    expect(started.id).toMatch(/^[0-9a-f]{16}$/);
    await expect.poll(async () => (await api.json<{ state: string }>('GET', `/v1/alerts/tests/${started.id}`)).state).toBe('done');
    expect((await api.call('GET', '/v1/alerts/tests/nope')).status()).toBe(404);
  });

  test('a busy Telegram reads Retrying and then Delivered; one that stays down reads Failed after 4 tries', async ({ page }) => {
    const api = makeApi(page);
    await setUpTelegram(api, { 'qa-retry': person() });
    await pairChat(api, 'qa-retry', 7300, 'Retry phone');
    const outcomeOf = async (title: string) =>
      (await api.json<{ entries: { title: string; outcome?: string }[] }>('GET', '/v1/alerts')).entries.find((e) => e.title === title)?.outcome;
    try {
      // The demo bot answers 503 once; the server waits the demo's pause (long enough to be seen) and tries again.
      const busy = `Playwright busy bot at ${Date.now()}`;
      await api.json('POST', '/v1/demo/telegram/fail', { count: 1, retry_ms: 8000 });
      expect((await api.call('POST', '/v1/demo/alerts', { title: busy })).status()).toBe(202);
      await expect.poll(() => outcomeOf(busy), { timeout: 20_000 }).toBe('retrying');
      await open(page, '/settings/apps');
      const recent = page.getByTestId('recent-alerts');
      const item = recent.getByRole('listitem').filter({ hasText: busy }).first();
      await expect(item.getByTestId('alert-outcome')).toHaveAttribute('data-outcome', 'retrying');
      await expect(item).toContainText('qa-retry: Retrying (Telegram retrying: ');
      await expectNoSidewaysScroll(page);
      await axeClean(page, '[data-testid="recent-alerts"]');
      // The second try lands: the same alert now reads Delivered, with the two tries behind it.
      await expect.poll(() => outcomeOf(busy), { timeout: 40_000 }).toBe('delivered');
      await page.reload();
      const done = page.getByTestId('recent-alerts').getByRole('listitem').filter({ hasText: busy }).first();
      await expect(done.getByTestId('alert-outcome')).toHaveAttribute('data-outcome', 'delivered');
      await expect(done).toContainText('qa-retry: Delivered (Telegram)');

      // Four 503s in a row are every try there is: the alert ends as failed, and says how many tries it had.
      const down = `Playwright bot down at ${Date.now()}`;
      await api.json('POST', '/v1/demo/telegram/fail', { count: 4, retry_ms: 500 });
      expect((await api.call('POST', '/v1/demo/alerts', { title: down })).status()).toBe(202);
      await expect.poll(() => outcomeOf(down), { timeout: 40_000 }).toBe('failed');
      await page.reload();
      const failed = page.getByTestId('recent-alerts').getByRole('listitem').filter({ hasText: down }).first();
      await expect(failed.getByTestId('alert-outcome')).toHaveAttribute('data-outcome', 'failed');
      await expect(failed).toContainText('qa-retry: Delivery failed (Telegram failed after 4 tries: ');
      await expectNoSidewaysScroll(page);
      await axeClean(page, '[data-testid="recent-alerts"]');
    } finally {
      await api.call('POST', '/v1/demo/telegram/fail', { count: 0, retry_ms: 3000 });
    }
  });

  for (const width of WIDTHS) {
    test(`recent alerts and the daily summary say what became of each alert, at ${width}px`, async ({ page }) => {
      const api = makeApi(page);
      const now = Date.now();
      await page.setViewportSize({ width, height: 900 });
      await setUpTelegram(
        api,
        {
          // Quiet around now, so a normal alert is held for the summary.
          'qa-quiet': person({ quiet_from: hhmm(now - HOUR), quiet_to: hhmm(now + HOUR) }),
          // Awake, with a paired chat: delivered.
          'qa-live': person({ time_zone: 'Asia/Tokyo' }),
          // Asks for texts but has no number: not sent.
          'qa-nowhere': person({ normal: { channels: ['sms'], bypass_quiet: false } }),
        },
        true,
      );
      await pairChat(api, 'qa-live', 7200 + width, 'Live phone');
      const title = `Playwright demo alert ${width} at ${now}`; // unique, so a retried run counts only its own rows
      expect((await api.call('POST', '/v1/demo/alerts', { title })).status()).toBe(202);
      // A test send is recorded too, and has no outcome: it must read as an em dash.
      await api.json('POST', '/v1/alerts/test', { channel: 'telegram', person: 'qa-live', async: true });
      await expect.poll(async () => (await api.json<{ entries: { title: string; outcomes?: unknown[]; kind: string }[] }>('GET', '/v1/alerts')).entries.some((e) => e.title === title), { timeout: 20_000 }).toBe(true);

      // The day the server filed the alert under. A run that crosses midnight would otherwise open "today" a day late,
      // so every time the summary falls back to its default day this day is chosen again (see pinDay).
      const alertDay = (await api.json<{ date: string }>('GET', '/v1/alerts/summary')).date;
      const pinDay = async (summaryRoot: Locator) => {
        const dayBox = summaryRoot.getByTestId('summary-day');
        await expect(dayBox).toHaveText(/^\d{4}-\d{2}-\d{2}$/);
        if (((await dayBox.textContent()) ?? '').trim() !== alertDay) {
          await dayBox.click();
          await page.getByRole('option', { name: alertDay }).click();
        }
        await expect(dayBox).toHaveText(alertDay);
      };

      await open(page, '/settings/apps');
      const recent = page.getByTestId('recent-alerts');
      const item = recent.getByRole('listitem').filter({ hasText: title }).first();
      await expect(item.getByTestId('alert-outcome')).toHaveAttribute('data-outcome', 'delivered');
      await expect(item).toContainText('qa-live: Delivered (Telegram)');
      await expect(item).toContainText('qa-quiet: Held: quiet hours (Telegram)');
      await expect(item).toContainText('qa-nowhere: Not sent (SMS)');
      const testItem = recent.getByRole('listitem').filter({ hasText: 'Test alert from Oz Box' }).first();
      await expect(testItem.getByTestId('alert-outcome')).toHaveAttribute('data-outcome', 'none');
      await expect(testItem.getByTestId('alert-outcome')).toContainText('—');
      await expectNoSidewaysScroll(page);
      await axeClean(page, '[data-testid="recent-alerts"]');

      // The daily summary lists the day's alerts with a tag for each person's outcome.
      await recent.getByRole('button', { name: 'Daily summary' }).click();
      const summary = page.getByTestId('summary-sheet');
      await pinDay(summary);
      await expect(summary.getByTestId('summary-items')).toBeVisible();
      const rows = summary.getByTestId('summary-item').filter({ hasText: title });
      await expect(rows).toHaveCount(3);
      await expect(rows.filter({ hasText: 'qa-live' })).toHaveAttribute('data-status', 'delivered');
      await expect(rows.filter({ hasText: 'qa-quiet' })).toHaveAttribute('data-status', 'held_quiet');
      await expect(rows.filter({ hasText: 'qa-nowhere' })).toHaveAttribute('data-status', 'not_sent');
      await expect(rows.filter({ hasText: 'qa-quiet' })).toContainText('Held: quiet hours');
      await expect(summary.getByTestId('summary-counts')).toContainText(/\d+ delivered, \d+ held, \d+ not sent/);
      await expect(summary.getByRole('button', { name: 'Close' }).last()).toBeInViewport();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, summary);
      await axeClean(page, '[data-testid="summary-sheet"]');

      // One person's day: their rows only, and the day follows their own time zone.
      await summary.getByTestId('summary-person').click();
      await page.getByRole('option', { name: 'qa-live' }).click();
      await expect(summary.getByTestId('summary-zone')).toContainText('Asia/Tokyo');
      const mine = summary.getByTestId('summary-item').filter({ hasText: title });
      await expect(mine).toHaveCount(1);
      await expect(mine).toHaveAttribute('data-status', 'delivered');
      await expect(summary.getByTestId('summary-item').filter({ hasText: 'qa-quiet' })).toHaveCount(0);
      await expect(summary.getByTestId('summary-day')).toHaveText(/^\d{4}-\d{2}-\d{2}$/);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, summary);
      await axeClean(page, '[data-testid="summary-sheet"]');
      await summary.getByTestId('summary-person').click();
      await page.getByRole('option', { name: 'Everyone (fleet time zone)' }).click();
      await pinDay(summary);
      await expect(summary.getByTestId('summary-item').filter({ hasText: title })).toHaveCount(3);

      // The day before the alert's day has none of its alerts.
      const yesterday = new Date(`${alertDay}T00:00:00Z`);
      yesterday.setUTCDate(yesterday.getUTCDate() - 1);
      await summary.getByTestId('summary-day').click();
      await page.getByRole('option', { name: yesterday.toISOString().slice(0, 10) }).click();
      await expect(summary.getByTestId('summary-none')).toBeVisible();
      await summary.getByRole('button', { name: 'Close' }).last().click();
      await expect(summary).toBeHidden();
    });
  }
});
