import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// G7 R4, tier B: Chat, Settings -> Apps, Schedules and Triggers of a REAL this-box dashboard (a real ozboxd, a real `ozbox serve`,
// signed in). Nothing is mocked. Nothing says "demo": the chat and the runs are live, Telegram is not a stand-in, a new schedule
// or trigger defaults to the one engine a box can run, and the old engine name is made current. No run is fired: on a developer's
// computer a real engine could be installed, and a spec must not start one (firing one is a tier C step, by hand).
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4186, signIn: true });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: s.origin, code: s.code, stop: async () => undefined });
});
test.afterAll(async () => {
  await s?.stop();
});

async function get(path: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await page.request.get(`${s.origin}${path}`);
  return { status: r.status(), body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

async function csrf(): Promise<Record<string, string>> {
  const st = (await (await page.request.get(`${s.origin}/auth/session`)).json()) as { csrf?: string };
  return { 'X-Ozbox-CSRF': st.csrf ?? '', Origin: s.origin };
}

test('the API says live for chat, schedules and triggers, and the Telegram is not a stand-in', async () => {
  const chat = await get('/v1/chat');
  expect(chat.status).toBe(200);
  expect(chat.body['source']).toBe('live');
  expect(chat.body['runs_available']).toBe(true);
  expect(chat.body['transcript']).toEqual({ kept: 'memory', lines: 200, visible_to: 'you' });
  expect((await get('/v1/schedules')).body['source']).toBe('live');
  expect((await get('/v1/triggers')).body['source']).toBe('live');
  expect(((await get('/v1/apps')).body['telegram'] as { demo: boolean }).demo).toBe(false);
});

test('a schedule and a trigger made with no engine, or the old name, run on claude-code (and are removed again)', async () => {
  const h = await csrf();
  const mkSched = await page.request.post(`${s.origin}/v1/schedules`, { headers: h, data: { name: 'r4-b-sched', when_text: 'every day at 3am UTC', prompt: 'Check.', engine: 'claude', enabled: false, target: { box_name: s.box } } });
  expect(mkSched.status(), await mkSched.text()).toBeLessThan(300);
  const sch = (await mkSched.json()) as { id: string; engine: string };
  const mkTrig = await page.request.post(`${s.origin}/v1/triggers`, { headers: h, data: { name: 'r4-b-trig', template: 'Look at {{id}}.', enabled: false, target: { box_name: s.box } } });
  expect(mkTrig.status(), await mkTrig.text()).toBeLessThan(300);
  const trg = (await mkTrig.json()) as { id: string; engine: string };
  try {
    expect(sch.engine).toBe('claude-code');
    expect(trg.engine).toBe('claude-code');
  } finally {
    await page.request.delete(`${s.origin}/v1/schedules/${sch.id}`, { headers: await csrf() });
    await page.request.delete(`${s.origin}/v1/triggers/${trg.id}`, { headers: await csrf() });
  }
});

for (const w of WIDTHS) {
  test(`Chat, Apps, Schedules and Triggers name nothing as a demo, and offer the one engine a box runs, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/chat`);
    await expect(page.getByRole('heading', { name: 'Chat', level: 1 })).toBeVisible();
    await expect(page.getByTestId('chat-transcript-note')).toContainText("dashboard's memory", { timeout: 15_000 });
    await expect(page.getByTestId('chat-source-note')).toHaveCount(0);
    await expect(page.getByTestId('chat-no-runs')).toHaveCount(0);
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);

    await page.goto(`${s.origin}/settings/apps`);
    await expect(page.getByTestId('app-telegram')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('telegram-demo-note')).toHaveCount(0);
    await expect(page.getByTestId('telegram-notify-only')).toContainText('cannot approve, deny, stop or raise a spending limit');

    await page.goto(`${s.origin}/schedules`);
    await expect(page.getByRole('heading', { name: 'Schedules', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'New schedule' }).first()).toBeEnabled({ timeout: 15_000 });
    await expect(page.getByTestId('schedules-source-note')).toHaveCount(0);
    await page.getByRole('button', { name: 'New schedule' }).first().click();
    const sheet = page.getByTestId('schedule-sheet');
    await expect(sheet.getByRole('combobox', { name: 'Agent' })).toHaveText('claude-code');
    await sheet.getByRole('combobox', { name: 'Agent' }).click();
    await expect(page.getByRole('option')).toHaveText(['claude-code']);
    await page.keyboard.press('Escape');
    await page.keyboard.press('Escape');
    await expectNoSidewaysScroll(page);

    await page.goto(`${s.origin}/triggers`);
    await expect(page.getByRole('heading', { name: 'Triggers', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'New trigger' }).first()).toBeEnabled({ timeout: 15_000 });
    await expect(page.getByTestId('triggers-source-note')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });
}
