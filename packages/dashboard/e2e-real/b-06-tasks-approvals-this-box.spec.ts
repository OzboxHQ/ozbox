import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// G7 R2, tier B: Tasks (which now holds what Runs showed) and Approvals of a REAL this-box dashboard (a real ozboxd, a real
// `ozbox serve`, signed in). Nothing is mocked. Each page says what it really has: no demo data, no simulated agent, a plain
// statement for a source that cannot answer, and the fact that plans are kept in memory. A task is reviewed but never queued:
// on a developer's computer a real engine could be installed, and a spec must not start one. Starting a run on a real box
// is a tier C step (by hand).
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4184, signIn: true });
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

test('the server is a box, and says outright what each of the two pages reads', async () => {
  const info = (await get('/v1/info')).body as { provider: string; fleet: { mode: string; demo: boolean } };
  expect(info.provider).toBe('thisbox');
  expect(info.fleet.mode).toBe('this_box');
  expect(info.fleet.demo).toBe(false);
  // a box keeps tasks: live, empty, never simulated
  const tasks = await get('/v1/tasks');
  expect(tasks.status).toBe(200);
  expect(tasks.body['source']).toBe('live');
  expect(tasks.body['items']).toEqual([]);
  // plans live in the server's memory, and the answer says so
  const plans = await get('/v1/approvals');
  expect(plans.status).toBe(200);
  expect(plans.body['persisted']).toBe(false);
  expect(plans.body['ttl_s']).toBe(600);
  // no secrets service in this stack: change requests answer "not available", never an error and never a made-up list
  const requests = await get('/v1/approvals/requests');
  expect(requests.status).toBe(200);
  expect(requests.body['available']).toBe(false);
  // tool requests are not available on a box's own dashboard: a typed refusal with words
  const tools = await get(`/v1/boxes/${s.box}/tools/requests`);
  expect(tools.status).toBe(501);
  expect(String(tools.body['error']).length).toBeGreaterThan(5);
});

for (const w of WIDTHS) {
  test(`Runs is gone and Tasks says it has none yet, with no demo and no simulated agent, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/runs`);
    await expect(page).toHaveURL(/\/tasks$/);
    await expect(page.getByRole('heading', { name: 'Tasks', level: 1 })).toBeVisible();
    await expect(page.getByText('No tasks yet')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expect(page.getByText('Simulated')).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Runs', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'New task' })).toBeEnabled();
    await expectNoSidewaysScroll(page);
  });

  test(`New task offers the one engine a box can run, reviews a plan and queues nothing, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/tasks`);
    await page.getByRole('button', { name: 'New task' }).click();
    const sheet = page.getByTestId('new-task-sheet');
    await expect(sheet).toBeVisible();
    await expect(sheet.getByTestId('new-task-no-box')).toHaveCount(0);
    // the engine list: Claude Code, which a box drives; not the simulator and not Codex, which nothing drives yet
    await sheet.getByLabel('Agent engine', { exact: true }).click();
    await expect(page.getByRole('option', { name: 'claude-code' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'fake' })).toHaveCount(0);
    await expect(page.getByRole('option', { name: 'codex' })).toHaveCount(0);
    await page.keyboard.press('Escape');
    // an empty form is refused with a reason
    await sheet.getByRole('button', { name: 'Review plan' }).click();
    await expect(sheet.getByText('Choose a box.')).toBeVisible();
    // the real preview: the plan names the engine and this box, and nothing is queued
    await sheet.getByLabel('Box', { exact: true }).click();
    await page.getByRole('option', { name: s.box }).click();
    await sheet.getByLabel('What should it do?').fill('review only, never queued');
    await sheet.getByRole('button', { name: 'Review plan' }).click();
    await expect(sheet.getByTestId('new-task-plan')).toContainText(`claude-code on ${s.box}`, { timeout: 15_000 });
    await expect(sheet.getByRole('button', { name: 'Queue task' })).toBeInViewport();
    await page.keyboard.press('Escape');
    await expect(sheet).toBeHidden();
    expect(((await get('/v1/tasks')).body['items'] as unknown[]).length).toBe(0);
    await expectNoSidewaysScroll(page);
  });

  test(`Approvals says what each source has, and that plans are kept in memory, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/approvals`);
    await expect(page.getByRole('heading', { name: 'Approvals', level: 1 })).toBeVisible();
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expect(page.getByTestId('plans-memory-note')).toContainText('never on disk', { timeout: 15_000 });
    await expect(page.getByTestId('plans-memory-note')).toContainText('10 minutes');
    // change requests: this box has no secrets service answering, and the page says so rather than showing an empty list
    await expect(page.getByTestId('requests-need-newer-box')).toBeVisible({ timeout: 20_000 });
    // requests from agents: the box's own list, empty
    await expect(page.getByTestId('agent-approvals')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('No agent is waiting for you.')).toBeVisible();
    // tool requests: not available on a box's own dashboard, said as a statement
    await expect(page.getByTestId('tool-requests-unavailable')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('tool-requests-error')).toHaveCount(0);
    // "Nothing waiting" is said, and says the change-request list is not part of it
    await expect(page.getByText('Nothing waiting')).toBeVisible();
    await expect(page.getByText('Change requests are not shown here')).toBeVisible();
    await expectNoSidewaysScroll(page);
  });
}
