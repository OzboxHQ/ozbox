import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// G7 R5, tier B: Orchestrations, Browser, Memory and Skills of a REAL this-box dashboard (a real ozboxd, a real `ozbox serve`,
// signed in). Nothing is mocked. On a box nothing is a stand-in, so none of the four shows a demo or simulated note; memory and
// skills say they are kept ON THIS BOX; a skill is installed for this box and the page says which agents may use it. Writes go
// to scratch objects this spec makes and removes (a note, an install).
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4185, signIn: true });
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, { origin: s.origin, code: s.code });
});
test.afterAll(async () => {
  await s?.stop();
});

async function call(method: 'GET' | 'POST' | 'DELETE', path: string, data?: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  // the same request the page makes, with the session's own CSRF value
  const csrf = ((await (await page.request.get(`${s.origin}/auth/session`)).json()) as { csrf?: string }).csrf ?? '';
  const r = await page.request.fetch(`${s.origin}${path}`, { method, headers: { 'x-ozbox-csrf': csrf }, ...(data === undefined ? {} : { data }) });
  return { status: r.status(), body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

test('the server is a box, and the four pages are live, never simulated', async () => {
  const info = (await call('GET', '/v1/info')).body as { provider: string; fleet: { demo: boolean } };
  expect(info.provider).toBe('thisbox');
  expect(info.fleet.demo).toBe(false);
  const orch = await call('GET', '/v1/orchestrations');
  expect(orch.status).toBe(200);
  expect(orch.body['source']).toBe('live');
  expect(orch.body['items']).toEqual([]);
  const browser = await call('GET', '/v1/browser/sessions');
  expect(browser.status).toBe(200);
  expect(browser.body['source']).toBe('live');
  const mem = await call('GET', '/v1/memory');
  expect(mem.body['store']).toEqual({ persisted: true, on_a_box: true, host: s.box });
  const skills = await call('GET', '/v1/skills');
  expect(skills.body['store']).toEqual({ persisted: true, on_a_box: true, host: s.box });
});

for (const w of WIDTHS) {
  test(`Orchestrations and Browser show no demo or simulated note on a box, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/orchestrations`);
    await expect(page.getByRole('heading', { name: 'Orchestrations', level: 1 })).toBeVisible();
    await expect(page.getByText('No orchestrations yet')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('orch-source-note')).toHaveCount(0);
    await expect(page.getByTestId('orch-list-error')).toHaveCount(0);
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expectNoSidewaysScroll(page);

    await page.goto(`${s.origin}/browser`);
    await expect(page.getByRole('heading', { name: 'Browser', level: 1 })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Open now' })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('browser-session')).toHaveCount(0);
    await expect(page.getByTestId('browser-source-note')).toHaveCount(0);
    await expect(page.getByTestId('browser-unavailable')).toHaveCount(0);
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });

  test(`Memory says it is kept on this box, and a note survives a reload, at ${w}px`, async () => {
    const title = `r5-note-${w}`;
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/memory`);
    await expect(page.getByTestId('memory-where')).toContainText(`this box (${s.box})`, { timeout: 15_000 });
    await expect(page.getByTestId('memory-forgotten')).toHaveCount(0);
    await page.getByRole('button', { name: 'Add a note' }).click();
    const sheet = page.getByTestId('mem-sheet');
    await sheet.getByLabel('Whose memory').fill('project:r5');
    await sheet.getByLabel('Title', { exact: true }).fill(title);
    await sheet.getByLabel('Note', { exact: true }).fill('written by the tier B spec; removed at the end');
    await sheet.getByRole('button', { name: 'Save note' }).click();
    await expect(sheet).toHaveCount(0);
    await page.reload();
    await expect(page.getByTestId('mem-note').filter({ hasText: title })).toBeVisible({ timeout: 15_000 });
    await page.getByTestId('mem-note').filter({ hasText: title }).getByRole('button', { name: 'Forget', exact: true }).click();
    await page.getByRole('button', { name: 'Forget note' }).click();
    await expect(page.getByTestId('mem-note').filter({ hasText: title })).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });

  test(`Skills says it is kept on this box and installs for it, at ${w}px`, async () => {
    const name = 'keep-memory';
    await call('POST', `/v1/skills/${name}/uninstall`, { scope: `box:${s.box}` });
    try {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(`${s.origin}/skills`);
      await expect(page.getByTestId('skills-where')).toContainText(`this box (${s.box})`, { timeout: 15_000 });
      const card = page.locator(`[data-testid="skill-card"][data-skill="${name}"]`);
      await card.getByRole('button', { name: 'Install', exact: true }).click();
      const sheet = page.getByTestId('skill-install-sheet');
      await sheet.getByLabel('Where', { exact: true }).click();
      await page.getByRole('option', { name: 'One box' }).click();
      await sheet.getByLabel('Box', { exact: true }).click();
      await page.getByRole('option', { name: s.box }).click();
      await expect(sheet.getByTestId('skill-scope-says')).toContainText(`Orchestration agents on box ${s.box}`);
      await sheet.getByRole('button', { name: 'Install', exact: true }).click();
      await expect(card.getByTestId('skill-install')).toContainText(`Orchestration agents on box ${s.box}`);
      await page.reload();
      await expect(page.locator(`[data-testid="skill-card"][data-skill="${name}"]`).getByTestId('skill-install')).toContainText('Waiting for your review', { timeout: 15_000 });
      await expectNoSidewaysScroll(page);
    } finally {
      await call('POST', `/v1/skills/${name}/uninstall`, { scope: `box:${s.box}` });
    }
  });
}
