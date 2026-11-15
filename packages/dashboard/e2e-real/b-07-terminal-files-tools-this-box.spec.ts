import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn } from '../e2e/auth-fixtures';
import { expectNoSidewaysScroll } from '../e2e/fixtures';
import { startRealThisBox, type RealStack } from './real-stack';
import { WIDTHS } from './support';

// G7 R3, tier B: Files, Tools and the Terminal of a REAL this-box dashboard (a real ozboxd, a real `ozbox serve`, signed in).
// Nothing is mocked. Each page names what it is: no demo note, and the terminal names its box and says its shell is the box
// user's, started by the box's own daemon. The shell's parent process is the DAEMON, never `ozbox serve` (the supervisor's user
// on a real box): that is what "runs as the box user" means on a laptop, where both programs share one login.
test.describe.configure({ mode: 'serial' });

let s: RealStack;
let page: Page;

test.beforeAll(async ({ browser }) => {
  s = await startRealThisBox({ port: 4185, signIn: true });
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

test('the API says live for files, and names the box user for a terminal', async () => {
  const roots = await get(`/v1/boxes/${s.box}/files/roots`);
  expect(roots.status).toBe(200);
  expect(roots.body['source']).toBe('live');
  const r = await page.request.post(`${s.origin}/v1/boxes/${s.box}/terminal`, { data: { cols: 80, rows: 24 }, headers: await writeHeaders() });
  expect(r.status()).toBe(200);
  const body = (await r.json()) as { session: string; target: unknown };
  expect(body.target).toEqual({ box: s.box, source: 'live', runs_as: 'box_user' });
  await page.request.delete(`${s.origin}/v1/terminal/${body.session}`, { headers: await writeHeaders() });
});

async function writeHeaders(): Promise<Record<string, string>> {
  return { 'X-Ozbox-CSRF': await csrf(), Origin: s.origin };
}

async function csrf(): Promise<string> {
  const st = (await (await page.request.get(`${s.origin}/auth/session`)).json()) as { csrf?: string };
  return st.csrf ?? '';
}

for (const w of WIDTHS) {
  test(`the terminal names the box, and its shell is started by the box's daemon, not by the server, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes/${s.box}/terminal`);
    const target = page.getByTestId('terminal-target');
    await expect(target).toContainText(s.box);
    await expect(page.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
    await expect(target).toHaveAttribute('data-source', 'live');
    await expect(target).toHaveAttribute('data-runs-as', 'box_user');
    await expect(target).toContainText('as the box user');
    await expect(page.getByTestId('terminal-source-note')).toHaveCount(0);
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
    await page.getByTestId('terminal-screen').click();
    // the shell's parent process id, between markers the typed command itself does not contain
    await page.keyboard.type(`echo "ppid:$(ps -o ppid= -p $$ | tr -d ' '):end"`);
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('terminal-screen')).toContainText(`ppid:${s.daemon.pid}:end`, { timeout: 10_000 });
    await expect(page.getByTestId('terminal-screen')).not.toContainText(`ppid:${s.serve.pid}:end`);
  });

  test(`Files shows the box's real folder with no demo note at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes/${s.box}/files`);
    await expect(page.getByRole('button', { name: 'projects', exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('files-source-note')).toHaveCount(0);
    await expect(page.getByTestId('files-refresh-error')).toHaveCount(0);
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });

  test(`Tools never shows a demo note, and says what it has or why it has none, at ${w}px`, async () => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${s.origin}/boxes/${s.box}/tools`);
    await expect(page.getByRole('heading', { name: 'Tools', level: 1 })).toBeVisible();
    // one of three honest outcomes, never a blank page: the tools, a statement that this server has none, or the error
    const outcome = page.getByTestId('tools-view').or(page.getByTestId('tools-unavailable')).or(page.getByTestId('tools-error'));
    await expect(outcome).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId('tools-source-note')).toHaveCount(0);
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });
}
