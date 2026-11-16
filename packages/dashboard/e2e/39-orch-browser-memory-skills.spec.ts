import { execFileSync } from 'node:child_process';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// G7 R5, tier A (the demo provider): Orchestrations, Browser, Memory and Skills say what is real. The demo's agents and browser
// are stand-ins and say so; memory and skills say where they are kept; a skill's install says which agents may use it; a
// role that may not change a page is offered nothing to change. A `page.route` appears only where the real server cannot be
// made to answer that way (a server with no task store), and always beside an assertion against the real server.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function getJson(request: APIRequestContext, path: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await request.get(`${origin()}${path}`, { headers: headers() });
  return { status: r.status(), body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

/**
 * Answer a page's reads of `path` with the real server's own body plus `change`. The real body is read once, up front, by the
 * test's own request; the route then answers at once and never waits on anything. (The page cancels a read it no longer wants:
 * a refresh that starts while another is in flight, a navigation. A handler that was in the middle of fetching the real answer
 * for that read lost its response with "Response has been disposed", and the test failed for a read nobody was waiting on.)
 */
async function overlay(page: Page, request: APIRequestContext, path: string, change: (real: Record<string, unknown>) => Record<string, unknown>): Promise<void> {
  const real = await getJson(request, path);
  expect(real.status, `the real server answers ${path}`).toBe(200);
  const json = change(real.body);
  await page.route((u) => u.pathname === path, (route) => route.fulfill({ status: 200, json }));
}

const RULES = '---\nengine: fake\nmerge_approval: person\ntest_command: make test\n---\nSmall commits.';

test('raising an orchestration cap says it was raised, not that it failed', async ({ page, request }) => {
  const goal = 'orch-39 raise the cap';
  const made = await request.post(`${origin()}/v1/orchestrations`, { headers: headers(), data: { goal, conductor_box: 'alpha', rules: RULES } });
  expect(made.status()).toBe(201);
  const id = ((await made.json()) as { id: string }).id;
  try {
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, '/orchestrations');
    const card = page.getByTestId('orch-card').filter({ hasText: goal });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await card.getByRole('button', { name: 'Open' }).click();
    await page.getByLabel('Add to the cap (US dollars)').fill('5');
    await page.getByRole('button', { name: 'Add budget' }).click();
    await expect(page.getByText('The cap was raised.')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('That did not work')).toHaveCount(0);
  } finally {
    await request.post(`${origin()}/v1/orchestrations/${id}/stop`, { headers: headers(), data: {} });
  }
});

test('Browser take-over says when a click or key did not reach the browser, once, and sends nothing more until dismissed', async ({ page }) => {
  // the take-over needs a real Chromium, which this harness does not start: the pictures and the refusal are the server's
  // answers as a held session gives them, supplied here
  const session = 'b-39-input';
  await page.route((u) => u.pathname === '/v1/browser/sessions', (route) =>
    route.fulfill({
      json: {
        live: [{ id: session, box: 'alpha' }],
        recordings: [{ session, box: 'alpha', started_ms: 1, last_ms: 2, ended_ms: null, device: 'desktop', run: null, state: 'taken_over', actions: 1, paused_reason: null, live: true }],
        source: 'simulated',
        unreachable: [],
      },
    }),
  );
  const px = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
  await page.route(`**/v1/browser/sessions/${session}/frame`, (route) => route.fulfill({ json: { jpeg: px, page: 'https://example.test/', control: 'person', device: 1280 } }));
  await page.route((u) => u.pathname === `/v1/browser/sessions/${session}`, (route) =>
    route.fulfill({ json: { session, control: 'person', held_reason: '', actions: 1, max_actions: 50, minutes: 1, max_minutes: 30, device: 'desktop', holder: 'owner' } }),
  );
  let inputs = 0;
  await page.route(`**/v1/browser/sessions/${session}/input`, (route) => {
    inputs += 1;
    return route.fulfill({ status: 409, json: { code: 'session_closed', message: 'That browser session has closed.' } });
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, '/browser');
  await page.getByRole('button', { name: 'Watch' }).first().click();
  const live = page.getByTestId('browser-live-sheet');
  await expect(live.getByTestId('browser-picture')).toBeVisible({ timeout: 15_000 });
  const picture = live.getByTestId('browser-picture');
  await picture.focus();
  await picture.press('a');
  const err = live.getByTestId('browser-input-error');
  await expect(err).toBeVisible({ timeout: 10_000 });
  await expect(err).toContainText('That browser session has closed.');
  await picture.press('b');
  await picture.press('c');
  await expect.poll(() => inputs).toBe(1);
  await err.getByRole('button', { name: 'Dismiss and try again' }).click();
  await expect(err).toHaveCount(0);
  await picture.press('d');
  await expect(err).toBeVisible({ timeout: 10_000 });
  expect(inputs).toBe(2);
});

// each width uses its own skill so a retry or another width never meets this one's state
const SKILL: Record<number, string> = { 390: 'ci-failure-triage', 820: 'eval-runner', 1024: 'keep-memory', 1440: 'reply-drafter' };

for (const width of WIDTHS) {
  test(`Orchestrations says its agents are simulated and shows no failure, at ${width}px`, async ({ page, request }) => {
    const api = await getJson(request, '/v1/orchestrations');
    expect(api.status).toBe(200);
    expect(api.body['source']).toBe('simulated');
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/orchestrations');
    await expect(page.getByRole('heading', { name: 'Orchestrations', level: 1 })).toBeVisible();
    await expect(page.getByTestId('demo-banner')).toBeVisible();
    const note = page.getByTestId('orch-source-note');
    await expect(note).toBeVisible({ timeout: 15_000 });
    await expect(note).toContainText('simulated');
    await expect(page.getByTestId('orch-source-badge')).toHaveText('Simulated');
    await expect(page.getByTestId('orch-list-error')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
  });

  test(`Orchestrations says why its list could not be read instead of showing nothing, at ${width}px`, async ({ page, request }) => {
    expect((await getJson(request, '/v1/orchestrations')).status).toBe(200);
    await page.route('**/v1/orchestrations', (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'store_unavailable', message: 'the store could not be read' }) }));
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/orchestrations');
    const err = page.getByTestId('orch-list-error');
    await expect(err).toBeVisible({ timeout: 15_000 });
    await expect(err).toContainText('could not be read');
    await expect(err).toContainText('the store could not be read');
    await expectNoSidewaysScroll(page);
  });

  test(`Browser says its browser is a stand-in, at ${width}px`, async ({ page, request }) => {
    const api = await getJson(request, '/v1/browser/sessions');
    expect(api.status).toBe(200);
    expect(api.body['source']).toBe('simulated');
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/browser');
    await expect(page.getByRole('heading', { name: 'Browser', level: 1 })).toBeVisible();
    const note = page.getByTestId('browser-source-note');
    await expect(note).toBeVisible({ timeout: 15_000 });
    await expect(note).toContainText('stand-in browser');
    await expect(page.getByTestId('browser-unavailable')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
  });

  test(`Browser says plainly that this server cannot keep sessions, not a generic failure, at ${width}px`, async ({ page, request }) => {
    // the real server answers; the 501 is the answer a server with no task store gives, which this harness cannot start
    expect((await getJson(request, '/v1/browser/sessions')).status).toBe(200);
    await page.route('**/v1/browser/sessions*', (route) =>
      route.fulfill({ status: 501, contentType: 'application/json', body: JSON.stringify({ code: 'browser_unavailable', message: 'browsing needs the task store on this server' }) }),
    );
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/browser');
    const empty = page.getByTestId('browser-unavailable');
    await expect(empty).toBeVisible({ timeout: 15_000 });
    await expect(empty).toContainText('Browsing is not available on this server');
    await expect(empty).toContainText('task store');
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Open a browser' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Browsing settings' })).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });

  test(`Browser names a running box whose sessions could not be read, at ${width}px`, async ({ page, request }) => {
    await overlay(page, request, '/v1/browser/sessions', (real) => ({ ...real, unreachable: [{ name: 'alpha', reason: 'the box did not answer' }] }));
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/browser');
    const note = page.getByTestId('unreachable-note');
    await expect(note).toBeVisible({ timeout: 15_000 });
    await expect(note).toContainText('alpha');
    await expect(note).toContainText('the box did not answer');
    await expectNoSidewaysScroll(page);
  });

  test(`a skill's review says when its files could not be read, at ${width}px`, async ({ page, request }) => {
    const name = SKILL[width] ?? 'keep-memory';
    expect((await request.get(`${origin()}/v1/skills/${name}/review`, { headers: headers() })).status()).toBe(200);
    await page.route(`**/v1/skills/${name}/review*`, (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'internal', message: 'the skill store could not be read' }) }));
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/skills');
    await page.locator(`[data-testid="skill-card"][data-skill="${name}"]`).getByRole('button', { name: 'Review and approve' }).click();
    const err = page.getByTestId('skill-review-error');
    await expect(err).toBeVisible({ timeout: 15_000 });
    await expect(err).toContainText('the skill store could not be read');
    await expect(page.getByTestId('skill-review-sheet').getByRole('button', { name: 'Approve these files' })).toBeDisabled();
    await expectNoSidewaysScroll(page);
  });

  test(`Memory says where the notes are kept, at ${width}px`, async ({ page, request }) => {
    const api = await getJson(request, '/v1/memory');
    expect(api.status).toBe(200);
    const store = api.body['store'] as { persisted: boolean; on_a_box: boolean };
    expect(store.persisted).toBe(true);
    expect(store.on_a_box).toBe(false);
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/memory');
    await expect(page.getByRole('heading', { name: 'Memory', level: 1 })).toBeVisible();
    const where = page.getByTestId('memory-where');
    await expect(where).toBeVisible({ timeout: 15_000 });
    await expect(where).toContainText('the computer that runs this dashboard');
    await expect(where).toContainText('not on your other boxes');
    await expect(where).toHaveAttribute('data-persisted', 'true');
    await expect(page.getByTestId('memory-forgotten')).toHaveCount(0);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
  });

  test(`Memory says when its notes are forgotten on restart, at ${width}px`, async ({ page, request }) => {
    // a server with no settings file keeps notes for its own run only; the harness always has one, so that answer is injected
    expect(((await getJson(request, '/v1/memory')).body['store'] as { persisted: boolean }).persisted).toBe(true);
    await overlay(page, request, '/v1/memory', (real) => ({ ...real, store: { persisted: false, on_a_box: false, host: null } }));
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/memory');
    await expect(page.getByTestId('memory-forgotten')).toContainText('forgotten when it stops', { timeout: 15_000 });
    await expect(page.getByTestId('memory-where')).toHaveAttribute('data-persisted', 'false');
    await expectNoSidewaysScroll(page);
  });

  test(`Skills says where they are kept, that nothing is copied to a box, and how to add your own, at ${width}px`, async ({ page, request }) => {
    expect(((await getJson(request, '/v1/skills')).body['store'] as { persisted: boolean }).persisted).toBe(true);
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/skills');
    await expect(page.getByRole('heading', { name: 'Skills', level: 1 })).toBeVisible();
    const where = page.getByTestId('skills-where');
    await expect(where).toBeVisible({ timeout: 15_000 });
    await expect(where).toContainText('the computer that runs this dashboard');
    await expect(where).toContainText('does not copy files onto a box');
    await expect(page.getByTestId('skills-own')).toContainText('ozbox skills add');
    await expectNoSidewaysScroll(page);
  });

  test(`a skill is installed for one box, and the page says which agents may use it, at ${width}px`, async ({ page, request }) => {
    const name = SKILL[width] ?? 'keep-memory';
    const reset = async () => {
      await request.post(`${origin()}/v1/skills/${name}/uninstall`, { headers: headers(), data: { scope: 'box:alpha' } });
      await request.post(`${origin()}/v1/skills/${name}/uninstall`, { headers: headers(), data: { scope: 'fleet' } });
    };
    await reset();
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/skills');
      const card = page.locator(`[data-testid="skill-card"][data-skill="${name}"]`);
      await expect(card).toBeVisible({ timeout: 15_000 });
      await card.getByRole('button', { name: 'Install', exact: true }).click();
      const sheet = page.getByTestId('skill-install-sheet');
      await expect(sheet.getByTestId('skill-scope-says')).toContainText('Every agent session');
      await expect(sheet.getByTestId('skill-scope-says')).toContainText('Nothing is copied onto a box');
      await sheet.getByLabel('Where', { exact: true }).click();
      await page.getByRole('option', { name: 'One box' }).click();
      // a box scope needs a box: the button waits for one
      await expect(sheet.getByRole('button', { name: 'Install', exact: true })).toBeDisabled();
      await sheet.getByLabel('Box', { exact: true }).click();
      await page.getByRole('option', { name: 'alpha' }).click();
      await expect(sheet.getByTestId('skill-scope-says')).toContainText('Orchestration agents on box alpha');
      if (width < 1024) await expectTouchTargets(page, sheet);
      await sheet.getByRole('button', { name: 'Install', exact: true }).click();
      await expect(sheet).toHaveCount(0);
      await expect(card.getByTestId('skill-install')).toContainText('Orchestration agents on box alpha');
      const list = await getJson(request, '/v1/skills');
      const item = (list.body['skills'] as { name: string; installs: { scope: string }[] }[]).find((s) => s.name === name);
      expect(item?.installs.map((i) => i.scope)).toEqual(['box:alpha']);
      await expectNoSidewaysScroll(page);
    } finally {
      await reset();
    }
  });
}

test.describe('a role that may not change these pages is offered nothing to change', () => {
  test.describe.configure({ mode: 'serial' });
  const PEOPLE = '[[users]]\nid = "owner"\nlabel = "Owner"\n\n[[users]]\nid = "friend"\nlabel = "Friend"\n\n[[users]]\nid = "watcher"\nlabel = "Watcher"\nrole = "viewer"\n';

  async function api(page: Page, method: string, path: string, body?: unknown): Promise<{ status: number; body: { code?: string; message?: string } }> {
    return page.evaluate(
      async ([m, p, b]) => {
        const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
        const res = await fetch(p as string, { method: m as string, headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, ...(b === undefined ? {} : { body: JSON.stringify(b) }) });
        return { status: res.status, body: (await res.json().catch(() => ({}))) as { code?: string; message?: string } };
      },
      [method, path, body] as const,
    );
  }

  /** What the page would show once somebody had used it: a note and an orchestration, made through the program before anyone signs in. */
  function seed(s: AuthServer, tag: string): void {
    const run = (...args: string[]) => execFileSync(s.bin, args, { env: s.env, stdio: ['ignore', 'ignore', 'inherit'] });
    run('memory', 'add', '--scope', 'project:r5', '--title', `${tag} note`, '--body', 'seeded for the role spec');
    run('orch', 'start', '--goal', `${tag} goal`, '--box', 'alpha', '--yes');
  }

  async function sees(page: Page, s: AuthServer, tag: string, mayWrite: boolean, mayInstall: boolean, w: number) {
    await page.setViewportSize({ width: w, height: 900 });

    await page.goto(`${s.origin}/memory`);
    await expect(page.getByTestId('mem-note').filter({ hasText: `${tag} note` })).toBeVisible({ timeout: 15_000 });
    const note = page.getByTestId('mem-note').filter({ hasText: `${tag} note` });
    for (const name of ['Edit', 'Forget']) await expect(note.getByRole('button', { name, exact: true })).toHaveCount(mayWrite ? 1 : 0);
    await expect(page.getByRole('button', { name: 'Add a note' })).toHaveCount(mayWrite ? 1 : 0);
    await expect(page.getByTestId('cannot-note')).toHaveCount(mayWrite ? 0 : 1);
    await expectNoSidewaysScroll(page);

    await page.goto(`${s.origin}/skills`);
    const card = page.getByTestId('skill-card').first();
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.getByRole('button', { name: 'Install', exact: true })).toHaveCount(mayInstall ? 1 : 0);
    await expect(card.getByRole('button', { name: mayInstall ? 'Review and approve' : 'Read the files' })).toBeVisible();
    await expect(page.getByTestId('cannot-note')).toHaveCount(mayInstall ? 0 : 1);
    await expectNoSidewaysScroll(page);

    await page.goto(`${s.origin}/orchestrations`);
    await expect(page.getByTestId('orch-card').filter({ hasText: `${tag} goal` })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole('button', { name: 'Start orchestration' })).toHaveCount(mayWrite ? 1 : 0);
    await expect(page.getByRole('button', { name: 'Connect an agent' })).toHaveCount(mayWrite ? 1 : 0);
    await expect(page.getByTestId('cannot-note')).toHaveCount(mayWrite ? 0 : 1);
    await page.getByTestId('orch-card').filter({ hasText: `${tag} goal` }).getByRole('button', { name: 'Open' }).click();
    const detail = page.getByTestId('orch-detail');
    await expect(detail).toBeVisible();
    await expect(detail.getByRole('button', { name: 'Pause', exact: true })).toHaveCount(mayWrite ? 1 : 0);
    await expect(detail.getByRole('button', { name: 'Stop', exact: true })).toHaveCount(mayWrite ? 1 : 0);
    await expect(detail.getByLabel('Add to the cap (US dollars)')).toHaveCount(mayWrite ? 1 : 0);
    await expectNoSidewaysScroll(page);
  }

  test.describe('a viewer', () => {
    let server: AuthServer;
    let page: Page;
    test.beforeAll(async ({ browser }) => {
      server = await startAuthServer(4197, ['alpha'], 5, undefined, {}, PEOPLE);
      seed(server, 'viewer');
      page = await (await browser.newContext()).newPage();
      await addVirtualAuthenticator(page);
      await page.setViewportSize({ width: 1440, height: 900 });
      await firstSignIn(page, server, 'watcher');
    });
    test.afterAll(() => server.stop());

    for (const w of WIDTHS) {
      test(`reads notes, skills and orchestrations and is offered no change, at ${w}px`, async () => {
        await sees(page, server, 'viewer', false, false, w);
      });
    }

    test('is refused by the server in the same places', async () => {
      await page.goto(server.origin + '/memory');
      const note = await api(page, 'POST', '/v1/memory', { scope: 'project:r5', title: 'x', body: 'y' });
      expect([note.status, note.body.code]).toEqual([403, 'role_forbidden']);
      const skill = await api(page, 'POST', '/v1/skills/keep-memory/install', { scope: 'fleet' });
      expect([skill.status, skill.body.code]).toEqual([403, 'role_forbidden']);
      const orch = await api(page, 'POST', '/v1/orchestrations', { goal: 'x', conductor_box: 'alpha' });
      expect([orch.status, orch.body.code]).toEqual([403, 'role_forbidden']);
    });
  });

  test.describe('a member', () => {
    let server: AuthServer;
    let page: Page;
    test.beforeAll(async ({ browser }) => {
      server = await startAuthServer(4198, ['alpha'], 5, undefined, {}, PEOPLE);
      seed(server, 'member');
      page = await (await browser.newContext()).newPage();
      await addVirtualAuthenticator(page);
      await page.setViewportSize({ width: 1440, height: 900 });
      await firstSignIn(page, server, 'friend');
    });
    test.afterAll(() => server.stop());

    for (const w of WIDTHS) {
      test(`may change notes and orchestrations but not install a skill, at ${w}px`, async () => {
        // the notes and the orchestration controls are on; the skill controls are not (owners review code an agent may run)
        await page.setViewportSize({ width: w, height: 900 });
        await page.goto(`${server.origin}/memory`);
        const note = page.getByTestId('mem-note').filter({ hasText: 'member note' });
        await expect(note).toBeVisible({ timeout: 15_000 });
        await expect(note.getByRole('button', { name: 'Edit', exact: true })).toBeVisible();
        await expect(note.getByRole('button', { name: 'Forget', exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Add a note' })).toBeVisible();
        await page.goto(`${server.origin}/skills`);
        const card = page.getByTestId('skill-card').first();
        await expect(card).toBeVisible({ timeout: 15_000 });
        await expect(card.getByRole('button', { name: 'Install', exact: true })).toHaveCount(0);
        await expect(page.getByTestId('cannot-note')).toContainText('install, remove, review or approve a skill');
        await page.goto(`${server.origin}/orchestrations`);
        await expect(page.getByRole('button', { name: 'Start orchestration' })).toBeVisible({ timeout: 15_000 });
        // a positive control for the viewer's absences: the member does see the controls of the same orchestration
        await page.getByTestId('orch-card').filter({ hasText: 'member goal' }).getByRole('button', { name: 'Open' }).click();
        const detail = page.getByTestId('orch-detail');
        await expect(detail.getByRole('button', { name: 'Pause', exact: true })).toBeVisible();
        await expect(detail.getByRole('button', { name: 'Stop', exact: true })).toBeVisible();
        await expect(detail.getByLabel('Add to the cap (US dollars)')).toBeVisible();
        await expectNoSidewaysScroll(page);
      });
    }

    test('is refused a skill by the server', async () => {
      await page.goto(server.origin + '/skills');
      const skill = await api(page, 'POST', '/v1/skills/keep-memory/install', { scope: 'fleet' });
      expect([skill.status, skill.body.code]).toEqual([403, 'role_forbidden']);
    });
  });
});
