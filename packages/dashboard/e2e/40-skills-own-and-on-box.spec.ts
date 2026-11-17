import AxeBuilder from '@axe-core/playwright';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { applyPlan } from './apply';
import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// Skills of your own, and skills on a box's disk, against the real server with the demo provider. The demo's boxes are
// pretend, but the code that writes the skill, hashes it and reads it back is the box daemon's own, over a private folder: the
// assertions are on what the server answers after the page acted. A `page.route` appears only for an error state the real
// server cannot be made to give, and always beside an assertion against the real server.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

type Json = Record<string, unknown>;
const api = async (request: APIRequestContext, method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown): Promise<{ status: number; body: Json }> => {
  const r = await request.fetch(`${origin()}${path}`, { method, headers: headers(), ...(data === undefined ? {} : { data }) });
  return { status: r.status(), body: (await r.json().catch(() => ({}))) as Json };
};

async function axeClean(page: Page, testId: string) {
  const r = await new AxeBuilder({ page }).include(`[data-testid="${testId}"]`).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

// These tests need `delta` to be the paused box it is seeded as, and an earlier spec in the shared server (03) resumes it to
// watch a change reach another tab. So this spec puts it back, rather than assume the order the files run in.
test.beforeAll(async ({ request }) => {
  const boxes = (await (await request.get(`${origin()}/v1/boxes`, { headers: headers() })).json()) as { spec: { name: string }; state: string }[];
  if (boxes.find((b) => b.spec.name === 'delta')?.state !== 'running') return;
  const plan = await request.post(`${origin()}/v1/plans`, { headers: headers(), data: { operation: { op: 'pause', name: 'delta' } } });
  const { plan_id } = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers(), { plan_id })).ok()).toBe(true);
});

const md = (name: string, body: string) => `---\nname: ${name}\ndescription: Checks the e2e skill.\nversion: 1\n---\n${body}\n`;

async function clean(request: APIRequestContext, name: string) {
  await api(request, 'DELETE', `/v1/boxes/alpha/skills/${name}`);
  await api(request, 'DELETE', `/v1/skills/${name}`);
}

const card = (page: Page, name: string) => page.locator(`[data-testid="skill-card"][data-skill="${name}"]`);

for (const width of WIDTHS) {
  test(`a skill of your own is written, reviewed, approved, put on a box and read back, at ${width}px`, async ({ page, request }) => {
    const name = `own-${width}`;
    await clean(request, name);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/skills');
      await expect(page.getByRole('heading', { name: 'Skills', level: 1 })).toBeVisible();
      await page.getByTestId('skill-add').click();
      const add = page.getByTestId('skill-add-sheet');
      await add.getByLabel('Name', { exact: true }).fill(name);
      await add.getByLabel('Description', { exact: true }).fill('Checks the e2e skill.');
      await add.getByLabel('Instructions', { exact: true }).fill('Say hello.\n');
      if (width < 1024) await expectTouchTargets(page, add);
      await axeClean(page, 'skill-add-sheet');
      await expectNoSidewaysScroll(page);
      await add.getByRole('button', { name: 'Add to library' }).click();

      // the review opens at once: where it came from, what to look for, then the files as plain text
      const review = page.getByTestId('skill-review-sheet');
      await expect(review.getByTestId('skill-review-provenance')).toContainText('Added by');
      await expect(review.getByTestId('skill-review-provenance')).toContainText('writing it on this page');
      await expect(review.getByTestId('skill-review-injection')).toContainText('instructions to ignore rules');
      await expect(review.locator('pre').first()).toContainText('Say hello.');
      if (width < 1024) await expectTouchTargets(page, review);
      await axeClean(page, 'skill-review-sheet');

      // nothing is on any box, and it is refused before approval (the real server's answer)
      const hash = ((await api(request, 'GET', '/v1/skills')).body['skills'] as { name: string; hash: string }[]).find((s) => s.name === name)?.hash ?? '';
      const refused = await api(request, 'PUT', `/v1/boxes/alpha/skills/${name}`, { hash });
      expect([refused.status, refused.body['code']]).toEqual([409, 'not_approved']);
      // the library is read again after an approval; hold the FIRST read back so Install is opened BEFORE the page knows the skill
      // is approved (what a slow machine does by itself). Only the first: a read that is cancelled and asked again (the page does
      // that on every change it hears of) must then be answered at once, or the page would never learn anything.
      let listHeld = false;
      const slowList = async (route: import('@playwright/test').Route) => {
        if (route.request().method() !== 'GET' || listHeld) return route.continue();
        listHeld = true;
        await new Promise((done) => setTimeout(done, 2000));
        return route.continue().catch(() => undefined);
      };
      await page.route((u) => u.pathname === '/v1/skills', slowList);
      await review.getByRole('button', { name: 'Approve these files' }).click();
      await expect(review).toHaveCount(0);

      await card(page, name).getByRole('button', { name: 'Install', exact: true }).click();
      const sheet = page.getByTestId('skill-install-sheet');
      await sheet.getByLabel('Where', { exact: true }).click();
      await page.getByRole('option', { name: "On a box's disk" }).click();
      await expect(sheet.getByTestId('skill-disk-not-approved')).toHaveCount(0);
      await page.unroute((u) => u.pathname === '/v1/skills', slowList);
      await sheet.getByLabel('Box', { exact: true }).click();
      // only a running box is offered: delta is paused
      await expect(page.getByRole('option', { name: 'delta' })).toHaveCount(0);
      await page.getByRole('option', { name: 'alpha' }).click();
      await expect(sheet.getByTestId('skill-disk-folders')).toContainText('Claude Code');
      await expect(sheet.getByTestId('skill-scope-says')).toContainText(`Puts ${name} in`);
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, 'skill-install-sheet');
      await sheet.getByRole('button', { name: 'Put on the box' }).click();
      await expect(sheet).toHaveCount(0);

      const held = card(page, name).getByTestId('skill-box-hold');
      await expect(held).toContainText('alpha');
      await expect(held).toContainText('Matches the library');
      // what the box holds, as the box says it (its files hashed again)
      const view = (await api(request, 'GET', '/v1/boxes/alpha/skills')).body as { state: string; skills: { name: string; places: { state: string; hash: string; matches_library: boolean }[] }[] };
      const place = view.skills.find((s) => s.name === name)?.places[0];
      expect([view.state, place?.state, place?.hash, place?.matches_library]).toEqual(['ok', 'intact', hash, true]);
      await expectNoSidewaysScroll(page);

      // take it off the box, behind a confirmation
      await held.getByRole('button', { name: 'Remove from alpha' }).click();
      await page.getByRole('button', { name: 'Remove from box' }).click();
      await expect(card(page, name).getByTestId('skill-box-hold')).toHaveCount(0);
      const after = (await api(request, 'GET', '/v1/boxes/alpha/skills')).body as { skills: { name: string }[] };
      expect(after.skills.some((s) => s.name === name)).toBe(false);

      // delete it from the library
      await card(page, name).getByRole('button', { name: 'Delete from library' }).click();
      await page.getByRole('button', { name: 'Delete skill' }).click();
      await expect(card(page, name)).toHaveCount(0);
    } finally {
      await clean(request, name);
    }
  });
}

test('uploaded files are checked, scripts are marked, and a hidden character is refused', async ({ page, request }) => {
  const name = 'own-upload';
  await clean(request, name);
  try {
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, '/skills');
    await page.getByTestId('skill-add').click();
    const add = page.getByTestId('skill-add-sheet');
    await add.getByLabel('How', { exact: true }).click();
    await page.getByRole('option', { name: 'Upload files' }).click();
    // a hidden direction-changing character: refused with its reason, and nothing can be sent
    await add.getByTestId('skill-pick-files').setInputFiles([
      { name: 'SKILL.md', mimeType: 'text/markdown', buffer: Buffer.from(md(name, 'Be nice.')) },
      { name: 'notes.md', mimeType: 'text/markdown', buffer: Buffer.from('a‮b') },
    ]);
    await expect(add.getByTestId('skill-add-problems')).toContainText('notes.md holds a hidden or control character');
    await expect(add.getByRole('button', { name: 'Add to library' })).toBeDisabled();
    // the real server refuses the same bytes
    const r = await api(request, 'POST', '/v1/skills', { files: { 'SKILL.md': md(name, 'x'), 'notes.md': 'a‮b' } });
    expect(r.status).toBe(400);
    await add.getByRole('button', { name: 'Clear' }).click();
    // good files, one of them a script
    await add.getByTestId('skill-pick-files').setInputFiles([
      { name: 'SKILL.md', mimeType: 'text/markdown', buffer: Buffer.from(md(name, 'Run the script.')) },
      { name: 'run.sh', mimeType: 'text/x-sh', buffer: Buffer.from('echo hello\n') },
    ]);
    await expect(add.getByTestId('skill-picked')).toContainText('2 files chosen');
    await add.getByRole('button', { name: 'Add to library' }).click();
    const review = page.getByTestId('skill-review-sheet');
    await expect(review.getByTestId('skill-review-scripts')).toContainText('An agent can run any file in a skill');
    await expect(review.getByTestId('skill-script-badge')).toHaveCount(1);
    await expect(review.getByTestId('skill-review-provenance')).toContainText('uploading files');
    await review.getByRole('button', { name: 'Cancel' }).click();
    await expect(card(page, name).getByTestId('skill-has-scripts')).toBeVisible();
    const item = ((await api(request, 'GET', '/v1/skills')).body['skills'] as { name: string; files: { path: string; kind: string }[]; approved: boolean }[]).find((s) => s.name === name);
    expect(item?.files.map((f) => [f.path, f.kind])).toEqual([['SKILL.md', 'instructions'], ['run.sh', 'script']]);
    expect(item?.approved).toBe(false);
  } finally {
    await clean(request, name);
  }
});

test('replacing a skill of your own asks first, keeps the old version, and restoring it needs approval again', async ({ page, request }) => {
  const name = 'own-history';
  await clean(request, name);
  try {
    const first = await api(request, 'POST', '/v1/skills', { files: { 'SKILL.md': md(name, 'First.') } });
    expect(first.status).toBe(200);
    const firstHash = first.body['hash'] as string;
    await page.setViewportSize({ width: 1024, height: 900 });
    await open(page, '/skills');
    await expect(card(page, name)).toBeVisible({ timeout: 15_000 });
    await page.getByTestId('skill-add').click();
    const add = page.getByTestId('skill-add-sheet');
    await add.getByLabel('Name', { exact: true }).fill(name);
    await add.getByLabel('Description', { exact: true }).fill('Checks the e2e skill.');
    await add.getByLabel('Instructions', { exact: true }).fill('Second.');
    // the name is taken: it cannot be sent until the person says it replaces the one in the library
    await expect(add.getByTestId('skill-add-replace')).toBeVisible();
    await expect(add.getByRole('button', { name: 'Add to library' })).toBeDisabled();
    await add.getByLabel('Replace the skill of this name in my library', { exact: false }).click();
    await add.getByRole('button', { name: 'Add to library' }).click();
    await page.getByTestId('skill-review-sheet').getByRole('button', { name: 'Cancel' }).click();
    await expect(card(page, name).getByRole('button', { name: 'Earlier versions (1)' })).toBeVisible();
    const h = (await api(request, 'GET', `/v1/skills/${name}/history`)).body['revisions'] as { hash: string; current: boolean }[];
    expect(h.map((r) => r.current)).toEqual([true, false]);
    expect(h[1]?.hash).toBe(firstHash);

    await card(page, name).getByRole('button', { name: 'Earlier versions (1)' }).click();
    const sheet = page.getByTestId('skill-history-sheet');
    const old = sheet.getByTestId('skill-revision').filter({ hasNot: page.getByText('Current') }).first();
    await old.getByRole('button', { name: 'Read' }).click();
    await expect(page.getByTestId('skill-review-sheet').locator('pre').first()).toContainText('First.');
    await expect(page.getByTestId('skill-review-sheet').getByRole('button', { name: 'Approve these files' })).toHaveCount(0);
    await page.getByTestId('skill-review-sheet').getByRole('button', { name: 'Cancel' }).click();
    await old.getByRole('button', { name: 'Restore' }).click();
    await page.getByTestId('skill-review-sheet').getByRole('button', { name: 'Cancel' }).click();
    const now = ((await api(request, 'GET', '/v1/skills')).body['skills'] as { name: string; hash: string; approved: boolean }[]).find((s) => s.name === name);
    expect([now?.hash, now?.approved]).toEqual([firstHash, false]);
  } finally {
    await clean(request, name);
  }
});

test('when what the boxes hold cannot be read the page says so; the real server answers it', async ({ page, request }) => {
  const real = await api(request, 'GET', '/v1/skills/holdings');
  expect(real.status).toBe(200);
  const boxes = real.body['boxes'] as { box: string; state: string }[];
  // a paused box is not known, never read as holding nothing
  expect(boxes.find((b) => b.box === 'delta')?.state).toBe('stopped');
  expect(real.body['source']).toBe('simulated');
  await page.setViewportSize({ width: 820, height: 900 });
  await open(page, '/skills');
  await expect(page.getByTestId('skills-holdings-unknown')).toContainText('delta');
  await expect(page.getByTestId('tools-source-note')).toHaveCount(0);
  await expect(page.getByTestId('skills-source-note')).toBeVisible();
  // the failure state: the holdings request fails
  await page.route((u) => u.pathname === '/v1/skills/holdings', (route) => route.fulfill({ status: 500, json: { error: 'the boxes could not be asked', code: 'internal' } }));
  await page.reload();
  await expect(page.getByTestId('skills-holdings-error')).toContainText('What the boxes hold could not be read');
});

const risky = (name: string) =>
  `---\nname: ${name}\ndescription: Checks the e2e skill.\nallowed-tools: Bash(git *)\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: ./notify.sh\nmodel: opus\n---\nChanges: !\`git diff --stat\`\n`;

for (const width of WIDTHS) {
  test(`a skill that runs commands shows what it asks for and is approved only when each is acknowledged, at ${width}px`, async ({ page, request }) => {
    const name = `own-risky-${width}`;
    await clean(request, name);
    try {
      const added = await api(request, 'POST', '/v1/skills', { files: { 'SKILL.md': risky(name) } });
      expect(added.status, JSON.stringify(added.body)).toBe(200);
      const hash = added.body['hash'] as string;
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/skills');
      await expect(card(page, name).getByTestId('skill-runs-commands')).toBeVisible({ timeout: 15_000 });
      await card(page, name).getByRole('button', { name: 'Review and approve' }).click();
      const review = page.getByTestId('skill-review-sheet');
      const asks = review.getByTestId('skill-review-asks');
      // each thing it asks for is named, with the commands, and the other settings are shown
      for (const key of ['allowed-tools', 'hooks', 'shell-injection']) await expect(asks.locator(`[data-ask="${key}"]`)).toBeVisible();
      await expect(asks.locator('[data-ask="hooks"] pre')).toContainText('./notify.sh');
      await expect(asks.locator('[data-ask="shell-injection"] pre')).toContainText('git diff --stat');
      await expect(asks.getByTestId('skill-asks-shown')).toContainText('model');
      await expect(review.getByTestId('skill-runs-badge')).toBeVisible();
      if (width < 1024) await expectTouchTargets(page, review);
      await axeClean(page, 'skill-review-sheet');
      await expectNoSidewaysScroll(page);
      // approval waits for every one of them
      const approve = review.getByRole('button', { name: 'Approve these files' });
      await expect(approve).toBeDisabled();
      for (const key of ['allowed-tools', 'hooks']) await asks.getByTestId(`skill-ack-${key}`).click();
      await expect(approve).toBeDisabled();
      expect((await api(request, 'POST', `/v1/skills/${name}/approve`, { hash, acknowledged: ['hooks', 'allowed-tools'] })).status).toBe(409);
      await asks.getByTestId('skill-ack-shell-injection').click();
      await expect(approve).toBeEnabled();
      await approve.click();
      await expect(review).toHaveCount(0);
      const now = ((await api(request, 'GET', '/v1/skills')).body['skills'] as { name: string; approved: boolean }[]).find((s) => s.name === name);
      expect(now?.approved).toBe(true);
    } finally {
      await clean(request, name);
    }
  });
}

test('a skill on a box says whether this dashboard put it there, and offers to remove only its own', async ({ page, request }) => {
  const name = 'own-origin';
  await clean(request, name);
  try {
    const added = await api(request, 'POST', '/v1/skills', { files: { 'SKILL.md': md(name, 'Hi.') } });
    const hash = added.body['hash'] as string;
    expect((await api(request, 'POST', `/v1/skills/${name}/approve`, { hash })).status).toBe(200);
    expect((await api(request, 'PUT', `/v1/boxes/alpha/skills/${name}`, { hash })).status).toBe(200);
    const view = (await api(request, 'GET', '/v1/boxes/alpha/skills')).body as { skills: { name: string; places: { origin: string; pushed_by?: string; version?: string }[] }[] };
    const place = view.skills.find((s) => s.name === name)?.places[0];
    expect(place?.origin).toBe('dashboard');
    // nothing the box's own record says is passed on as attribution
    expect(place && 'pushed_by' in place).toBe(false);
    expect(place && 'version' in place).toBe(false);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, '/skills');
    const held = card(page, name).getByTestId('skill-box-hold');
    await expect(held.getByTestId('skill-hold-origin')).toContainText('Put here from this dashboard');
    await expect(held.getByRole('button', { name: 'Remove from alpha' })).toBeVisible();
  } finally {
    await clean(request, name);
  }
});
