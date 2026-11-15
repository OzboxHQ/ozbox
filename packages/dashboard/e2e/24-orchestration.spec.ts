import { applyPlan } from './apply';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Orchestrations on the demo provider: one conductor, two worker boxes, a worker that asks you something, a merge queue
// that waits for your approval, and a pause that saves everything. The agents and the merge are simulated: nothing here
// calls a model or touches a repository, and every orchestration is stopped at the end.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });
const RULES = '---\nengine: fake\nmerge_approval: person\ntest_command: make test\n---\nSmall commits.';

async function post(request: APIRequestContext, path: string, data: unknown = {}): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await request.post(`${origin()}${path}`, { headers: headers(), data });
  return { status: r.status(), body: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

// alpha and charlie survive the earlier specs; bravo does not (02-actions destroys it on purpose), so the second worker is a
// box this spec makes and removes at the end. Only one, because the start-from-the-page test below makes worker boxes of
// its own and every box a spec leaves running is state the shared server keeps.
const CONDUCTOR = 'alpha';
const WORKER_API = 'charlie';
const WORKER_WEB = 'orch-web';
const OWN_BOXES = [WORKER_WEB];

async function makeBox(request: APIRequestContext, name: string) {
  if ((await request.get(`${origin()}/v1/boxes/${name}`, { headers: headers() })).ok()) return;
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers: headers(),
    data: { operation: { op: 'create', spec: { name, size: 'S', work_disk_gb: 50, image: null, region: null, from_snapshot: null, labels: {} } } },
  });
  expect(plan.ok(), await plan.text()).toBe(true);
  const body = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers(), { plan_id: body.plan_id })).ok()).toBe(true);
}

async function removeBox(request: APIRequestContext, name: string) {
  const plan = await request.post(`${origin()}/v1/plans`, { headers: headers(), data: { operation: { op: 'destroy', name, final_snapshot: false } } });
  if (!plan.ok()) return;
  const body = (await plan.json()) as { plan_id: string };
  await applyPlan(request, origin(), headers(), { plan_id: body.plan_id, confirm_name: name });
}

test.beforeAll(async ({ playwright }) => {
  const request = await playwright.request.newContext();
  try {
    for (const name of OWN_BOXES) await makeBox(request, name);
  } finally {
    await request.dispose();
  }
});

test.afterAll(async ({ playwright }) => {
  const request = await playwright.request.newContext();
  try {
    for (const name of OWN_BOXES) await removeBox(request, name);
  } finally {
    await request.dispose();
  }
});

async function seed(request: APIRequestContext, goal: string): Promise<string> {
  const r = await post(request, '/v1/orchestrations', { goal, conductor_box: CONDUCTOR, rules: RULES });
  expect(r.status).toBe(201);
  const id = r.body['id'] as string;
  for (const [title, box, claim] of [
    ['Invoices API', WORKER_API, 'src/api'],
    ['Invoices screen', WORKER_WEB, 'src/web'],
  ] as const) {
    const f = await post(request, `/v1/orchestrations/${id}/features`, { title, brief: `build ${title} sim:steps=2`, box, claims: [claim] });
    expect(f.status, JSON.stringify(f.body)).toBe(200);
  }
  return id;
}

async function stop(request: APIRequestContext, id: string) {
  await post(request, `/v1/orchestrations/${id}/stop`);
}

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

for (const width of WIDTHS) {
  test(`orchestrations at ${width}px: features finish, the merge waits for you, and it merges when you approve`, async ({ page, request }, testInfo) => {
    const goal = `orch-${width}-${testInfo.retry} ship invoices`;
    const id = await seed(request, goal);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/orchestrations');
      await expect(page.getByRole('heading', { name: 'Orchestrations', level: 1 })).toBeVisible();
      await expect(page.getByTestId('orch-source-note')).toBeVisible();
      const card = page.getByTestId('orch-card').filter({ hasText: goal });
      await expect(card).toBeVisible({ timeout: 15_000 });
      await expectNoSidewaysScroll(page);
      await card.getByRole('button', { name: 'Open' }).click();

      const detail = page.getByTestId('orch-detail');
      await expect(detail.getByRole('heading', { name: goal })).toBeVisible();
      const features = page.getByTestId('orch-features');
      await expect(features.getByTestId('orch-feature')).toHaveCount(2);
      await expect(features).toContainText('Invoices API');
      await expect(features).toContainText('src/api');
      await expect(features).toContainText('orch/' + id + '/invoices-api');
      await expect(page.getByText('3 worker boxes, 3 sub-agents each, merges approved by you')).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, detail);
      await axeClean(page, '[data-testid="orch-detail"]');

      // the simulated workers finish; each can be put in the merge queue
      const queue = features.getByRole('button', { name: 'Queue Invoices API for the merge' });
      await expect(queue).toBeVisible({ timeout: 45_000 });
      await queue.click();
      const merge = page.getByTestId('orch-merge');
      await expect(merge).toContainText('Invoices API', { timeout: 15_000 });
      await expect(merge).toContainText('Waiting for approval', { timeout: 30_000 });
      await expect(page.getByTestId('orch-approvals')).toContainText('merge orch/' + id + '/invoices-api into main');
      await expect(page.getByTestId('orch-approvals')).toContainText('1 waiting for you');
      await expectNoSidewaysScroll(page);
      await axeClean(page, '[data-testid="orch-detail"]');

      // approving is yours: the queue goes on and the feature is merged
      const pending = await request.get(`${origin()}/v1/approval-requests`, { headers: headers() });
      const item = ((await pending.json()) as { items: { id: string; action: string }[] }).items.find((a) => a.action.includes(`orch/${id}/invoices-api`));
      expect(item).toBeTruthy();
      expect((await post(request, `/v1/approval-requests/${item?.id}/approve`)).status).toBe(200);
      await expect(merge).toContainText('Merged', { timeout: 30_000 });
      await expect(features.getByTestId('orch-feature').filter({ hasText: 'Invoices API' })).toContainText('Merged', { timeout: 15_000 });
    } finally {
      await stop(request, id);
    }
  });
}

test('a question for you is answered from the page, and the worker is told', async ({ page, request }) => {
  const goal = `orch-ask-${Date.now()} ship`;
  const id = await seed(request, goal);
  try {
    expect((await post(request, `/v1/orchestrations/demo/${id}/ask`, { feature: 'f1', text: 'Drop the old invoices table?', for_person: true })).status).toBe(200);
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, '/orchestrations');
    const card = page.getByTestId('orch-card').filter({ hasText: goal });
    await expect(card).toContainText('Needs you', { timeout: 15_000 });
    await card.getByRole('button', { name: 'Open' }).click();
    const q = page.getByTestId('orch-question').filter({ hasText: 'Drop the old invoices table?' });
    await expect(q).toBeVisible();
    await expect(q).toContainText('For you');
    await expectNoSidewaysScroll(page);
    await axeClean(page, '[data-testid="orch-questions"]');
    await q.getByLabel(/Your answer to/).fill('No. Keep it for a year.');
    await q.getByRole('button', { name: 'Answer' }).click();
    await expect(page.getByTestId('orch-question')).toHaveCount(0, { timeout: 15_000 });
    await expect(page.getByTestId('orch-messages')).toContainText('No. Keep it for a year.');
  } finally {
    await stop(request, id);
  }
});

test('pause saves the work and resume continues; stop asks first', async ({ page, request }) => {
  const goal = `orch-pause-${Date.now()} ship`;
  const id = await seed(request, goal);
  try {
    await page.setViewportSize({ width: 820, height: 900 });
    await open(page, '/orchestrations');
    await page.getByTestId('orch-card').filter({ hasText: goal }).getByRole('button', { name: 'Open' }).click();
    const detail = page.getByTestId('orch-detail');
    await detail.getByRole('button', { name: 'Pause', exact: true }).first().click();
    await expect(detail.getByText('Paused', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
    await detail.getByRole('button', { name: 'Resume', exact: true }).first().click();
    await expect(detail.getByText('Active', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
    await detail.getByRole('button', { name: 'Stop', exact: true }).first().click();
    const confirm = page.getByRole('alertdialog');
    await expect(confirm).toContainText('Stop this orchestration?');
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(detail.getByText('Active', { exact: true }).first()).toBeVisible();
  } finally {
    await stop(request, id);
  }
});

test('starting an orchestration from the page, and connecting your own agent', async ({ page, request }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await open(page, '/orchestrations');
  await page.getByRole('button', { name: 'Start orchestration' }).click();
  const sheet = page.getByTestId('orch-start-sheet');
  await expect(sheet).toBeVisible();
  await sheet.getByRole('button', { name: 'Start', exact: true }).click();
  await expect(sheet.getByText('Say what the job is.')).toBeVisible();
  await expect(sheet.getByText('Choose the conductor box.')).toBeVisible();
  const goal = `orch-sheet-${Date.now()} add a CSV export`;
  await sheet.getByLabel('Goal').fill(goal);
  await sheet.getByLabel('Conductor box').click();
  await page.getByRole('option', { name: 'alpha' }).click();
  await sheet.getByLabel('Worker boxes at most').fill('9');
  await sheet.getByRole('button', { name: 'Start', exact: true }).click();
  const detail = page.getByTestId('orch-detail');
  await expect(detail.getByRole('heading', { name: goal })).toBeVisible({ timeout: 15_000 });
  // 9 is over the person's limit of 3: the limit held
  await expect(page.getByText('3 worker boxes, 3 sub-agents each')).toBeVisible();
  await expect(page.getByText(/is over the limit of 3/)).toBeVisible();
  await expectNoSidewaysScroll(page);
  const list = await request.get(`${origin()}/v1/orchestrations`, { headers: headers() });
  const mine = ((await list.json()) as { items: { id: string; goal: string }[] }).items.find((o) => o.goal === goal);
  expect(mine).toBeTruthy();

  await page.getByRole('button', { name: 'All orchestrations' }).click();
  await page.getByRole('button', { name: 'Connect an agent' }).click();
  const connect = page.getByTestId('orch-connect-sheet');
  await connect.getByRole('button', { name: 'Create a token' }).click();
  const snippet = connect.getByTestId('orch-mcp-snippet');
  await expect(snippet).toHaveValue(/ozmt_[0-9a-f]{64}/);
  await expect(snippet).toHaveValue(/http:\/\/127\.0\.0\.1:\d+\/mcp/);
  await axeClean(page, '[data-testid="orch-connect-sheet"]');
  if (mine) await stop(request, mine.id);
});
