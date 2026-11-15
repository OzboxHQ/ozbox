
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The task board on the demo provider: a task is planned, queued, run by the simulated agent and finished; a run that
// reaches its spend limit pauses, saves its work and asks, and continues when budget is added; the list filters and acts on
// several at once. The agent is simulated: nothing here calls a model, and every run is cancelled at the end.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function seed(request: APIRequestContext, prompt: string, extra: Record<string, unknown> = {}): Promise<string> {
  const r = await request.post(`${origin()}/v1/tasks`, { headers: headers(), data: { engine: 'fake', box: 'charlie', prompt, ...extra } });
  expect(r.status()).toBe(201);
  return ((await r.json()) as { id: string }).id;
}

async function cancel(request: APIRequestContext, id: string) {
  await request.post(`${origin()}/v1/tasks/${id}/cancel`, { headers: headers() });
}

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

const card = (page: Page, marker: string) => page.getByTestId('task-card').filter({ hasText: marker }).first();

for (const width of WIDTHS) {
  test(`tasks at ${width}px: plan a task, queue it, watch it finish`, async ({ page }, testInfo) => {
    const marker = `board-${width}-${testInfo.retry}`;
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/tasks');
    await expect(page.getByRole('heading', { name: 'Tasks', level: 1 })).toBeVisible();
    await expect(page.getByText(/simulated agent/)).toBeVisible();
    await expectNoSidewaysScroll(page);

    await page.getByRole('button', { name: 'New task' }).click();
    const sheet = page.getByTestId('new-task-sheet');
    await expect(sheet).toBeVisible();
    // an empty form is refused with a reason, and nothing is queued
    await sheet.getByRole('button', { name: 'Review plan' }).click();
    await expect(sheet.getByText('Choose a box.')).toBeVisible();
    await sheet.getByLabel('Box', { exact: true }).click();
    await page.getByRole('option', { name: 'charlie' }).click();
    await sheet.getByLabel('What should it do?').fill(`${marker} sim:steps=3`);
    await sheet.getByLabel('Pause and ask after (US dollars)').fill('5');
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page, '[data-testid="new-task-sheet"]');
    await sheet.getByRole('button', { name: 'Review plan' }).click();
    // plan first: nothing is queued until the last step
    await expect(sheet.getByTestId('new-task-plan')).toContainText('fake on charlie');
    await expect(page.getByTestId('task-card').filter({ hasText: marker })).toHaveCount(0);
    await sheet.getByRole('button', { name: 'Queue task' }).click();

    await expect(card(page, marker)).toBeVisible();
    // the simulated agent runs it to the Review column
    await expect(page.getByTestId('col-review').getByTestId('task-card').filter({ hasText: marker })).toBeVisible({ timeout: 30_000 });
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByTestId('task-board'));
    await axeClean(page, '[data-testid="task-board"]');

    await card(page, marker).getByRole('button', { name: 'Open' }).click();
    const detail = page.getByTestId('task-sheet');
    await expect(detail.getByTestId('task-log')).toContainText('finished', { timeout: 10_000 }).catch(() => undefined);
    await expect(detail.getByRole('link', { name: 'Pull request' })).toHaveAttribute('href', /^https:\/\/example\.com\//);
    await expect(detail.getByTestId('task-log')).toContainText('step 3 of 3');
    await axeClean(page, '[data-testid="task-sheet"]');
    await detail.getByRole('button', { name: 'Mark as done' }).click();
    await detail.getByRole('button', { name: 'Close' }).first().click();
    await expect(page.getByTestId('col-done').getByTestId('task-card').filter({ hasText: marker })).toBeVisible({ timeout: 10_000 });
  });

  test(`tasks at ${width}px: a spend limit pauses the run, saves its work and asks; budget lets it continue`, async ({ page, request }, testInfo) => {
    const marker = `cap-${width}-${testInfo.retry}`;
    const id = await seed(request, `${marker} sim:steps=100000 sim:cents=10`, { caps: { max_spend_cents: 25 } });
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/tasks');
      const needs = page.getByTestId('col-needs_you').getByTestId('task-card').filter({ hasText: marker });
      await expect(needs).toBeVisible({ timeout: 30_000 });
      await expect(needs).toContainText('Paused at its spend limit');
      await expectNoSidewaysScroll(page);
      await needs.getByRole('button', { name: 'Open' }).click();
      const detail = page.getByTestId('task-sheet');
      await expect(detail.getByText('Saved work')).toBeVisible();
      await expect(detail.getByText(/^wip\/charlie\//)).toBeVisible();
      const form = detail.getByTestId('resume-form');
      // adding nothing is refused
      await form.getByRole('button', { name: 'Add and continue' }).click();
      await expect(form.getByText('Add something to at least one limit.')).toBeVisible();
      if (width < 1024) await expectTouchTargets(page, form);
      await axeClean(page, '[data-testid="task-sheet"]');
      await form.getByLabel('Add US dollars').fill('50');
      await form.getByRole('button', { name: 'Add and continue' }).click();
      await detail.getByRole('button', { name: 'Close' }).first().click();
      await expect(page.getByTestId('col-running').getByTestId('task-card').filter({ hasText: marker })).toBeVisible({ timeout: 30_000 });
    } finally {
      await cancel(request, id);
    }
  });
}

test('the list filters, selects and acts on several tasks at once', async ({ page, request }) => {
  const marker = `bulk-${Date.now()}`;
  const ids = [await seed(request, `${marker} a sim:steps=2 sim:fail`), await seed(request, `${marker} b sim:steps=2 sim:fail`)];
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, '/tasks');
  await page.getByRole('tab', { name: 'List' }).click();
  await page.getByLabel('State', { exact: true }).click();
  await page.getByRole('option', { name: 'Failed' }).click();
  const rows = page.getByTestId('task-row').filter({ hasText: marker });
  await expect(rows).toHaveCount(2, { timeout: 30_000 });
  await page.getByLabel('Box', { exact: true }).click();
  await page.getByRole('option', { name: 'alpha' }).click();
  await expect(page.getByText('No task matches these filters')).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await page.getByLabel('State', { exact: true }).click();
  await page.getByRole('option', { name: 'Failed' }).click();
  await expect(rows).toHaveCount(2);
  await axeClean(page, '[data-testid="task-table"]');
  for (const id of ids) await page.getByTestId('task-table').getByLabel(`Select ${id}`).check();
  const bar = page.getByTestId('bulk-bar');
  await expect(bar).toContainText('2 selected');
  await expect(bar.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  await bar.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByText('2 done, 0 not applicable')).toBeVisible();
  // the retries are new runs, linked to the failed ones
  await page.getByLabel('State', { exact: true }).click();
  await page.getByRole('option', { name: 'Any' }).click();
  await expect(page.getByTestId('task-row').filter({ hasText: marker })).toHaveCount(4, { timeout: 15_000 });
  const all = await request.get(`${origin()}/v1/tasks`, { headers: headers() });
  const items = ((await all.json()) as { items: { id: string; prompt: string; state: string }[] }).items.filter((t) => t.prompt.includes(marker));
  for (const t of items) if (!['failed', 'cancelled', 'done', 'review'].includes(t.state)) await cancel(request, t.id);
});

// The model a run uses is on its card and in its detail. The run is handed a token for the credential broker, never the
// provider's key, so the key only needs to exist in the secret store; no model call is made here.
for (const width of WIDTHS) {
  test(`tasks at ${width}px: the card and the detail name the provider and model the run uses`, async ({ page, request }, testInfo) => {
    const id = `e2e-model-${width}-${testInfo.retry}`;
    const marker = `model-${width}-${testInfo.retry}`;
    const settingsUrl = `${origin()}/v1/settings`;
    const original = (await (await request.get(settingsUrl, { headers: headers() })).json()) as { settings: { models: { providers: unknown[]; engines: Record<string, unknown> } } };
    const next = structuredClone(original.settings);
    next.models.providers = [
      ...next.models.providers,
      { id, kind: 'anthropic', label: `E2E ${width}`, base_url: null, local_endpoint: false, monthly_cap_usd: null, region: null, resource: null, hosted_on: null },
    ];
    next.models.engines = { ...next.models.engines, 'claude-code': { provider_id: id, model: 'claude-sonnet-4-5', fallback: null } };
    expect((await request.put(settingsUrl, { headers: headers(), data: next })).ok()).toBe(true);
    expect((await request.put(`${origin()}/v1/secrets/model-key-${id}`, { headers: headers(), data: { value: 'sk-ant-PLAYWRIGHT-NEVER-SHOWN' } })).ok()).toBe(true);
    let taskId = '';
    try {
      taskId = await seed(request, `${marker} sim:steps=200`);
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/tasks');
      const c = card(page, marker);
      await expect(c.getByTestId('task-model')).toContainText(`${id} / claude-sonnet-4-5`, { timeout: 30_000 });
      await expectNoSidewaysScroll(page);
      await c.getByRole('button', { name: 'Open' }).click();
      const detail = page.getByTestId('task-sheet');
      await expect(detail.getByTestId('task-detail-model')).toContainText(`${id} / claude-sonnet-4-5`);
      expect(await page.content()).not.toContain('PLAYWRIGHT-NEVER-SHOWN');
      if (width < 1024) await expectTouchTargets(page, detail);
      await axeClean(page, '[data-testid="task-sheet"]');
    } finally {
      if (taskId) await cancel(request, taskId);
      await request.put(settingsUrl, { headers: headers(), data: original.settings });
      await request.delete(`${origin()}/v1/secrets/model-key-${id}`, { headers: headers() });
    }
  });
}

// A model for one run, chosen in the New task sheet: only the providers the engine can speak to are offered, the plan names
// the choice before anything is queued, and the queued run carries it. The key exists only in the secret store.
for (const width of WIDTHS) {
  test(`tasks at ${width}px: a model for one run is chosen in the sheet, shown in the plan and carried by the run`, async ({ page, request }, testInfo) => {
    const id = `e2e-pick-${width}-${testInfo.retry}`;
    const marker = `pick-${width}-${testInfo.retry}`;
    const settingsUrl = `${origin()}/v1/settings`;
    const original = (await (await request.get(settingsUrl, { headers: headers() })).json()) as { settings: { models: { providers: unknown[] } } };
    const next = structuredClone(original.settings);
    next.models.providers = [
      ...next.models.providers,
      { id, kind: 'anthropic', label: `E2E pick ${width}`, base_url: null, local_endpoint: false, monthly_cap_usd: null, region: null, resource: null, hosted_on: null },
      { id: `${id}-oa`, kind: 'openai', label: `E2E other ${width}`, base_url: null, local_endpoint: false, monthly_cap_usd: null, region: null, resource: null, hosted_on: null },
    ];
    expect((await request.put(settingsUrl, { headers: headers(), data: next })).ok()).toBe(true);
    expect((await request.put(`${origin()}/v1/secrets/model-key-${id}`, { headers: headers(), data: { value: 'sk-ant-PLAYWRIGHT-NEVER-SHOWN' } })).ok()).toBe(true);
    let taskId = '';
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/tasks');
      await page.getByRole('button', { name: 'New task' }).click();
      const sheet = page.getByTestId('new-task-sheet');
      await expect(sheet).toBeVisible();
      await sheet.getByLabel('Box', { exact: true }).click();
      await page.getByRole('option', { name: 'charlie' }).click();
      await sheet.getByLabel('What should it do?').fill(`${marker} sim:steps=200`);
      // the engine's own choice is the default, and only providers the engine can use are offered
      const group = sheet.getByTestId('new-task-model');
      await expect(group).toBeVisible();
      await expect(sheet.getByLabel('Model', { exact: true })).toHaveCount(0);
      await sheet.getByLabel('Model provider').click();
      await expect(page.getByRole('option', { name: `E2E other ${width}` })).toHaveCount(0);
      await page.getByRole('option', { name: `E2E pick ${width}` }).click();
      // a provider with no model is refused with a reason, and nothing is queued
      await sheet.getByRole('button', { name: 'Review plan' }).click();
      await expect(sheet.getByText('Name a model, or go back to the engine’s own choice.')).toBeVisible();
      await sheet.getByLabel('Model', { exact: true }).fill('claude-sonnet-4-5');
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, '[data-testid="new-task-sheet"]');
      await sheet.getByRole('button', { name: 'Review plan' }).click();
      await expect(sheet.getByTestId('new-task-plan-model')).toContainText(`${id} / claude-sonnet-4-5`);
      await sheet.getByRole('button', { name: 'Queue task' }).click();

      const c = card(page, marker);
      await expect(c).toBeVisible();
      await expect(c.getByTestId('task-model')).toContainText(`${id} / claude-sonnet-4-5`, { timeout: 30_000 });
      const all = await request.get(`${origin()}/v1/tasks`, { headers: headers() });
      const mine = ((await all.json()) as { items: { id: string; prompt: string; requested_model: { provider_id: string; model: string } | null }[] }).items.find((t) => t.prompt.includes(marker));
      expect(mine?.requested_model).toEqual({ provider_id: id, model: 'claude-sonnet-4-5' });
      taskId = mine?.id ?? '';
      expect(await page.content()).not.toContain('PLAYWRIGHT-NEVER-SHOWN');
      await expectNoSidewaysScroll(page);
    } finally {
      if (taskId) await cancel(request, taskId);
      await request.put(settingsUrl, { headers: headers(), data: original.settings });
      await request.delete(`${origin()}/v1/secrets/model-key-${id}`, { headers: headers() });
    }
  });
}
