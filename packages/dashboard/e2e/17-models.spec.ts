import { applyPlan } from './apply';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Settings -> Models on the demo provider: a cloud provider card with its set-up guide and a write-only key, which engine
// uses which model, and local AI on a GPU box (review the download, then apply) that shows up as a local endpoint whose
// models can be listed. The demo box answers for itself; nothing reaches a real provider or cloud, so the provider's own
// "Test connection" is only pressed on the local endpoint.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });
const SENTINEL = 'bk-PLAYWRIGHT-MODELS-SENTINEL';

async function makeGpuBox(request: APIRequestContext, name: string) {
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers: headers(),
    data: { operation: { op: 'create', spec: { name, size: { Gpu: 'Small' }, work_disk_gb: 200, image: null, region: null, from_snapshot: null, labels: {} } } },
  });
  const body = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers(), { plan_id: body.plan_id })).ok()).toBe(true);
}

/** Installs vLLM on the demo box through the tools installer, as the Tools tab does, and waits for it. */
async function installVllm(request: APIRequestContext, name: string) {
  const base = `${origin()}/v1/boxes/${name}/tools`;
  const plan = await request.post(`${base}/plan`, { headers: headers(), data: { install: ['vllm'] } });
  expect(plan.ok()).toBe(true);
  const hash = ((await plan.json()) as { plan: { hash: string } }).plan.hash;
  expect((await request.post(`${base}/apply`, { headers: headers(), data: { install: ['vllm'], plan_hash: hash } })).ok()).toBe(true);
  await expect
    .poll(async () => {
      const r = (await (await request.get(base, { headers: headers() })).json()) as { tools: { id: string; installed: boolean }[] };
      return r.tools.find((t) => t.id === 'vllm')?.installed;
    }, { timeout: 20_000 })
    .toBe(true);
}

/** The settings as they are now, and a way to put them back: these tests add providers and an engine choice to a server that
 * every later test shares, and a leftover engine choice makes the simulated agent wait for a key that will never come. */
async function snapshotSettings(request: APIRequestContext) {
  const url = `${origin()}/v1/settings`;
  const original = ((await (await request.get(url, { headers: headers() })).json()) as { settings: unknown }).settings;
  return async (secretIds: string[]) => {
    await request.put(url, { headers: headers(), data: original });
    for (const id of secretIds) await request.delete(`${origin()}/v1/secrets/model-key-${id}`, { headers: headers() });
  };
}

async function removeBox(request: APIRequestContext, name: string) {
  const plan = await request.post(`${origin()}/v1/plans`, { headers: headers(), data: { operation: { op: 'destroy', name, final_snapshot: false } } });
  if (!plan.ok()) return;
  const body = (await plan.json()) as { plan_id: string };
  await applyPlan(request, origin(), headers(), { plan_id: body.plan_id, confirm_name: name });
}

async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

for (const width of WIDTHS) {
  test(`models at ${width}px: a cloud provider, an engine's model, and local AI on a GPU box`, async ({ page, request }, testInfo) => {
    const tag = testInfo.retry === 0 ? '' : `r${testInfo.retry}-`;
    const box = `gpu-${tag}${width}`;
    const label = `Cloud ${tag}${width}`;
    const id = `cloud-${tag}${width}`;
    await makeGpuBox(request, box);
    const restore = await snapshotSettings(request);
    try {
      await installVllm(request, box);
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/settings/models');
      await expect(page.getByRole('heading', { name: 'Model providers' })).toBeVisible();
      await expectNoSidewaysScroll(page);

      // a provider through your own cloud account: its fields, its guide, and a write-only key
      await page.getByRole('button', { name: 'Add provider' }).click();
      const sheet = page.getByTestId('provider-sheet');
      await sheet.getByLabel('Provider type').click();
      await page.getByRole('option', { name: 'AWS Bedrock (your AWS account)' }).click();
      await sheet.getByLabel('Name').fill(label);
      await sheet.getByLabel('AWS region').fill('not a region');
      await sheet.getByLabel('API key').fill(SENTINEL);
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet.getByRole('alert').first()).toContainText('region like us-east-1');
      await sheet.getByRole('button', { name: 'Set-up guide' }).click();
      const guide = sheet.getByTestId('provider-guide');
      await expect(guide).toContainText('Bedrock');
      await expect(guide.getByRole('listitem')).toHaveCount(4);
      if (width < 1024) await expectTouchTargets(page, sheet);
      await guide.getByRole('button', { name: 'Back to the form' }).click();
      await sheet.getByLabel('AWS region').fill('us-east-1');
      await expect(sheet.getByRole('button', { name: 'Save' })).toBeInViewport();
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet).toBeHidden();
      const card = page.getByTestId(`provider-${id}`);
      await expect(card.getByText('Key saved')).toBeVisible();
      expect(await page.content()).not.toContain(SENTINEL);

      // which engine uses which model: Claude Code may use Bedrock, and the list offers only providers it can use
      await page.getByTestId('engine-claude-code').getByRole('button', { name: 'Choose for Claude Code' }).click();
      const eng = page.getByTestId('engine-sheet');
      await eng.getByLabel('Provider', { exact: true }).click();
      await expect(page.getByRole('option', { name: label })).toBeVisible();
      await page.getByRole('option', { name: label }).click();
      await eng.getByLabel('Model name', { exact: true }).fill('anthropic.claude-sonnet-4-20250514-v1:0');
      await eng.getByRole('button', { name: 'Save' }).click();
      await expect(eng).toBeHidden();
      await expect(page.getByTestId('engine-claude-code')).toContainText(`${label} · anthropic.claude-sonnet-4-20250514-v1:0`);

      // local AI: review the download first, then apply
      const local = page.getByTestId('model-local-ai');
      await local.scrollIntoViewIfNeeded();
      await local.getByLabel('GPU box').click();
      await page.getByRole('option', { name: box }).click();
      await expect(local.getByTestId('local-status')).toContainText('Installed');
      await local.getByLabel('Model to download').click();
      await page.getByRole('option', { name: /Qwen2\.5 Coder 7B \(Qwen\/Qwen2\.5-Coder-7B-Instruct\)/ }).click();
      await local.getByRole('button', { name: 'Review the download' }).click();
      const plan = page.getByTestId('local-plan-sheet');
      await expect(plan.getByTestId('local-plan-size')).toContainText('about 15.2 GB');
      await expect(plan).toContainText('127.0.0.1');
      await expect(plan.getByRole('button', { name: 'Download and add' })).toBeInViewport();
      await expectNoSidewaysScroll(page);
      await plan.getByRole('button', { name: 'Download and add' }).click();
      await expect(plan).toBeHidden();
      const lp = page.getByTestId(`provider-vllm-${box}`);
      await expect(lp).toBeVisible();
      await expect(lp).toContainText(`Runs on box ${box}`);
      await lp.getByRole('button', { name: 'Test connection' }).click();
      await expect(lp.getByTestId('model-list-result')).toContainText('Qwen/Qwen2.5-Coder-7B-Instruct');
      await expect(lp.getByTestId('model-list-result')).toContainText(/no price per token/i);

      // usage: nothing is recorded until a run uses a model, and the card says so
      await expect(page.getByTestId('usage-empty')).toBeVisible();

      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('main'));
      for (const section of ['model-engines', 'model-local-ai', 'model-usage']) await axeClean(page, section);
    } finally {
      await removeBox(request, box);
      await restore([id, `vllm-${box}`]);
    }
  });
}

// Your own price for a model: entered per provider and model, shown in the list, and cleared again.
for (const width of WIDTHS) {
  test(`models at ${width}px: enter your own price for a model and clear it`, async ({ page, request }, testInfo) => {
    const tag = testInfo.retry === 0 ? '' : `r${testInfo.retry}-`;
    const label = `Priced ${tag}${width}`;
    const id = `priced-${tag}${width}`;
    const restore = await snapshotSettings(request);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/settings/models');
      await page.getByRole('button', { name: 'Add provider' }).click();
      const sheet = page.getByTestId('provider-sheet');
      await sheet.getByLabel('Provider type').click();
      await page.getByRole('option', { name: 'OpenAI' }).first().click();
      await sheet.getByLabel('Name').fill(label);
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet).toBeHidden();
      const card = page.getByTestId('model-prices');
      await card.scrollIntoViewIfNeeded();
      await card.getByRole('button', { name: 'Add a price' }).click();
      const ps = page.getByTestId('price-sheet');
      await ps.getByLabel('Provider', { exact: true }).click();
      await page.getByRole('option', { name: label }).click();
      await ps.getByLabel('Model name', { exact: true }).fill('my-model');
      await ps.getByLabel(/^Input/).fill('abc');
      await ps.getByLabel(/^Output/).fill('4');
      await ps.getByRole('button', { name: 'Save' }).click();
      await expect(ps.getByRole('alert').first()).toContainText('plain numbers');
      await ps.getByLabel(/^Input/).fill('1.25');
      if (width < 1024) await expectTouchTargets(page, ps);
      await expectNoSidewaysScroll(page);
      await axeClean(page, 'price-sheet');
      await ps.getByRole('button', { name: 'Save' }).click();
      await expect(ps).toBeHidden();
      const row = card.getByTestId('price-row').filter({ hasText: `${id}/my-model` });
      await expect(row).toContainText('1.25 in / 4 out per million');
      await row.getByRole('button', { name: 'Clear' }).click();
      await expect(card.getByTestId('price-row').filter({ hasText: `${id}/my-model` })).toHaveCount(0);
    } finally {
      await restore([id]);
    }
  });
}

// ADR 0054: whether each engine can run on a person's own subscription. Read only and honest: every row says Planned or
// Not offered with the reason and the vendor's own pages, and nothing offers to connect one.
for (const width of WIDTHS) {
  test(`subscriptions at ${width}px: honest status, vendor links, no connect button`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/settings/models');
    const card = page.getByTestId('model-subscriptions');
    await card.scrollIntoViewIfNeeded();
    await expect(card.getByRole('heading', { name: 'Use a subscription instead of a key' })).toBeVisible();
    await expect(card).toContainText('None can be connected yet');
    const claude = card.getByTestId('subscription-claude-code-claude');
    await expect(claude).toContainText('Not offered');
    await expect(claude).toContainText("Anthropic's terms");
    await expect(card.getByTestId('subscription-codex-chatgpt')).toContainText('Planned');
    await expect(card.getByText('Available', { exact: true })).toHaveCount(0);
    await expect(card.getByRole('button')).toHaveCount(0);
    for (const href of await card.getByRole('link').evaluateAll((as) => as.map((a) => a.getAttribute('href') ?? ''))) {
      expect(href.startsWith('https://')).toBe(true);
    }
    if (width < 1024) await expectTouchTargets(page, card);
    await expectNoSidewaysScroll(page);
    await axeClean(page, 'model-subscriptions');
  });
}
