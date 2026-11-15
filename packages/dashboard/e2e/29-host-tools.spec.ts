import { applyPlan } from './apply';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The tool host on the demo provider: the tools an agent on a box has, what each would be decided as in a sandbox, in
// staging and on production, and the real calls an agent makes over MCP with a person's token: one that goes ahead, one
// that production refuses without a grant, one a rule forbids. Every call is in the audit log by tool, group and decision,
// and never by its arguments. The boxes are this spec's own; nothing here touches another spec's boxes.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

const OWN = 'ht-own';
const PROD = 'ht-prod';
const SENTINEL = 'sentinel-arg-8c41d';

async function makeBox(request: APIRequestContext, name: string, labels: Record<string, string> = {}) {
  if ((await request.get(`${origin()}/v1/boxes/${name}`, { headers: headers() })).ok()) return;
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers: headers(),
    data: { operation: { op: 'create', spec: { name, size: 'S', work_disk_gb: 50, image: null, region: null, from_snapshot: null, labels } } },
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

interface Settings {
  default_mode: string;
  modes: unknown[];
  rules: { id: string; tool: string | null }[];
  browser_hosts: string[];
}

async function settings(request: APIRequestContext): Promise<Settings> {
  const r = await request.get(`${origin()}/v1/permissions`, { headers: headers() });
  expect(r.ok()).toBe(true);
  return ((await r.json()) as { settings: Settings }).settings;
}

/** Take away any rule this spec added, so a retry (or another spec) starts clean. */
async function cleanRules(request: APIRequestContext) {
  const s = await settings(request);
  const rules = s.rules.filter((r) => r.tool !== 'files_search');
  if (rules.length !== s.rules.length) await request.put(`${origin()}/v1/permissions`, { headers: headers(), data: { ...s, rules } });
}

interface McpUrl {
  url: string;
  token: string;
}

async function mcpToken(request: APIRequestContext): Promise<McpUrl> {
  const r = await request.post(`${origin()}/v1/orchestrations/mcp-token`, { headers: headers(), data: {} });
  expect(r.ok(), await r.text()).toBe(true);
  return (await r.json()) as McpUrl;
}

interface Rpc {
  result?: { isError?: boolean; content?: { text: string }[]; tools?: { name: string; inputSchema: { required: string[] } }[] };
  error?: { code: number };
}

async function rpc(request: APIRequestContext, m: McpUrl, method: string, params: unknown): Promise<Rpc> {
  const r = await request.post(m.url, { headers: { Authorization: `Bearer ${m.token}`, 'Content-Type': 'application/json' }, data: { jsonrpc: '2.0', id: 1, method, params } });
  expect(r.status()).toBe(200);
  return (await r.json()) as Rpc;
}

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

test.beforeAll(async ({ playwright }) => {
  const request = await playwright.request.newContext();
  try {
    await makeBox(request, OWN);
    await makeBox(request, PROD, { env: 'production' });
  } finally {
    await request.dispose();
  }
});

test.afterAll(async ({ playwright }) => {
  const request = await playwright.request.newContext();
  try {
    await cleanRules(request);
    await removeBox(request, OWN);
    await removeBox(request, PROD);
  } finally {
    await request.dispose();
  }
});

for (const width of WIDTHS) {
  test(`tools at ${width}px: each tool shows its decision by place, an agent's calls go through the engine over MCP, and the log names the tool and never the arguments`, async ({ page, request }) => {
    await cleanRules(request);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/permissions');
      const card = page.getByTestId('perm-tools');
      await expect(card).toBeVisible({ timeout: 30_000 });
      const tool = (name: string) => card.locator(`[data-testid="host-tool"][data-tool="${name}"]`);
      await expect(card.getByTestId('host-tool')).toHaveCount(17);
      // a sandbox: reads go ahead, the shell and writes ask
      await expect(tool('files_read')).toHaveAttribute('data-effect', 'allow');
      await expect(tool('shell')).toHaveAttribute('data-effect', 'ask');
      await expect(tool('git_push')).toHaveAttribute('data-effect', 'ask');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));
      await axeClean(page, '[data-testid="perm-tools"]');
      // production: changes are refused without a grant, reads are not
      await page.getByRole('combobox', { name: 'Where' }).click();
      await page.getByRole('option', { name: 'Production' }).click();
      await expect(card.getByTestId('perm-tools-list')).toHaveAttribute('data-env', 'production');
      await expect(tool('shell')).toHaveAttribute('data-reason', 'production_no_grant');
      await expect(tool('shell')).toHaveAttribute('data-effect', 'deny');
      await expect(tool('files_read')).toHaveAttribute('data-effect', 'allow');

      // what an agent does over MCP, with a person's token
      const m = await mcpToken(request);
      const list = await rpc(request, m, 'tools/list', {});
      const names = (list.result?.tools ?? []).map((t) => t.name);
      for (const n of ['shell', 'git_push', 'files_write', 'browser_fetch', 'ci_rerun', 'staging_read']) expect(names).toContain(n);
      expect((list.result?.tools ?? []).find((t) => t.name === 'shell')?.inputSchema.required).toContain('box');
      const ok = await rpc(request, m, 'tools/call', { name: 'files_list', arguments: { box: OWN } });
      expect(ok.result?.isError).toBe(false);
      const refused = await rpc(request, m, 'tools/call', { name: 'shell', arguments: { box: PROD, command: `echo ${SENTINEL}` } });
      expect(refused.result?.isError).toBe(true);
      expect(refused.result?.content?.[0]?.text).toContain('production');
      const unknown = await rpc(request, m, 'tools/call', { name: 'format_disk', arguments: { box: OWN } });
      expect(unknown.error?.code).toBe(-32602);
      // a rule that forbids one tool stops its calls, and the page says which rule
      const s = await settings(request);
      const put = await request.put(`${origin()}/v1/permissions`, {
        headers: headers(),
        data: { ...s, rules: [...s.rules, { id: '', effect: 'deny', action: 'tool.call', scope: 'person', scope_id: null, path: null, command: null, env: null, tool: 'files_search', server: null, note: '' }] },
      });
      expect(put.ok(), await put.text()).toBe(true);
      const denied = await rpc(request, m, 'tools/call', { name: 'files_search', arguments: { box: OWN, text: SENTINEL } });
      expect(denied.result?.isError).toBe(true);
      expect(denied.result?.content?.[0]?.text).toContain('forbids');

      // the log: decisions and completions by tool and group, never the command or the text searched for
      await page.reload();
      await expect(tool('files_search')).toHaveAttribute('data-effect', 'deny', { timeout: 30_000 });
      await expect(tool('files_search')).toContainText('rule');
      const audit = page.getByTestId('perm-audit');
      await audit.getByRole('combobox', { name: 'Show' }).click();
      await page.getByRole('option', { name: 'Permission decisions' }).click();
      const list2 = page.getByTestId('perm-audit-list');
      await expect(list2.getByTestId('perm-audit-entry').filter({ hasText: 'tool=files_list' }).first()).toBeVisible({ timeout: 15_000 });
      await expect(list2.getByTestId('perm-audit-entry').filter({ hasText: 'permission.deny' }).filter({ hasText: 'tool=shell' }).first()).toContainText('production_no_grant');
      await expect(list2.getByTestId('perm-audit-entry').filter({ hasText: 'permission.deny' }).filter({ hasText: 'tool=files_search' }).first()).toContainText('rule_deny');
      await expect(list2.getByTestId('perm-audit-entry').filter({ hasText: 'server=files' }).first()).toBeVisible();
      await audit.getByRole('combobox', { name: 'Show' }).click();
      await page.getByRole('option', { name: 'Tool calls' }).click();
      await expect(list2.getByTestId('perm-audit-entry').filter({ hasText: 'tool.completed' }).filter({ hasText: 'tool=files_list' }).first()).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('perm-audit')).not.toContainText(SENTINEL);
      await expect(page.getByTestId('perm-audit-status')).toHaveAttribute('data-ok', 'yes', { timeout: 30_000 });
      await expectNoSidewaysScroll(page);
    } finally {
      await cleanRules(request);
    }
  });
}

test('the browser hosts are saved, checked and shown back', async ({ page, request }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, '/permissions');
  const hosts = page.getByTestId('perm-hosts');
  await expect(hosts).toBeVisible({ timeout: 30_000 });
  await hosts.getByLabel('Allowed hosts').fill('http://not-a-host');
  await hosts.getByRole('button', { name: 'Save hosts' }).click();
  await expect(hosts.getByText(/Use host names such as example.com/)).toBeVisible();
  await hosts.getByLabel('Allowed hosts').fill('docs.example.com *.example.org');
  await hosts.getByRole('button', { name: 'Save hosts' }).click();
  await expect(page.getByText('Hosts saved.').first()).toBeVisible();
  await page.reload();
  await expect(page.getByTestId('perm-hosts').getByLabel('Allowed hosts')).toHaveValue('docs.example.com *.example.org', { timeout: 15_000 });
  // put it back
  const s = await settings(request);
  await request.put(`${origin()}/v1/permissions`, { headers: headers(), data: { ...s, browser_hosts: [] } });
});
