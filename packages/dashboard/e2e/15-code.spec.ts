import { applyPlan } from './apply';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// A box's Code panel on the demo provider: the web IDE and the desktop are set up through a reviewed plan, opened on
// localhost through a one-time sign-in address, and removed again; the editors list carries the documented links. The
// demo's IDE is a stand-in server, and its password is kept by the server and never shown. Nothing reaches a real box.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function makeBox(request: APIRequestContext, name: string) {
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers: headers(),
    data: { operation: { op: 'create', spec: { name, size: 'S', work_disk_gb: 50, image: null, region: null, from_snapshot: null, labels: {} } } },
  });
  const body = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers(), { plan_id: body.plan_id })).ok()).toBe(true);
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
  test(`code at ${width}px: set up the IDE, open it on localhost, see the editors, remove it`, async ({ page, request, context }, testInfo) => {
    // a name of its own per retry and per repeat: the demo keeps a box's code state by name after it is destroyed
    const tag = `${testInfo.repeatEachIndex === 0 ? '' : `p${testInfo.repeatEachIndex}-`}${testInfo.retry === 0 ? '' : `r${testInfo.retry}-`}`;
    const name = `code-${tag}${width}`;
    await makeBox(request, name);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, `/boxes/${name}`);
      await page.getByRole('tab', { name: 'Code' }).click();
      const tab = page.getByTestId('code-tab');
      await expect(tab).toBeVisible();
      const ide = page.getByTestId('code-svc-ide');
      await expect(page.getByTestId('code-state-ide')).toHaveText('Not set up', { timeout: 15_000 });
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, tab);
      await axeClean(page, 'code-tab');

      // the address switch says what it needs, and is off
      const sw = ide.getByRole('switch', { name: 'Serve Web IDE on your own address' });
      await expect(sw).toBeDisabled();
      await expect(ide.getByText(/sign-in mode/)).toBeVisible();

      // set up: reviewed first, nothing changes until Apply
      await ide.getByRole('button', { name: 'Set up Web IDE' }).click();
      const plan = page.getByTestId('code-plan-sheet');
      await expect(plan.getByRole('list', { name: 'Changes' })).toContainText('127.0.0.1');
      await expect(page.getByTestId('code-state-ide')).toHaveText('Not set up');
      await expectNoSidewaysScroll(page);
      const apply = plan.getByRole('button', { name: 'Apply', exact: true });
      await expect(apply).toBeInViewport();
      if (width < 1024) expect((await apply.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(43.5);
      await axeClean(page, 'code-plan-sheet');
      await apply.click();
      await expect(plan).toHaveCount(0, { timeout: 20_000 });
      await expect(page.getByTestId('code-state-ide')).toHaveText('Running', { timeout: 15_000 });

      // the server keeps the password: it is on no page and in no answer
      const answer = await (await page.request.get(`${origin()}/v1/boxes/${name}/code`, { headers: headers() })).text();
      expect(answer).not.toMatch(/"password"\s*:/);
      expect(answer).toContain('"password_set":true');

      // open on localhost: a new tab, signed in by the one-time address, shows the (simulated) IDE
      const opened = context.waitForEvent('page');
      await ide.getByRole('button', { name: 'Open Web IDE' }).click();
      const tabPage = await opened;
      await tabPage.waitForLoadState('domcontentloaded');
      await expect(tabPage.locator('body')).toContainText('Simulated web IDE', { timeout: 15_000 });
      expect(tabPage.url()).toMatch(/^http:\/\/localhost:\d+\//);
      await tabPage.close();

      // the editors: the documented links, and none where there is none
      const vscode = page.getByTestId('code-editor-vscode').getByRole('link', { name: 'Open in VS Code' });
      await expect(vscode).toHaveAttribute('href', `vscode://vscode-remote/ssh-remote+ozbox-${name}/work/repos`);
      await expect(page.getByTestId('code-editor-zed').getByRole('link')).toHaveAttribute('href', `zed://ssh/ozbox-${name}/work/repos`);
      await expect(page.getByTestId('code-editor-cursor')).toContainText("does not describe this link");
      await expect(page.getByTestId('code-editor-jetbrains').getByRole('link')).toHaveCount(0);
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, tab);
      await axeClean(page, 'code-tab');

      await expect(page.getByTestId('code-browser-note')).toContainText('about:config');
      // what is running: terminal sessions that outlive the tab, agents and servers; stopping is planned first
      const running = page.getByTestId('code-running');
      await expect(running.getByTestId('code-session-term-1')).toBeVisible({ timeout: 15_000 });
      await expect(running).toContainText('tmux sessions end if the box restarts');
      await expect(running.getByTestId('code-agent-4242')).toContainText('claude');
      await expect(running.getByTestId('code-server-3000')).toBeVisible();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, running);
      await axeClean(page, 'code-running');
      await running.getByRole('button', { name: 'Stop session term-1' }).click();
      await expect(plan.getByRole('list', { name: 'Changes' })).toContainText('tmux session term-1');
      await expect(running.getByTestId('code-session-term-1')).toBeVisible();
      await plan.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(plan).toHaveCount(0, { timeout: 20_000 });
      // the list is read again after a change: wait for the new answer (term-2 present), then check term-1 is gone
      await expect(running.getByTestId('code-session-term-2')).toBeVisible({ timeout: 20_000 });
      await expect(running.getByTestId('code-session-term-1')).toHaveCount(0);
      // Open goes to the web terminal
      await running.getByRole('button', { name: 'Open term-2 in the web terminal' }).click();
      await expect(page.getByRole('tab', { name: 'Terminal' })).toHaveAttribute('aria-selected', 'true');
      await page.getByRole('tab', { name: 'Code' }).click();

      // remove: reviewed, then gone
      await ide.getByRole('button', { name: 'Stop and remove Web IDE' }).click();
      await expect(plan.getByRole('list', { name: 'Changes' })).toContainText('remove');
      await plan.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(plan).toHaveCount(0, { timeout: 20_000 });
      await expect(page.getByTestId('code-state-ide')).toHaveText('Not set up', { timeout: 15_000 });
    } finally {
      await removeBox(request, name);
    }
  });
}
