import { expect, test, type APIRequestContext } from '@playwright/test';
import { applyPlan } from './apply';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// The Cloudflare tunnel on a box, from the Code panel, on the demo provider: set up through a reviewed plan, the token is
// asked once in a password field and shown nowhere afterwards, and the tunnel is removed through a reviewed plan.
// Nothing reaches a real box or a real Cloudflare account.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });
const TUNNEL_TOKEN = 'abcd'.repeat(12); // a made-up value of the right shape

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

for (const width of WIDTHS) {
  test(`the tunnel on a box at ${width}px: set up with a token that is never shown again, then removed`, async ({ page, request }, testInfo) => {
    const tag = testInfo.retry === 0 ? '' : `r${testInfo.retry}-`;
    const name = `conn-${tag}${width}`;
    await makeBox(request, name);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, `/boxes/${name}`);
      await page.getByRole('tab', { name: 'Code' }).click();
      const card = page.getByTestId('code-connector');
      await expect(card).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('code-state-connector')).toHaveText('Not set up', { timeout: 15_000 });
      // desktop editors over SSH keep their keybindings on the person's computer: the panel says so
      await expect(page.getByTestId('code-keybindings-note')).toContainText('keybindings');
      await expectNoSidewaysScroll(page);

      await card.getByRole('button', { name: 'Set up the tunnel on this box' }).click();
      const sheet = page.getByTestId('code-token-sheet');
      const field = sheet.getByLabel('Tunnel token');
      await expect(field).toHaveAttribute('type', 'password');
      await expect(field).toHaveAttribute('autocomplete', 'off');
      if (width < 1024) expect((await field.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(43.5);
      // an empty or odd token is refused before anything is planned
      await sheet.getByRole('button', { name: 'Review the change' }).click();
      await expect(sheet.getByRole('alert')).toContainText('Enter the tunnel token');
      await field.fill("not a token'; rm -rf ~");
      await sheet.getByRole('button', { name: 'Review the change' }).click();
      await expect(sheet.getByRole('alert')).toContainText('does not look like a Cloudflare tunnel token');
      await field.fill(TUNNEL_TOKEN);
      await sheet.getByRole('button', { name: 'Review the change' }).click();

      const plan = page.getByTestId('code-plan-sheet');
      await expect(plan.getByRole('list', { name: 'Changes' })).toContainText('private file');
      await expect(plan).not.toContainText(TUNNEL_TOKEN);
      await expect(page.getByTestId('code-state-connector')).toHaveText('Not set up');
      await plan.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(plan).toHaveCount(0, { timeout: 20_000 });
      await expect(page.getByTestId('code-state-connector')).toHaveText('Running', { timeout: 15_000 });

      // the token is on no page and in no answer
      expect(await page.locator('body').innerText()).not.toContain(TUNNEL_TOKEN);
      const answer = await (await page.request.get(`${origin()}/v1/boxes/${name}/code`, { headers: headers() })).text();
      expect(answer).not.toContain(TUNNEL_TOKEN);
      if (width < 1024) await expectTouchTargets(page, card);
      await expectNoSidewaysScroll(page);

      await card.getByRole('button', { name: 'Stop and remove the tunnel' }).click();
      await expect(plan.getByRole('list', { name: 'Changes' })).toContainText('delete its token');
      await plan.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(plan).toHaveCount(0, { timeout: 20_000 });
      await expect(page.getByTestId('code-state-connector')).toHaveText('Not set up', { timeout: 15_000 });
    } finally {
      await removeBox(request, name);
    }
  });
}
