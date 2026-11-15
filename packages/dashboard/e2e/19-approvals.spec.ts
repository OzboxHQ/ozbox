
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// The approvals inbox on the demo provider: an agent that wants to push to a protected branch or run a command on the ask
// list stops and asks; the exact action is shown; Approve and Deny are decided once, and each decision is in Activity.
// The policy is edited in Settings, Approvals with a review of what changes. The agent is simulated.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function seed(request: APIRequestContext, prompt: string): Promise<string> {
  const r = await request.post(`${origin()}/v1/tasks`, { headers: headers(), data: { engine: 'fake', box: 'charlie', prompt } });
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

for (const width of WIDTHS) {
  test(`approvals at ${width}px: the exact action is shown, approving lets the run go on, and it is audited`, async ({ page, request }, testInfo) => {
    const marker = `appr-${width}-${testInfo.retry}`;
    const id = await seed(request, `${marker} sim:steps=100000 sim:push=main`);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/approvals');
      const item = page.getByTestId('agent-approval').filter({ hasText: 'git push origin main' }).first();
      await expect(item).toBeVisible({ timeout: 30_000 });
      await expect(item.getByTestId('exact-action')).toHaveText('git push origin main');
      await expect(item).toContainText('Push to a protected branch');
      await expect(item).toContainText('Second factor needed');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.getByTestId('agent-approvals'));
      await axeClean(page, '[data-testid="agent-approvals"]');

      // approving asks again with the exact action, so a stray tap cannot do it
      await item.getByRole('button', { name: 'Approve' }).click();
      const confirm = page.getByRole('alertdialog');
      await expect(confirm).toContainText('git push origin main');
      await confirm.getByRole('button', { name: 'Approve' }).click();
      await expect(page.getByTestId('agent-approval').filter({ hasText: 'git push origin main' })).toHaveCount(0, { timeout: 15_000 });
      await expect(page.getByText(/Approved by owner/).first()).toBeVisible();

      // the run carries on
      await open(page, '/tasks');
      await expect(page.getByTestId('col-running').getByTestId('task-card').filter({ hasText: marker })).toBeVisible({ timeout: 30_000 });
      // and the decision is in Activity
      await open(page, '/activity');
      await expect(page.getByText('approval.approved (owner)').locator('visible=true').first()).toBeVisible({ timeout: 15_000 });
    } finally {
      await cancel(request, id);
    }
  });
}

test('denying refuses the action, and the same request cannot be decided twice', async ({ page, request }) => {
  const marker = `deny-${Date.now()}`;
  const id = await seed(request, `${marker} sim:steps=100000 sim:command=sudo`);
  try {
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, '/approvals');
    const item = page.getByTestId('agent-approval').filter({ hasText: 'sudo' }).first();
    await expect(item).toBeVisible({ timeout: 30_000 });
    await expect(item).toContainText('Run a command on the ask list');
    const pending = await request.get(`${origin()}/v1/approval-requests`, { headers: headers() });
    const first = ((await pending.json()) as { items: { id: string; action: string }[] }).items.find((a) => a.action === 'sudo');
    expect(first).toBeTruthy();
    await item.getByRole('button', { name: 'Deny' }).click();
    await expect(page.getByText(/Denied by owner/).first()).toBeVisible({ timeout: 15_000 });
    const again = await request.post(`${origin()}/v1/approval-requests/${first?.id}/approve`, { headers: headers() });
    expect(again.status()).toBe(409);
  } finally {
    await cancel(request, id);
  }
});

for (const width of WIDTHS) {
  test(`Settings, Approvals at ${width}px: edit the policy with a review, and set a spend limit`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/settings/approvals');
    await expect(page.getByText('Push to a protected branch').first()).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));
    await page.getByRole('button', { name: 'Edit approvals' }).click();
    const sheet = page.getByTestId('policy-sheet');
    // a bad entry is refused with a reason
    await sheet.getByLabel('Protected branches').fill('bad branch');
    await sheet.getByRole('button', { name: 'Review changes' }).click();
    await expect(sheet.getByText('A branch name has characters it cannot have.')).toBeVisible();
    await sheet.getByLabel('Protected branches').fill('main\nstaging\nrelease/*');
    const usd = Math.floor(width / 10);
    await sheet.getByLabel('An action that would spend more than (US dollars)').fill(String(usd));
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page, '[data-testid="policy-sheet"]');
    // what will change is shown before anything is saved
    await sheet.getByRole('button', { name: 'Review changes' }).click();
    const review = sheet.getByTestId('policy-review');
    await expect(review).toContainText(`$${usd}.00`);
    await sheet.getByRole('button', { name: 'Back' }).click();
    await sheet.getByRole('button', { name: 'Review changes' }).click();
    await sheet.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText(`$${usd}.00`).first()).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: 'Edit limits' }).click();
    const caps = page.getByTestId('caps-sheet');
    await caps.getByLabel('Whole fleet, per month (US dollars)').fill('lots');
    await caps.getByRole('button', { name: 'Save' }).click();
    await expect(caps.getByText('Use an amount like 500 or leave it empty.')).toBeVisible();
    await caps.getByLabel('Whole fleet, per month (US dollars)').fill('500');
    await caps.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText(/of \$500\.00 used this month/)).toBeVisible({ timeout: 10_000 });
    await axeClean(page, 'main');
  });
}
