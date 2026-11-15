
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Permissions and the audit log on the demo provider: the mode, a rule, a time-boxed Production grant and the tamper-evident
// chain. What the engine decides is asked through the dry-run endpoint, so nothing here depends on (or disturbs) a running
// agent. Every rule and grant names a box that does not exist, so no other spec is affected.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

interface Check {
  effect: string;
  reason: string;
}

async function check(request: APIRequestContext, body: Record<string, unknown>): Promise<Check> {
  const r = await request.post(`${origin()}/v1/permissions/check`, { headers: headers(), data: body });
  expect(r.status()).toBe(200);
  return (await r.json()) as Check;
}

/** Remove anything a run of this spec left, so a retry starts clean. */
async function cleanUp(request: APIRequestContext, box: string) {
  const v = await request.get(`${origin()}/v1/permissions`, { headers: headers() });
  if (!v.ok()) return;
  const view = (await v.json()) as { settings: { default_mode: string; modes: unknown[]; rules: { id: string; scope_id: string | null }[] }; grants: { id: string; scope_id: string; state: string }[] };
  for (const g of view.grants) if (g.scope_id === box && g.state === 'active') await request.post(`${origin()}/v1/permissions/grants/${g.id}/revoke`, { headers: headers(), data: {} });
  const rules = view.settings.rules.filter((r) => r.scope_id !== box);
  if (rules.length !== view.settings.rules.length || view.settings.default_mode !== 'ask') {
    await request.put(`${origin()}/v1/permissions`, { headers: headers(), data: { ...view.settings, default_mode: 'ask', rules } });
  }
}

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

for (const width of WIDTHS) {
  test(`permissions at ${width}px: the page fits, a rule forbids, a grant opens production for a while and ends when revoked, and the log verifies`, async ({ page, request }, testInfo) => {
    const box = `zz-perm-${width}-${testInfo.retry}`;
    await cleanUp(request, box);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/permissions');
      await expect(page.getByRole('heading', { name: 'Permissions', level: 1 })).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId('perm-mode')).toBeVisible();
      await expect(page.getByTestId('perm-audit-status')).toHaveAttribute('data-ok', 'yes', { timeout: 30_000 });
      await expectNoSidewaysScroll(page);
      await expect(page.getByTestId('perm-grant-add')).toBeInViewport({ ratio: 0 });
      if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));
      await axeClean(page, '[data-testid="perm-mode"]');
      await axeClean(page, '[data-testid="perm-audit"]');

      // the mode: choosing one explains it; saving it survives a reload
      await page.getByRole('combobox', { name: 'Default mode' }).click();
      await page.getByRole('option', { name: 'Accept edits' }).click();
      await expect(page.getByTestId('perm-mode-help')).toContainText('File edits go ahead too');
      await page.getByRole('button', { name: 'Save mode' }).click();
      await expect(page.getByText('Mode saved.').first()).toBeVisible();
      await page.reload();
      await expect(page.getByTestId('perm-mode-select')).toContainText('Accept edits');

      // a rule: forbid pushing on a box; deny wins and only that box is affected
      expect((await check(request, { action: 'git.push', box_name: box })).effect).toBe('allow');
      await page.getByTestId('perm-rule-add').click();
      const sheet = page.getByTestId('perm-rule-sheet');
      await sheet.getByRole('button', { name: 'Add rule' }).click();
      await expect(sheet.getByText('Give an action, such as git.push or git.*.')).toBeVisible();
      await sheet.getByLabel('Action', { exact: true }).fill('git.push');
      await sheet.getByRole('combobox', { name: 'Applies to' }).click();
      await page.getByRole('option', { name: 'One box' }).click();
      await sheet.getByLabel('Which one').fill(box);
      await sheet.getByRole('button', { name: 'Add rule' }).click();
      await expect(page.getByTestId('perm-rule').filter({ hasText: box })).toContainText('Forbid git.push');
      const denied = await check(request, { action: 'git.push', box_name: box });
      expect(denied).toMatchObject({ effect: 'deny', reason: 'rule_deny' });
      expect((await check(request, { action: 'git.push', box_name: `${box}-other` })).effect).toBe('allow');

      // production: refused without a grant ...
      const prod = { action: 'command.run', box_name: box, env: 'production', actor: 'agent' };
      expect((await check(request, { ...prod, action: 'resource.touch' })).reason).toBe('production_no_grant');
      // ... a grant needs its name typed back when signed out ...
      await page.getByTestId('perm-grant-add').click();
      const gsheet = page.getByTestId('perm-grant-sheet');
      await gsheet.getByLabel('Which one').fill(box);
      await gsheet.getByLabel('Reason').fill('deploy the fix');
      await gsheet.getByLabel('Minutes').fill('5');
      await gsheet.getByLabel('Type the name to confirm').fill('not-the-name');
      await gsheet.getByRole('button', { name: 'Grant access' }).click();
      await expect(gsheet.getByText('The name does not match.')).toBeVisible();
      await expect(page.getByTestId('perm-grant')).toHaveCount(0);
      // ... and with it, the grant is made, shows how long is left, and says it is not a second factor
      await gsheet.getByLabel('Type the name to confirm').fill(box);
      await gsheet.getByRole('button', { name: 'Grant access' }).click();
      const grant = page.getByTestId('perm-grant').filter({ hasText: box });
      await expect(grant).toBeVisible({ timeout: 15_000 });
      await expect(grant).toContainText(/min left/);
      await expect(grant).toContainText('not a second factor');
      expect((await check(request, { ...prod, action: 'resource.touch' })).effect).not.toBe('deny');
      // the grant does not reach another box
      expect((await check(request, { ...prod, box_name: `${box}-other` })).reason).toBe('production_no_grant');

      // revoking ends it at once
      await grant.getByRole('button', { name: 'Revoke' }).click();
      await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke' }).click();
      await expect(page.getByTestId('perm-grant').filter({ hasText: box })).toHaveCount(0, { timeout: 15_000 });
      expect((await check(request, { ...prod, action: 'resource.touch' })).reason).toBe('production_no_grant');

      // the log has all of it, and still verifies
      await page.getByTestId('perm-audit-check').click();
      await expect(page.getByTestId('perm-audit-status')).toHaveAttribute('data-ok', 'yes', { timeout: 30_000 });
      await page.getByRole('combobox', { name: 'Show' }).click();
      await page.getByRole('option', { name: 'Grants' }).click();
      await expect(page.getByTestId('perm-audit-entry').filter({ hasText: 'grant.created' }).first()).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('perm-audit-entry').filter({ hasText: 'grant.revoked' }).first()).toBeVisible();
      // ids and words only: the reason typed into the grant is not copied into the log
      await expect(page.getByTestId('perm-audit-list')).not.toContainText('deploy the fix');
      await expectNoSidewaysScroll(page);

      // remove the rule
      await page.getByRole('combobox', { name: 'Show' }).click();
      await page.getByRole('option', { name: 'Everything' }).click();
      await page.getByTestId('perm-rule').filter({ hasText: box }).getByRole('button', { name: 'Remove' }).click();
      await expect(page.getByTestId('perm-rule').filter({ hasText: box })).toHaveCount(0, { timeout: 15_000 });
      expect((await check(request, { action: 'git.push', box_name: box })).effect).toBe('allow');
    } finally {
      await cleanUp(request, box);
    }
  });
}

test('the audit check is served and finds nothing wrong on a fresh demo', async ({ request }) => {
  const r = await request.get(`${origin()}/v1/audit/verify`, { headers: headers() });
  expect(r.status()).toBe(200);
  const body = (await r.json()) as { report: { ok: boolean; altered: number[]; deleted: unknown[] } };
  expect(body.report.ok).toBe(true);
  expect(body.report.altered).toEqual([]);
  expect(body.report.deleted).toEqual([]);
});
