import { expect, test, type APIRequestContext } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open } from './fixtures';

// G7 R2, tier A (the demo provider): Runs is folded into Tasks, a box links to its own tasks, and Approvals says that plans are
// kept in memory. The demo banner and the Simulated badge stay on every page that shows made-up data.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function seed(request: APIRequestContext, box: string, prompt: string): Promise<string> {
  const r = await request.post(`${origin()}/v1/tasks`, { headers: headers(), data: { engine: 'fake', box, prompt } });
  expect(r.status()).toBe(201);
  return ((await r.json()) as { id: string }).id;
}

for (const width of WIDTHS) {
  test(`the old Runs address lands on Tasks, and the menu has no Runs, at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/runs');
    await expect(page).toHaveURL(/\/tasks$/);
    await expect(page.getByRole('heading', { name: 'Tasks', level: 1 })).toBeVisible();
    await expect(page.getByTestId('demo-banner')).toBeVisible();
    await expect(page.getByText('Simulated').first()).toBeVisible();
    await expect(page.getByRole('link', { name: 'Runs', exact: true })).toHaveCount(0);
    await expectNoSidewaysScroll(page);
  });

  test(`a box links to its own tasks and Tasks opens filtered to it at ${width}px`, async ({ page, request }) => {
    const mine = `r2-box-${width}-${Date.now()}`;
    const theirs = `r2-other-${width}-${Date.now()}`;
    const a = await seed(request, 'charlie', mine);
    const b = await seed(request, 'alpha', theirs);
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/boxes/charlie');
    const link = page.getByTestId('box-tasks-link');
    await expect(link).toBeVisible();
    if (width < 1024) {
      const bb = await link.boundingBox();
      expect(bb?.height ?? 0, 'touch target').toBeGreaterThanOrEqual(43.5);
    }
    await link.click();
    await expect(page).toHaveURL(/\/tasks\?box=charlie$/);
    await expect(page.getByTestId('task-card').filter({ hasText: mine }).first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('task-card').filter({ hasText: theirs })).toHaveCount(0);
    await expect(page.getByLabel('Box', { exact: true })).toContainText('charlie');
    await expectNoSidewaysScroll(page);
    await request.post(`${origin()}/v1/tasks/${a}/cancel`, { headers: headers() });
    await request.post(`${origin()}/v1/tasks/${b}/cancel`, { headers: headers() });
  });

  test(`Approvals says plans are kept in memory, and what happens to one that lapses, at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/approvals');
    await expect(page.getByRole('heading', { name: 'Approvals', level: 1 })).toBeVisible();
    const note = page.getByTestId('plans-memory-note');
    await expect(note).toBeVisible({ timeout: 15_000 });
    await expect(note).toContainText('memory');
    await expect(note).toContainText('10 minutes');
    await expect(note).toContainText('never on disk');
    await expect(page.getByTestId('demo-banner')).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.locator('main'));
  });
}

test('the API says plans are kept in memory', async ({ request }) => {
  const r = await request.get(`${origin()}/v1/approvals`, { headers: headers() });
  expect(r.status()).toBe(200);
  const body = (await r.json()) as { persisted: boolean; ttl_s: number };
  expect(body.persisted).toBe(false);
  expect(body.ttl_s).toBe(600);
});
