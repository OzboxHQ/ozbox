
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Skills: a shipped skill is unusable until a person reads and approves its exact files. Each width uses its own skill so a
// retry or another width never meets this one's state, and each test puts the skill back as it found it.

const SKILL: Record<number, string> = { 390: 'ci-failure-triage', 820: 'eval-runner', 1024: 'keep-memory', 1440: 'reply-drafter' };

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function reset(request: APIRequestContext, name: string) {
  await request.post(`${origin()}/v1/skills/${name}/uninstall`, { headers: headers(), data: { scope: 'fleet' } });
  await request.post(`${origin()}/v1/skills/${name}/revoke`, { headers: headers() });
}

for (const width of WIDTHS) {
  test(`skills at ${width}px: install, review, approve, and nothing is usable before that`, async ({ page, request }) => {
    const name = SKILL[width] ?? 'keep-memory';
    await reset(request, name);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/skills');
      await expect(page.getByRole('heading', { name: 'Skills', level: 1 })).toBeVisible();
      await expectNoSidewaysScroll(page);

      const card = page.locator(`[data-testid="skill-card"][data-skill="${name}"]`);
      await expect(card).toBeVisible();
      await expect(card).toContainText('Ships with Oz Box');
      await expect(card).toContainText('Not installed anywhere');
      if (width < 1024) await expectTouchTargets(page, card);

      await card.getByRole('button', { name: 'Install', exact: true }).click();
      const install = page.getByTestId('skill-install-sheet');
      await axeClean(page, 'skill-install-sheet');
      await install.getByRole('button', { name: 'Install', exact: true }).click();
      await expect(install).toHaveCount(0);
      await expect(card.getByTestId('skill-install')).toContainText('Waiting for your review');

      // review shows the files themselves, then approves exactly them
      await card.getByRole('button', { name: 'Review and approve' }).click();
      const review = page.getByTestId('skill-review-sheet');
      await expect(review.locator('pre').first()).toContainText('name:');
      if (width < 1024) await expectTouchTargets(page, review);
      await axeClean(page, 'skill-review-sheet');
      await review.getByRole('button', { name: 'Approve these files' }).click();
      await expect(review).toHaveCount(0);
      await expect(card.getByTestId('skill-install')).toContainText('Approved');

      // the approval is a record: reload and it is still there
      await page.reload();
      await expect(page.locator(`[data-testid="skill-card"][data-skill="${name}"]`).getByTestId('skill-install')).toContainText('Approved');

      // withdraw it: the install stays and waits for review again
      await page.locator(`[data-testid="skill-card"][data-skill="${name}"]`).getByRole('button', { name: 'Withdraw approval' }).click();
      await expect(page.locator(`[data-testid="skill-card"][data-skill="${name}"]`).getByTestId('skill-install')).toContainText('Waiting for your review');

      // remove the install, behind a confirmation
      await page.locator(`[data-testid="skill-card"][data-skill="${name}"]`).getByRole('button', { name: 'Remove', exact: true }).click();
      await page.getByRole('button', { name: 'Remove install' }).click();
      await expect(page.locator(`[data-testid="skill-card"][data-skill="${name}"]`)).toContainText('Not installed anywhere');
    } finally {
      await reset(request, name);
    }
  });
}
