import { applyPlan } from './apply';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Schedules on the demo provider: the plain-language builder with its five-run preview (local time and UTC) before
// saving, pause and resume, run now into the history, and a paused box that is woken for a run. Nothing here reaches a
// real cloud or a real agent: the demo's runs are a stand-in that succeeds after a few seconds.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function plan(request: APIRequestContext, operation: object, confirm?: string) {
  const p = await request.post(`${origin()}/v1/plans`, { headers: headers(), data: { operation } });
  if (!p.ok()) return;
  const body = (await p.json()) as { plan_id: string };
  await applyPlan(request, origin(), headers(), { plan_id: body.plan_id, ...(confirm ? { confirm_name: confirm } : {}) });
}

async function removeSchedules(request: APIRequestContext, prefix: string) {
  const r = await request.get(`${origin()}/v1/schedules`, { headers: headers() });
  const body = (await r.json()) as { schedules: { id: string; name: string }[] };
  for (const s of body.schedules.filter((x) => x.name.startsWith(prefix))) await request.delete(`${origin()}/v1/schedules/${s.id}`, { headers: headers() });
}

async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function pickBox(page: Page, sheetId: string, box: string) {
  const sheet = page.getByTestId(sheetId);
  await sheet.getByRole('combobox', { name: 'Box' }).click();
  await page.getByRole('option', { name: box, exact: true }).click();
}

for (const width of WIDTHS) {
  test(`schedules at ${width}px: build with a preview, pause, run now and see the history`, async ({ page, request }) => {
    const name = `e2e-brief-${width}`;
    await removeSchedules(request, `e2e-`);
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/schedules');
      await expect(page.getByRole('heading', { name: 'Schedules', level: 1 })).toBeVisible();
      await expectNoSidewaysScroll(page);

      await page.getByRole('button', { name: 'New schedule' }).first().click();
      const sheet = page.getByTestId('schedule-sheet');
      await expect(sheet).toBeVisible();
      await sheet.getByLabel('Name').fill(name);
      await sheet.getByLabel('When, in words').fill('every weekday at 9am Lagos time');
      // the demo's own agent is the default here (a real server defaults to claude-code), so there is nothing to type
      await sheet.getByLabel('What should it do?').fill('sim:steps=1 Summarise overnight CI.');
      await pickBox(page, 'schedule-sheet', 'alpha');

      // Saving without a preview is refused; the preview shows the cron, the zone and five runs in local time and UTC.
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet.getByRole('alert')).toContainText('Preview the runs before saving');
      await sheet.getByRole('button', { name: 'Preview the next 5 runs' }).click();
      const preview = page.getByTestId('schedule-preview');
      await expect(preview).toContainText('0 9 * * 1-5');
      await expect(preview).toContainText('Africa/Lagos');
      await expect(preview.getByRole('listitem')).toHaveCount(5);
      await expect(preview.getByRole('listitem').first()).toContainText('UTC');
      await expect(preview.getByRole('listitem').first()).toContainText('09:00');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, 'schedule-sheet');

      // Changing the time makes the preview stale.
      await sheet.getByLabel('When, in words').fill('every day at 14:30');
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet.getByRole('alert')).toContainText('Preview again before saving');
      await sheet.getByRole('button', { name: 'Preview the next 5 runs' }).click();
      await expect(preview).toContainText('30 14 * * *');
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet).toHaveCount(0);

      const card = page.getByTestId('schedule-card').filter({ hasText: name });
      await expect(card).toBeVisible();
      await expect(card).toContainText('every day at 14:30');
      await expect(card).toContainText('On');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, card);
      await axeClean(page, 'schedule-card');

      // Pause, then resume.
      await card.getByRole('button', { name: 'Pause' }).click();
      await expect(card).toContainText('Paused');
      await card.getByRole('button', { name: 'Resume' }).click();
      await expect(card).toContainText('On');

      // Run now lands in the history within a few seconds and finishes (the demo's run takes a moment).
      await card.getByRole('button', { name: 'Run now' }).click();
      await card.getByRole('button', { name: 'History' }).click();
      const history = page.getByTestId('history-sheet');
      await expect(history.getByTestId('run-row').first()).toBeVisible({ timeout: 30_000 });
      await expect(history.getByTestId('run-row').first()).toContainText('Succeeded', { timeout: 40_000 });
      await expect(history.getByTestId('run-row').first()).toContainText('Run now');
      await expectNoSidewaysScroll(page);
      await axeClean(page, 'history-sheet');
      await history.getByRole('button', { name: 'Close' }).first().click();

      // A second run while none is going is fine, and removing asks first.
      await card.getByRole('button', { name: 'Remove' }).click();
      await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
      await expect(page.getByTestId('schedule-card').filter({ hasText: name })).toHaveCount(0);
    } finally {
      await removeSchedules(request, 'e2e-');
    }
  });
}

test('schedules: a heartbeat starts switched off, and a run on a paused box wakes it first', async ({ page, request }) => {
  const box = 'sched-sleepy';
  await plan(request, { op: 'create', spec: { name: box, size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} } });
  await plan(request, { op: 'pause', name: box });
  try {
    await page.setViewportSize({ width: 1440, height: 900 });
    await open(page, '/schedules');

    // Heartbeat: off until a person turns it on.
    await page.getByRole('button', { name: 'New schedule' }).first().click();
    const sheet = page.getByTestId('schedule-sheet');
    await sheet.getByLabel('Name').fill('e2e-heartbeat');
    await sheet.getByRole('combobox', { name: 'Kind' }).click();
    await page.getByRole('option', { name: 'A heartbeat (check-in)' }).click();
    await sheet.getByLabel('Check in every (minutes)').fill('30');
    await pickBox(page, 'schedule-sheet', box);
    await sheet.getByRole('button', { name: 'Save' }).click();
    const hb = page.getByTestId('schedule-card').filter({ hasText: 'e2e-heartbeat' });
    await expect(hb).toContainText('Paused');
    await expect(hb).toContainText('Heartbeat');
    await expect(hb).toContainText('Every 30 minutes');

    // A scheduled run for a paused box wakes it, and says so.
    await page.getByRole('button', { name: 'New schedule' }).first().click();
    await sheet.getByLabel('Name').fill('e2e-wake');
    await sheet.getByLabel('When, in words').fill('every day at 3am UTC');
    await sheet.getByLabel('What should it do?').fill('sim:steps=1 Check the disk.');
    await pickBox(page, 'schedule-sheet', box);
    await sheet.getByRole('button', { name: 'Preview the next 5 runs' }).click();
    await expect(page.getByTestId('schedule-preview').getByRole('listitem')).toHaveCount(5);
    await sheet.getByRole('button', { name: 'Save' }).click();
    const card = page.getByTestId('schedule-card').filter({ hasText: 'e2e-wake' });
    await card.getByRole('button', { name: 'Run now' }).click();
    await card.getByRole('button', { name: 'History' }).click();
    const row = page.getByTestId('history-sheet').getByTestId('run-row').first();
    await expect(row).toContainText('Woke the paused box first', { timeout: 30_000 });
  } finally {
    await removeSchedules(request, 'e2e-');
    await plan(request, { op: 'destroy', name: box, final_snapshot: false }, box);
  }
});

// A schedule can target "any box with this profile" instead of one box.
for (const width of WIDTHS) {
  test(`schedules at ${width}px: the box picker offers a profile, and the schedule is saved against it`, async ({ page, request }) => {
    const name = `e2e-profile-${width}`;
    const box = `prof-${width}`;
    const profile = `e2eprof${width}`;
    await removeSchedules(request, 'e2e-');
    await plan(request, { op: 'create', spec: { name: box, size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: { profile } } });
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/schedules');
      await page.getByRole('button', { name: 'New schedule' }).first().click();
      const sheet = page.getByTestId('schedule-sheet');
      await sheet.getByLabel('Name').fill(name);
      await sheet.getByLabel('When, in words').fill('every day at 14:30');
      await sheet.getByLabel('What should it do?').fill('sim:steps=1 Check the profile.');
      await sheet.getByRole('combobox', { name: 'Box' }).click();
      await page.getByRole('option', { name: `Any box with the profile ${profile}` }).click();
      if (width < 1024) await expectTouchTargets(page, sheet);
      await expectNoSidewaysScroll(page);
      await sheet.getByRole('button', { name: 'Preview the next 5 runs' }).click();
      // the box named schedule-preview holds the Preview button too, so it is the five runs that say the preview has come back
      await expect(page.getByTestId('schedule-preview').getByRole('listitem')).toHaveCount(5);
      await sheet.getByRole('button', { name: 'Save' }).click();
      await expect(sheet).toBeHidden();
      const list = (await (await request.get(`${origin()}/v1/schedules`, { headers: headers() })).json()) as { schedules: { name: string; target: { box_name: string | null; profile: string | null } }[] };
      const saved = list.schedules.find((s) => s.name === name);
      expect(saved?.target).toEqual({ box_name: null, profile });
    } finally {
      await removeSchedules(request, 'e2e-');
      await plan(request, { op: 'destroy', name: box, final_snapshot: false }, box);
    }
  });
}
