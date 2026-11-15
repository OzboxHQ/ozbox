import { type APIRequestContext, expect, test } from '@playwright/test';

import { applyPlan } from './apply';
import { WIDTHS, expectNoSidewaysScroll, open } from './fixtures';

// G7 R1 on the demo provider (tier A): a change to a box runs as a job, Needs you lists a failing self-test, Boxes has a Create
// button, and the Box page's Usage tab and cost are not hidden. The spec makes its own box that fails its self-test (a label
// steers the demo provider), so what earlier specs did to the seeded boxes does not matter.
// A box name is unique per run, so a box left by an earlier spec (or an earlier attempt) on the shared server cannot collide.
const unique = (base: string) => `${base}-${Math.random().toString(16).slice(2, 8)}`;
const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;

// clean up through the same path; a box that was never made has nothing to destroy and is not an error
async function destroyBox(request: APIRequestContext, name: string): Promise<void> {
  const headers = { Authorization: `Bearer ${token()}` };
  const del = await request.post(`${origin()}/v1/plans`, { headers, data: { operation: { op: 'destroy', name, final_snapshot: false } } });
  if (del.status() !== 200) return;
  const d = (await del.json()) as { plan_id: string };
  await applyPlan(request, origin(), headers, { plan_id: d.plan_id, confirm_name: name });
}

// The shared server has no cap on running boxes (spec 00 puts back the one it sets, and spec 01 checks that). This spec still lifts
// whatever cap it finds for the length of the file, so a cap set by a future spec could not refuse its creates, and puts it back.
type Settings = { budget: Record<string, unknown> };
let savedSettings: Settings | undefined;
test.beforeAll(async ({ request }) => {
  const headers = { Authorization: `Bearer ${token()}` };
  const cur = (await (await request.get(`${origin()}/v1/settings`, { headers })).json()) as { settings: Settings };
  savedSettings = cur.settings;
  const raised = { ...cur.settings, budget: { ...cur.settings.budget, max_running_boxes: 100 } };
  const put = await request.put(`${origin()}/v1/settings`, { headers, data: raised });
  expect(put.ok(), await put.text()).toBe(true);
});

test('a change answers at once with a job, and the job ends done with what applying returned', async ({ request }) => {
  const headers = { Authorization: `Bearer ${token()}` };
  const name = unique('r1-job');
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers,
    data: { operation: { op: 'create', spec: { name, size: 'S', work_disk_gb: 50, image: null, region: null, from_snapshot: null, labels: {} } } },
  });
  // a refused plan (a duplicate name, too many open plans) says why here, instead of a 400 on apply for a missing plan_id
  expect(plan.status(), await plan.text()).toBe(200);
  const { plan_id } = (await plan.json()) as { plan_id: string };
  expect(plan_id).toBeTruthy();
  try {
    const first = await request.post(`${origin()}/v1/apply`, { headers, data: { plan_id } });
    expect(first.status(), await first.text()).toBe(202);
    const { job_id } = (await first.json()) as { job_id: string };
    let job: { state: string; result?: { applied: boolean } } = { state: 'running' };
    for (let i = 0; i < 100 && job.state === 'running'; i++) {
      job = (await (await request.get(`${origin()}/v1/jobs/${job_id}`, { headers })).json()) as typeof job;
      if (job.state === 'running') await new Promise((r) => setTimeout(r, 100));
    }
    expect(job.state).toBe('done');
    expect(job.result?.applied).toBe(true);
    // the same plan cannot be used twice
    expect((await request.post(`${origin()}/v1/apply`, { headers, data: { plan_id } })).status()).toBe(409);
  } finally {
    await destroyBox(request, name);
  }
});

const FAILING = unique('r1-failing');
test.beforeAll(async ({ request }) => {
  const headers = { Authorization: `Bearer ${token()}` };
  const plan = await request.post(`${origin()}/v1/plans`, {
    headers,
    data: { operation: { op: 'create', spec: { name: FAILING, size: 'S', work_disk_gb: 50, image: null, region: null, from_snapshot: null, labels: { sim_profile: 'failing' } } } },
  });
  expect(plan.status(), await plan.text()).toBe(200);
  const { plan_id } = (await plan.json()) as { plan_id: string };
  expect((await applyPlan(request, origin(), headers, { plan_id })).ok()).toBe(true);
});
test.afterAll(async ({ request }) => {
  await destroyBox(request, FAILING);
  if (savedSettings) await request.put(`${origin()}/v1/settings`, { headers: { Authorization: `Bearer ${token()}` }, data: savedSettings });
});

for (const w of WIDTHS) {
  test(`Needs you names the failing self-test and Boxes can create a box at ${w}px`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: 900 });
    await open(page, '/');
    const needs = page.getByRole('region', { name: 'Needs you' });
    await expect(needs).toContainText(`${FAILING}: the self-test failed`, { timeout: 20_000 });
    await expectNoSidewaysScroll(page);
    await open(page, '/boxes');
    const create = page.getByTestId('create-box-button');
    await expect(create).toBeVisible();
    await create.click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expectNoSidewaysScroll(page);
  });

  test(`a box's Usage tab shows its usage and its cost is an estimate, never a bare dash at ${w}px`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: 900 });
    await open(page, '/boxes/alpha');
    await expect(page.getByLabel('CPU').first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText('Cost this month').locator('xpath=..')).not.toContainText('Fleet not connected');
    await expectNoSidewaysScroll(page);
  });
}
