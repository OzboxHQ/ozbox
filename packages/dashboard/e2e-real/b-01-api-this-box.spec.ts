import { expect, test } from '@playwright/test';

import { startRealThisBox, type RealStack } from './real-stack';
import { bearer } from './support';

// Tier B: a REAL ozboxd and a REAL `ozbox serve`, started as a box starts them. API level: what the server says it is, and
// that nothing it answers on a box is marked as simulated.
let s: RealStack;
test.beforeAll(async () => {
  s = await startRealThisBox({ port: 4180 });
});
test.afterAll(async () => {
  await s?.stop();
});

const get = async (request: import('@playwright/test').APIRequestContext, path: string) => request.get(`${s.origin}${path}`, { headers: bearer(s) });

test('the server says it is this box, live, with no demo and no fleet', async ({ request }) => {
  const i = (await (await get(request, '/v1/info')).json()) as { provider: string; metrics: string; fleet: { mode: string; demo: boolean; connected: boolean } };
  expect(i.provider).toBe('thisbox');
  expect(i.metrics).toBe('live');
  expect(i.fleet).toMatchObject({ mode: 'this_box', demo: false, connected: false });
  const boxes = (await (await get(request, '/v1/boxes')).json()) as { spec: { name: string } }[];
  expect(boxes.map((b) => b.spec.name)).toEqual([s.box]);
});

test('every fleet-only endpoint answers a typed "fleet not connected", never a made-up success', async ({ request }) => {
  for (const [method, path] of [
    ['POST', '/v1/plans'],
    ['POST', '/v1/apply'],
    ['GET', '/v1/cost'],
    ['GET', '/v1/cost/bill'],
  ] as const) {
    const r = await request.fetch(`${s.origin}${path}`, { method, headers: bearer(s), data: {} });
    expect(r.status(), `${method} ${path}`).toBe(409);
    expect(((await r.json()) as { code: string }).code, path).toBe('fleet_not_connected');
  }
});

test('the box answers from its real daemon: live metrics', async ({ request }) => {
  // The daemon samples the box from /proc and cgroups, which a Mac does not have: there it answers a typed 502 (the GET sweep
  // below still holds it to that). Live metrics are proven on Linux, which is where a box runs.
  test.skip(process.platform !== 'linux', 'ozboxd reads /proc and cgroups, so live metrics exist only on Linux');
  const m = await get(request, `/v1/boxes/${s.box}/metrics/now`);
  expect(m.status()).toBe(200);
  const body = (await m.json()) as Record<string, unknown>;
  expect(JSON.stringify(body)).not.toMatch(/simulated/i);
  // the answer is { source, sample: { ... } }; the totals are in the sample
  const sample = (body['sample'] ?? {}) as Record<string, unknown>;
  expect(typeof sample['mem_total_bytes']).toBe('number');
});

// Every GET of the API, on a box: a 2xx body never claims to be simulated, and a refusal says why in a typed error
// (`error` text and `code`), so a page can say plainly what is not connected, not built or not permitted.
const GETS = [
  '/v1/info',
  '/v1/boxes',
  `/v1/boxes/main-box`,
  '/v1/boxes/main-box/metrics/now',
  '/v1/boxes/main-box/selftest',
  '/v1/boxes/main-box/incidents',
  '/v1/boxes/main-box/files/roots',
  '/v1/boxes/main-box/tools',
  '/v1/runs',
  '/v1/tasks',
  '/v1/schedules',
  '/v1/triggers',
  '/v1/approvals',
  '/v1/approvals/requests',
  '/v1/permissions',
  '/v1/memory',
  '/v1/skills',
  '/v1/backups',
  '/v1/backups/settings',
  '/v1/models',
  '/v1/apps',
  '/v1/alerts',
  '/v1/activity',
  '/v1/browser/sessions',
  '/v1/orchestrations',
  '/v1/usage',
  '/v1/suggestions',
  '/v1/settings',
  '/v1/spend-caps',
  '/v1/catalog',
  '/v1/people',
];

for (const path of GETS) {
  test(`GET ${path} is honest on a box`, async ({ request }) => {
    const r = await get(request, path);
    const text = await r.text();
    expect(r.status(), `${path} answered ${r.status()}: ${text.slice(0, 200)}`).toBeLessThan(600);
    expect(text, `${path} says it is simulated`).not.toMatch(/"(source|metrics)"\s*:\s*"simulated"|"simulated"\s*:\s*true|sim_restic|ozbox-demo-/);
    if (r.status() >= 400) {
      const e = JSON.parse(text) as { error?: unknown; code?: unknown };
      expect(typeof e.error, `${path}: a refusal with no words (${text.slice(0, 120)})`).toBe('string');
      expect(typeof e.code, `${path}: a refusal with no code`).toBe('string');
      expect(String(e.error).length, `${path}: an empty refusal`).toBeGreaterThan(5);
    }
  });
}
