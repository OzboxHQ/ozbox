import { expect, test } from '@playwright/test';

// Specs share one server, in file order. Spec 00 saves a cap on running boxes to test that settings live on the server; every
// spec after it leaves boxes running, so a cap that outlived spec 00 filled up and refused later creates (specs 12 and 29 saw a
// refused plan instead of their own). This runs straight after 00 and fails if the cap is still set, so the leak is caught at its
// source and not 11 files later.
test('a spec that sets the fleet cap puts it back before the next one runs', async ({ request }) => {
  const url = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const r = await request.get(`${url.origin}/v1/settings`, { headers: { Authorization: `Bearer ${url.hash.replace('#token=', '')}` } });
  const { settings } = (await r.json()) as { settings: { budget: { max_running_boxes?: number | null } } };
  expect(settings.budget.max_running_boxes ?? null, 'the shared server still carries a cap an earlier spec set').toBeNull();
});
