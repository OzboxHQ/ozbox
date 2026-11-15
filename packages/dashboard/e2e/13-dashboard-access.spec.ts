import { expect, test, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Settings, Dashboard access. The tunnel settings are saved beside this server's own temporary configuration, the
// secret store is memory, and the token entered is fake. Nothing here starts a tunnel or reaches an outside service:
// the address check is answered by a stub in the browser.

async function axeClean(page: Page, scope: string) {
  const r = await axeScan(page, scope);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function forgetTunnel(page: Page) {
  await open(page, '/settings/access');
  await expect(page.getByTestId('access-section')).toBeVisible();
  const card = page.getByTestId('access-tunnel-card');
  if (await card.isVisible()) {
    await card.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
    await expect(page.getByTestId('access-providers')).toBeVisible();
  }
}

test.beforeEach(async ({ page }) => {
  await forgetTunnel(page);
});

test('five providers, each with a guide; a Cloudflare tunnel is saved write-only and then forgotten', async ({ page }) => {
  await open(page, '/settings/access');
  await expect(page.getByTestId('access-mode-card')).toContainText('On this computer only');
  for (const id of ['cloudflare', 'tailscale-funnel', 'tailscale-serve', 'caddy', 'ngrok']) {
    await expect(page.getByTestId(`access-setup-${id}`)).toBeVisible();
  }
  await expect(page.getByText('A custom domain needs a paid ngrok plan.')).toBeVisible();
  await page.getByTestId('access-setup-cloudflare').click();
  const sheet = page.getByTestId('access-guide-cloudflare');
  await expect(sheet.getByRole('heading', { name: 'Steps' })).toBeVisible();
  await expect(sheet.getByText('audience tag').first()).toBeVisible();
  await sheet.getByLabel('Public address', { exact: true }).fill('http://ozbox.example.com');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet.getByRole('alert').first()).toBeVisible();
  await sheet.getByLabel('Public address', { exact: true }).fill('https://ozbox.example.com');
  const token = sheet.getByLabel('Tunnel token', { exact: true });
  await expect(token).toHaveAttribute('type', 'password');
  await token.fill('PLAYWRIGHT_SENTINEL_TUNNEL_TOKEN');
  await expect(sheet.getByTestId('access-serve-command')).toContainText('ozbox serve --public-url https://ozbox.example.com --tunnel cloudflare');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet).toBeHidden();

  const card = page.getByTestId('access-tunnel-card');
  await expect(card).toContainText('https://ozbox.example.com');
  await expect(card).toContainText('Token saved');
  await expect(card.getByTestId('access-state')).toHaveText('Not started by this server');

  // The token is never shown again: not on the page, not in any response.
  expect(await page.content()).not.toContain('PLAYWRIGHT_SENTINEL');
  const u = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const bearer = u.hash.replace('#token=', '');
  for (const path of ['/v1/dashboard-access', '/v1/secrets', '/v1/settings', '/v1/activity']) {
    const res = await page.request.get(`${u.origin}${path}`, { headers: { Authorization: `Bearer ${bearer}` } });
    expect(await res.text(), path).not.toContain('PLAYWRIGHT_SENTINEL');
  }
  // and it survives a reload, which is the record, not the form
  await page.reload();
  await expect(page.getByTestId('access-tunnel-card')).toContainText('Token saved');

  // the address check shows what the server answered
  await page.route('**/v1/dashboard-access/check', (route) =>
    route.fulfill({ json: { health: { ok: false, code: 'unreachable', http_status: null, checked_ms: Date.now() } } }),
  );
  await page.getByTestId('access-check').click();
  await expect(page.getByTestId('access-health')).toContainText('nothing answered');

  await page.getByTestId('access-tunnel-card').getByRole('button', { name: 'Remove' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByTestId('access-providers')).toBeVisible();
});

test('a server of your own asks for its fields, shows the Caddyfile, and refuses an option-looking name', async ({ page }) => {
  await open(page, '/settings/access');
  await page.getByTestId('access-setup-caddy').click();
  const sheet = page.getByTestId('access-guide-caddy');
  await sheet.getByLabel('Public address', { exact: true }).fill('https://ozbox.example.com');
  await expect(sheet.getByText('reverse_proxy 127.0.0.1:7878')).toBeVisible();
  await expect(sheet.getByText('ozbox.example.com {')).toBeVisible();
  await sheet.getByLabel('Your server', { exact: true }).fill('-oProxyCommand=x');
  await sheet.getByLabel('Account on that server', { exact: true }).fill('ozbox-tunnel');
  await sheet.getByLabel('Key file for the tunnel', { exact: true }).fill('/work/home/ozbox/ozbox-dashboard/tunnel_ed25519');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet.getByText("Enter your server's name.")).toBeVisible();
  await sheet.getByLabel('Your server', { exact: true }).fill('vps.example.com');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet).toBeHidden();
  await expect(page.getByTestId('access-tunnel-card')).toContainText('Caddy on your own server');
});

test('a Tailscale provider only takes a .ts.net address', async ({ page }) => {
  await open(page, '/settings/access');
  await page.getByTestId('access-setup-tailscale-serve').click();
  const sheet = page.getByTestId('access-guide-tailscale-serve');
  await sheet.getByLabel('Public address', { exact: true }).fill('https://ozbox.example.com');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet.getByText('A Tailscale address ends in .ts.net.')).toBeVisible();
  await sheet.getByLabel('Public address', { exact: true }).fill('https://box.tail1234.ts.net');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet).toBeHidden();
  await expect(page.getByTestId('access-tunnel-card')).toContainText('Tailnet only');
});

for (const width of WIDTHS) {
  test(`at ${width}px: no sideways scroll, reachable controls, no serious accessibility problems`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page, '/settings/access');
    const section = page.getByTestId('access-section');
    await expect(section).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, section);
    await axeClean(page, '[data-testid="access-section"]');

    await page.getByTestId('access-setup-caddy').scrollIntoViewIfNeeded();
    await page.getByTestId('access-setup-caddy').click();
    const sheet = page.getByTestId('access-guide-caddy');
    await expect(sheet).toBeVisible();
    // the primary action is in the fixed footer, inside the window without scrolling
    const save = sheet.getByRole('button', { name: 'Save tunnel' });
    await expect(save).toBeInViewport();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, sheet);
    await axeClean(page, '[data-testid="access-guide-caddy"]');
    await sheet.getByRole('button', { name: 'Cancel' }).click();
    await expect(sheet).toBeHidden();

    // with a tunnel saved, its card has the same properties
    await page.getByTestId('access-setup-cloudflare').click();
    const cf = page.getByTestId('access-guide-cloudflare');
    await cf.getByLabel('Public address', { exact: true }).fill('https://ozbox.example.com');
    await cf.getByRole('button', { name: 'Save tunnel' }).click();
    await expect(page.getByTestId('access-tunnel-card')).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByTestId('access-tunnel-card'));
    await axeClean(page, '[data-testid="access-section"]');
  });
}

test('a saved tunnel is started, restarted and stopped from the page, and stopping warns about your own connection', async ({ page }) => {
  await open(page, '/settings/access');
  await page.getByTestId('access-setup-cloudflare').click();
  const sheet = page.getByTestId('access-guide-cloudflare');
  await sheet.getByLabel('Public address', { exact: true }).fill('https://ozbox.example.com');
  await sheet.getByLabel('Tunnel token', { exact: true }).fill('PLAYWRIGHT_SENTINEL_TUNNEL_TOKEN');
  await sheet.getByRole('button', { name: 'Save tunnel' }).click();
  await expect(sheet).toBeHidden();
  const card = page.getByTestId('access-tunnel-card');
  await expect(card.getByTestId('access-stop')).toBeHidden();

  // The server's own answers are replaced, so no program is started from a browser test: the real routes are covered by
  // the Rust tests; this proves what the page offers and says.
  const u = new URL(process.env['OZBOX_E2E_URL'] ?? '');
  const bearer = u.hash.replace('#token=', '');
  let state: 'running' | 'stopped' = 'stopped';
  const answer = async () => {
    const res = await page.request.get(`${u.origin}/v1/dashboard-access`, { headers: { Authorization: `Bearer ${bearer}` } });
    const body = await res.json();
    body.tunnel.managed = true;
    body.tunnel.live = { provider: 'cloudflare', public_url: 'https://ozbox.example.com', port: 7878, state, code: null, restarts: 0, health: null, updated_ms: Date.now() };
    return body;
  };
  const calls: string[] = [];
  await page.route('**/v1/dashboard-access', async (route) => (route.request().method() === 'GET' ? route.fulfill({ json: await answer() }) : route.fallback()));
  for (const action of ['start', 'stop', 'restart'] as const) {
    await page.route(`**/v1/dashboard-access/tunnel/${action}`, async (route) => {
      calls.push(action);
      state = action === 'stop' ? 'stopped' : 'running';
      await route.fulfill({ json: await answer() });
    });
  }
  await page.reload();
  await expect(page.getByTestId('access-state')).toHaveText('Stopped');
  await page.getByTestId('access-start').click();
  await expect(page.getByTestId('access-state')).toHaveText('Running');
  await expect(page.getByTestId('access-start')).toBeHidden();

  await page.getByTestId('access-restart').click();
  const restart = page.getByRole('alertdialog');
  await expect(restart).toContainText('cut off');
  await restart.getByRole('button', { name: 'Restart' }).click();
  await expect(restart).toBeHidden();

  await page.getByTestId('access-stop').click();
  const stop = page.getByRole('alertdialog');
  await expect(stop).toContainText('you lose your connection');
  await stop.getByRole('button', { name: 'Cancel' }).click();
  expect(calls).toEqual(['start', 'restart']);
  await page.getByTestId('access-stop').click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Stop' }).click();
  await expect(page.getByTestId('access-state')).toHaveText('Stopped');
  expect(calls).toEqual(['start', 'restart', 'stop']);
  await expectNoSidewaysScroll(page);
  // A refresh the page started may still be in flight: let it finish quietly rather than fail the test.
  await page.unrouteAll({ behavior: 'ignoreErrors' });
});
