import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

import { expectNoSidewaysScroll, expectTouchTargets } from './fixtures';

// A dashboard on a box with no provider configured shows that box only, from its own daemon, and says plainly that the
// fleet is not connected. This server is started the way a box starts it (`OZBOX_FORCE_BOX=1` stands in for the box's
// own marker files on this computer) with a stand-in for the daemon on a Unix socket. Nothing here is a demo.
const WIDTHS = [390, 820, 1440] as const;
const PORT = 4174;
const BOX = 'main-box';

let child: ChildProcess;
let daemon: Server;
let base = '';
let token = '';

test.beforeAll(async () => {
  const bin = process.env['OZBOX_BIN'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/debug/ozbox');
  const dir = mkdtempSync(join(tmpdir(), 'ozbox-e2e-box-'));
  const sock = join(dir, 'd.sock');
  const config = join(dir, 'config.toml');
  writeFileSync(config, '# no provider: this is what a box has\n');
  const sample = { ts_ms: Date.now(), cpu_pct: 12.5, mem_total_bytes: 8e9, mem_available_bytes: 4e9, swap_total_bytes: 0, swap_free_bytes: 0, psi_cpu_some_avg10: 0, psi_mem_some_avg10: 0, psi_io_some_avg10: 0, disk_total_bytes: 1e11, disk_free_bytes: 6e10, disk_read_bps: 0, disk_write_bps: 0, net_rx_bps: 0, net_tx_bps: 0, gpus: [], runs: [] };
  daemon = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url?.startsWith('/v1/metrics/now')) res.end(JSON.stringify(sample));
    else {
      res.statusCode = 404;
      res.end('{"error":"not found"}');
    }
  });
  await new Promise<void>((ok) => daemon.listen(sock, ok));
  const env = { ...process.env, OZBOX_STATE_DIR: join(dir, 'state'), OZBOX_CONFIG: config, HOME: dir, OZBOX_SECRET_STORE: 'memory', OZBOX_PROFILES: join(dir, 'profiles'), OZBOX_FORCE_BOX: '1', OZBOX_BOX_NAME: BOX, OZBOX_DAEMON_SOCKET: sock };
  child = spawn(bin, ['serve', '--port', String(PORT)], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const url = await new Promise<string>((ok, fail) => {
    let buf = '';
    child.stdout?.on('data', (d: Buffer) => {
      buf += d.toString();
      const m = /(http:\/\/127\.0\.0\.1:\d+\/#token=[0-9a-f]+)/.exec(buf);
      if (m?.[1]) ok(m[1]);
    });
    child.on('exit', (code) => fail(new Error(`ozbox serve exited with ${code}`)));
    setTimeout(() => fail(new Error('ozbox serve did not start')), 20_000);
  });
  const u = new URL(url);
  base = u.origin;
  token = u.hash.replace('#token=', '');
});

// Stopped even when a test failed, and waited for: the next attempt (a retry starts a new worker and runs the setup again) must
// find the port free, or it fails with "address already in use" and hides the real failure.
test.afterAll(async () => {
  if (child && child.exitCode === null && child.signalCode === null) {
    await new Promise<void>((done) => {
      child.once('exit', () => done());
      child.kill();
      setTimeout(() => {
        child.kill('SIGKILL');
        done();
      }, 5_000).unref();
    });
  }
  daemon?.close();
});

const go = (page: Page, path = '') => page.goto(`${base}${path}#token=${token}`);
const headers = () => ({ Authorization: `Bearer ${token}` });

test('the API lists this box only and answers fleet endpoints with a typed error', async ({ request }) => {
  const info = (await (await request.get(`${base}/v1/info`, { headers: headers() })).json()) as { provider: string; fleet: { mode: string; demo: boolean; connected: boolean } };
  expect(info.provider).toBe('thisbox');
  expect(info.fleet).toMatchObject({ mode: 'this_box', demo: false, connected: false });
  const boxes = (await (await request.get(`${base}/v1/boxes`, { headers: headers() })).json()) as { spec: { name: string } }[];
  expect(boxes.map((b) => b.spec.name)).toEqual([BOX]);
  for (const [method, path] of [['POST', '/v1/plans'], ['POST', '/v1/apply'], ['GET', '/v1/cost']] as const) {
    const r = await request.fetch(`${base}${path}`, { method, headers: headers(), data: {} });
    expect(r.status(), path).toBe(409);
    expect(((await r.json()) as { code: string }).code).toBe('fleet_not_connected');
  }
});

for (const width of WIDTHS) {
  test(`this box at ${width}px: its own box, no demo banner, fleet not connected, nothing to change`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await go(page);
    await expect(page.getByRole('heading', { name: 'Fleet', level: 1 })).toBeVisible();
    const notice = page.getByTestId('fleet-not-connected');
    await expect(notice).toBeVisible();
    await expect(notice).toContainText('Fleet not connected');
    await expect(notice).toContainText('only this box');
    await expect(page.getByTestId('demo-banner')).toHaveCount(0);
    // the one box is this one, and no invented names appear
    const cards = page.getByRole('list', { name: 'Boxes' }).getByRole('listitem');
    await expect(cards).toHaveCount(1);
    await expect(cards.first()).toContainText(BOX);
    await expect(page.getByText('alpha')).toHaveCount(0);
    await expectNoSidewaysScroll(page);

    // creating says why it is unavailable instead of opening a form
    await page.getByTestId('create-box-button').click();
    const sheet = page.getByTestId('fleet-not-connected-sheet');
    await expect(sheet).toBeVisible();
    await expect(sheet).toContainText('sees only this box');
    await expect(sheet.getByRole('button', { name: 'Close' }).first()).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(sheet).toHaveCount(0);

    // the boxes page: the row menu offers Open and says the rest is unavailable
    await go(page, '/boxes');
    await expect(page.getByTestId('fleet-not-connected')).toBeVisible();
    await page.getByRole('button', { name: `Actions for ${BOX}` }).first().click();
    await expect(page.getByRole('menuitem', { name: 'Open' })).toBeVisible();
    await expect(page.getByTestId('menu-fleet-not-connected')).toContainText('Not available from this box');
    await expect(page.getByRole('menuitem', { name: 'Destroy' })).toHaveCount(0);
    await page.keyboard.press('Escape');
    if (width < 1024) await expectTouchTargets(page, page.getByTestId('fleet-not-connected'));
    await expectNoSidewaysScroll(page);

    // costs across boxes are not shown as numbers
    await go(page, '/costs/bill');
    await expect(page.getByTestId('fleet-not-connected')).toBeVisible();
    await expect(page.getByTestId('bill-stats')).toHaveCount(0);
  });
}
