import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

import { expectNoSidewaysScroll, expectTouchTargets } from './fixtures';

// Coding agents on a box reach the Oz Box tools through a socket of their own (ADR 0043). The switch for it is on the box's
// page: on by default, off needs nothing, and the socket answers two paths and none of the dashboard's. This server is
// started the way a box starts it (OZBOX_FORCE_BOX stands in for the box's markers) with a stand-in daemon, and a socket
// path and user named for the debug build. The kernel's word about the caller (SO_PEERCRED) exists on Linux only, so what
// the socket does for a real caller is proven by the Rust tests and on a box; here it is the page and the two paths.
const WIDTHS = [390, 820, 1440] as const;
const PORT = 4176;
const BOX = 'main-box';

let child: ChildProcess;
let daemon: Server;
let base = '';
let token = '';
let sock = '';

test.beforeAll(async () => {
  const bin = process.env['OZBOX_BIN'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/debug/ozbox');
  const dir = mkdtempSync(join(tmpdir(), 'ozbox-e2e-agentmcp-'));
  const daemonSock = join(dir, 'd.sock');
  sock = join(dir, 'mcp.sock');
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
  await new Promise<void>((ok) => daemon.listen(daemonSock, ok));
  const env = {
    ...process.env,
    OZBOX_STATE_DIR: join(dir, 'state'),
    OZBOX_CONFIG: config,
    HOME: dir,
    OZBOX_SECRET_STORE: 'memory',
    OZBOX_PROFILES: join(dir, 'profiles'),
    OZBOX_FORCE_BOX: '1',
    OZBOX_BOX_NAME: BOX,
    OZBOX_DAEMON_SOCKET: daemonSock,
    OZBOX_AGENT_MCP_SOCKET: sock,
    OZBOX_AGENT_MCP_UID: String(process.getuid?.() ?? 0),
  };
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

// Stopped and waited for, so a retry (or the next spec) finds the port free; a server that ignores the polite signal is killed after 5 s.
function stopChild(c: ChildProcess | undefined): Promise<void> {
  return new Promise((done) => {
    if (!c || c.exitCode !== null || c.signalCode !== null) return done();
    const timer = setTimeout(() => c.kill('SIGKILL'), 5_000);
    c.once('exit', () => {
      clearTimeout(timer);
      done();
    });
    c.kill();
  });
}

test.afterAll(async () => {
  await stopChild(child);
  daemon?.close();
});

const headers = () => ({ Authorization: `Bearer ${token}` });
const go = (page: Page, path: string) => page.goto(`${base}${path}#token=${token}`);

/** One request to the agent socket, as a program on the box would make it. */
function onSocket(method: string, path: string): Promise<{ status: number; body: string }> {
  return new Promise((ok, fail) => {
    const r = httpRequest({ socketPath: sock, method, path, agent: false }, (res) => {
      let body = '';
      res.on('data', (d: Buffer) => (body += d.toString()));
      res.on('end', () => ok({ status: res.statusCode ?? 0, body }));
    });
    r.on('error', fail);
    r.end(method === 'POST' ? '{}' : undefined);
  });
}

test('the setting is on by default, names the engines, and turning it off and on is kept', async ({ request }) => {
  await expect.poll(async () => ((await (await request.get(`${base}/v1/agent-mcp`, { headers: headers() })).json()) as { available: boolean }).available, { timeout: 15_000 }).toBe(true);
  const s = (await (await request.get(`${base}/v1/agent-mcp`, { headers: headers() })).json()) as { enabled: boolean; engines: { id: string }[] };
  expect(s.enabled).toBe(true);
  expect(s.engines.map((e) => e.id)).toEqual(['claude-code', 'codex', 'gemini-cli', 'opencode']);
  const bad = await request.fetch(`${base}/v1/agent-mcp`, { method: 'PUT', headers: headers(), data: { enabled: 'yes' } });
  expect(bad.status()).toBe(400);
  const off = await request.fetch(`${base}/v1/agent-mcp`, { method: 'PUT', headers: headers(), data: { enabled: false } });
  expect(off.status()).toBe(200);
  expect(((await off.json()) as { enabled: boolean }).enabled).toBe(false);
  const on = await request.fetch(`${base}/v1/agent-mcp`, { method: 'PUT', headers: headers(), data: { enabled: true } });
  expect(((await on.json()) as { enabled: boolean }).enabled).toBe(true);
});

test('the agent socket answers two paths and none of the dashboard API', async () => {
  for (const path of ['/v1/info', '/v1/boxes', '/v1/agent-mcp', '/v1/permissions', '/']) {
    const r = await onSocket('GET', path);
    expect(r.status, path).toBe(404);
    expect(r.body).not.toContain(BOX);
  }
  expect((await onSocket('GET', '/mcp')).status).toBe(405);
  // a caller the kernel cannot name (or that is not the box user) is refused, never given a token
  const e = await onSocket('POST', '/v1/enrol');
  expect([200, 403]).toContain(e.status);
});

for (const width of WIDTHS) {
  test(`the box page's switch at ${width}px: on, then off, then on again`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await go(page, `/boxes/${BOX}`);
    const card = page.getByTestId('agent-mcp-card');
    await expect(card).toBeVisible();
    await expect(card).toContainText('Coding agents on this box can use Oz Box tools');
    await expect(page.getByTestId('agent-mcp-state')).toHaveText('On');
    await expect(card.getByTestId('agent-mcp-toggle')).toBeInViewport({ ratio: 0 });
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, card);

    await card.getByTestId('agent-mcp-toggle').click();
    await expect(page.getByTestId('agent-mcp-state')).toHaveText('Off');
    await expect(card).toContainText('agents on this box see no Oz Box tools');
    await page.reload();
    await expect(page.getByTestId('agent-mcp-state')).toHaveText('Off');

    await page.getByTestId('agent-mcp-toggle').click();
    await expect(page.getByTestId('agent-mcp-state')).toHaveText('On');
    await expectNoSidewaysScroll(page);
  });
}

// Standing permission for coding agents (ADR 0043): off by default and said so, turned on for a short time with the
// minutes left shown, and ended by one click. The switch is the same gate as the box page's own (a fresh step-up on a box that
// has a sign-in; this stand-in box has none, like the switch above).
for (const width of WIDTHS) {
  test(`standing permission at ${width}px: off by default, on with the minutes left, then off`, async ({ page, request }) => {
    await request.fetch(`${base}/v1/agent-mcp`, { method: 'PUT', headers: headers(), data: { enabled: true } });
    await page.setViewportSize({ width, height: 900 });
    await go(page, `/boxes/${BOX}`);
    const card = page.getByTestId('agent-mcp-standing');
    await expect(card).toBeVisible();
    await expect(card).toContainText('Agents ask for every risky step');
    await expect(card).toContainText('any program the box user starts');
    const toggle = card.getByTestId('agent-mcp-standing-toggle');
    await expect(toggle).toHaveText('Allow for 30 minutes');
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, card);

    await toggle.click();
    await expect(card).toContainText(/On for (29|30) more minutes/);
    await expect(toggle).toHaveText('End now');
    await page.reload();
    await expect(page.getByTestId('agent-mcp-standing')).toContainText(/On for (29|30) more minutes/);

    await page.getByTestId('agent-mcp-standing-toggle').click();
    await expect(page.getByTestId('agent-mcp-standing')).toContainText('Agents ask for every risky step');
    await expect(page.getByTestId('agent-mcp-standing-toggle')).toHaveText('Allow for 30 minutes');
    await expectNoSidewaysScroll(page);
  });
}
