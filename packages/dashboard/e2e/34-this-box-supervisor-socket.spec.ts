import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

import { expectNoSidewaysScroll, expectTouchTargets } from './fixtures';

// The dashboard on a box reaches its daemon through the dashboard user's OWN socket (ADR 0040, decision 3), not the box
// user's. Here the box socket does not exist at all, and a stand-in daemon listens on the supervisor socket only: the box
// page must still show this box's runs from it, and a session started from Chat must start its run there.
const WIDTHS = [390, 820, 1440] as const;
const PORT = 4175;
const BOX = 'main-box';

let child: ChildProcess;
let daemon: Server;
let base = '';
let token = '';
const seen: { method: string; url: string; body: string }[] = [];

test.beforeAll(async () => {
  const bin = process.env['OZBOX_BIN'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/debug/ozbox');
  const dir = mkdtempSync(join(tmpdir(), 'ozbox-e2e-sup-'));
  const supSock = join(dir, 'supervisor.sock');
  const boxSock = join(dir, 'missing', 'ozboxd.sock');
  const config = join(dir, 'config.toml');
  writeFileSync(config, '# no provider: this is what a box has\n');
  const sample = { ts_ms: Date.now(), cpu_pct: 12.5, mem_total_bytes: 8e9, mem_available_bytes: 4e9, swap_total_bytes: 0, swap_free_bytes: 0, psi_cpu_some_avg10: 0, psi_mem_some_avg10: 0, psi_io_some_avg10: 0, disk_total_bytes: 1e11, disk_free_bytes: 6e10, disk_read_bps: 0, disk_write_bps: 0, net_rx_bps: 0, net_tx_bps: 0, gpus: [], runs: [{ id: 'run-from-supervisor-socket', cpu_pct: 3.5, mem_bytes: 123_000_000, mem_max_bytes: null }] };
  daemon = createServer((req, res) => {
    let body = '';
    req.on('data', (d: Buffer) => (body += d.toString()));
    req.on('end', () => {
      seen.push({ method: req.method ?? '', url: req.url ?? '', body });
      res.setHeader('Content-Type', 'application/json');
      if (req.url?.startsWith('/v1/metrics/now')) res.end(JSON.stringify(sample));
      else if (req.url?.startsWith('/v1/metrics')) res.end(JSON.stringify({ step: '5s', points: [sample] }));
      else if (req.url === '/v1/selftest') {
        // POST runs it and answers the result; GET answers the last one, wrapped
        const result = { ts_ms: Date.now(), ok: true, all_verified: true, checks: [{ name: 'work disk mounted', outcome: 'pass' }] };
        res.end(JSON.stringify(req.method === 'POST' ? result : { result }));
      }
      else if (req.url?.startsWith('/v1/incidents')) res.end(JSON.stringify({ incidents: [] }));
      else if (req.method === 'GET' && req.url === '/v1/runs') res.end(JSON.stringify({ runs: [] }));
      else if (req.method === 'POST' && req.url === '/v1/runs') {
        res.statusCode = 201;
        res.end(JSON.stringify({ id: 'r-chat-1', state: 'running', capability: 'cap-test-1' }));
      } else if (req.url?.startsWith('/v1/runs/r-chat-1/log')) res.end(JSON.stringify({ id: 'r-chat-1', log: { text: '', next: 0, state: 'running', exit_code: null } }));
      else {
        res.statusCode = 404;
        res.end('{"error":"not found"}');
      }
    });
  });
  await new Promise<void>((ok) => daemon.listen(supSock, ok));
  const env = { ...process.env, OZBOX_STATE_DIR: join(dir, 'state'), OZBOX_CONFIG: config, HOME: dir, OZBOX_SECRET_STORE: 'memory', OZBOX_PROFILES: join(dir, 'profiles'), OZBOX_FORCE_BOX: '1', OZBOX_BOX_NAME: BOX, OZBOX_DAEMON_SOCKET: boxSock, OZBOX_DAEMON_SUPERVISOR_SOCKET: supSock };
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

test.afterAll(() => {
  child?.kill();
  daemon?.close();
});

const go = (page: Page, path = '') => page.goto(`${base}${path}#token=${token}`);

for (const width of WIDTHS) {
  test(`this box at ${width}px: its runs come from the supervisor socket, and a Chat session starts its run there`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    // this box's runs, read from the daemon through the supervisor socket (the box socket does not exist)
    const sample = await page.request.get(`${base}/v1/boxes/${BOX}/metrics/now`, { headers: { Authorization: `Bearer ${token}` } });
    expect(sample.status()).toBe(200);
    expect(JSON.stringify(await sample.json())).toContain('run-from-supervisor-socket');
    // and the Health tab shows this box's own self-test from it, not "unreachable"
    await go(page, `/boxes/${BOX}`);
    await page.getByRole('tab', { name: 'Health' }).click();
    await expect(page.getByTestId('selftest')).toContainText('work disk mounted', { timeout: 20_000 });
    await expect(page.getByText("this box's agent is not running")).toHaveCount(0);
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByRole('main'));

    const before = seen.filter((s) => s.method === 'POST' && s.url === '/v1/runs').length;
    await go(page, '/chat');
    await expect(page.getByRole('heading', { name: 'Chat', level: 1 })).toBeVisible();
    await expectNoSidewaysScroll(page);
    if (width < 1024) await expectTouchTargets(page, page.getByTestId('chat-composer'));
    await page.getByTestId('chat-composer').fill(`/new ${BOX} fix the parser ${width}`);
    await page.getByRole('button', { name: 'Send' }).click();
    await expect.poll(() => seen.filter((s) => s.method === 'POST' && s.url === '/v1/runs').length, { timeout: 30_000 }).toBeGreaterThan(before);
    const start = seen.filter((s) => s.method === 'POST' && s.url === '/v1/runs').at(-1);
    // a supervised interactive session: the run is the coding agent, kept open for the next message
    const run = JSON.parse(start?.body ?? '{}') as { argv?: string[]; keep_stdin_open?: boolean };
    expect(run.keep_stdin_open).toBe(true);
    expect(run.argv?.length).toBeGreaterThan(0);
    // end the session so the next width starts from nothing
    const h = { Authorization: `Bearer ${token}` };
    const chat = (await (await page.request.get(`${base}/v1/chat`, { headers: h })).json()) as { bound: { kind: string; id?: string } | null };
    if (chat.bound?.kind === 'task' && chat.bound.id) await page.request.post(`${base}/v1/tasks/${chat.bound.id}/cancel`, { headers: h });
    await page.request.post(`${base}/v1/chat/bind`, { headers: h, data: { task: null } });
    await expectNoSidewaysScroll(page);
  });
}
