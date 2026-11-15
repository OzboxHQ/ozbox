import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';

// `ozbox serve --public-url` behind a stand-in for a tunnel: a local HTTPS proxy answers for a fake host name and
// forwards to the loopback server with the Host and Origin headers untouched. The browser maps the fake name to this
// computer and accepts the proxy's throwaway certificate. This exercises what a real tunnel would: the passkey's
// relying-party id and origin, the exact Host and Origin check, and the `__Host-` session cookie over https.
// Nothing leaves this computer.

const HOST = 'ozbox.example.test';
const PROXY_PORT = 8443;
const UPSTREAM_PORT = 4177;
const ORIGIN = `https://${HOST}:${PROXY_PORT}`;
const here = dirname(fileURLToPath(import.meta.url));
const bin = process.env['OZBOX_BIN'] ?? resolve(here, '../../../target/debug/ozbox');

test.use({ ignoreHTTPSErrors: true, launchOptions: { args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1`] } });
test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let proxy: ChildProcess;
let page: Page;

/** A request straight to the proxy, naming the host and origin the test wants (a browser will not forge those). */
function raw(method: string, path: string, headers: Record<string, string>): Promise<number> {
  return new Promise((ok, fail) => {
    const req = https.request({ host: '127.0.0.1', port: PROXY_PORT, method, path, rejectUnauthorized: false, headers: { Host: `${HOST}:${PROXY_PORT}`, ...headers } }, (res) => {
      res.resume();
      ok(res.statusCode ?? 0);
    });
    req.on('error', fail);
    req.end(method === 'POST' ? '{}' : undefined);
  });
}

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(UPSTREAM_PORT, ['alpha'], 0.05, ORIGIN);
  proxy = spawn('node', [resolve(here, '../../../scripts/local-public-proxy.mjs'), '--listen', String(PROXY_PORT), '--upstream', String(UPSTREAM_PORT), '--host', HOST], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise<void>((ok, fail) => {
    proxy.stdout?.on('data', (d: Buffer) => d.toString().includes('ready') && ok());
    proxy.on('exit', (c) => fail(new Error(`the local proxy exited with ${c}`)));
    setTimeout(() => fail(new Error('the local proxy did not start')), 15_000);
  });
  page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  await addVirtualAuthenticator(page);
});

test.afterAll(() => {
  server?.stop();
  proxy?.kill();
});

test('the fake public address shows the sign-in page, and only that address is answered', async () => {
  await page.goto(ORIGIN + '/');
  await expect(page.getByRole('heading', { name: 'Sign in to Oz Box' })).toBeVisible();
  // the dashboard's data is refused without a session
  expect(await raw('GET', '/v1/boxes', {})).toBe(401);
  // a request that names another site as its origin is refused before anything else
  expect(await raw('POST', '/auth/passkey/login/options', { Origin: 'https://evil.example', 'Content-Type': 'application/json' })).toBe(403);
  // the same address on the wrong host name is refused: the Host must be the public address exactly
  expect(await raw('GET', '/v1/boxes', { Host: 'evil.example' })).toBe(403);
  // and so is the loopback address itself, which is only ever the tunnel's way in
  const direct = await page.request.get(`http://127.0.0.1:${UPSTREAM_PORT}/v1/boxes`);
  expect(direct.status()).toBe(403);
});

test('a passkey made at the public address signs in, and the session cookie is locked to it', async () => {
  await firstSignIn(page, server);
  const cookies = await page.context().cookies(ORIGIN);
  const session = cookies.find((c) => c.name === '__Host-ozbox_session');
  expect(session, 'the session cookie').toBeDefined();
  expect(session?.secure).toBe(true);
  expect(session?.httpOnly).toBe(true);
  expect(session?.path).toBe('/');
  expect(['Strict', 'Lax']).toContain(session?.sameSite);
  expect(session?.domain).toBe(HOST);
  // the signed-in dashboard answers its own address (the first sign-in ended with its session menu on screen)
  await expect(page.getByRole('button', { name: 'Session menu' })).toBeVisible();
  // a change that names another origin is refused even with the cookie
  const cookie = `__Host-ozbox_session=${session?.value ?? ''}`;
  expect(await raw('POST', '/v1/plans', { Cookie: cookie, Origin: 'https://evil.example', 'Content-Type': 'application/json' })).toBe(403);
});

// --- Refusals at start-up: no browser, no server ---

function serveWith(authToml: string | null, args: string[]): { code: number; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), 'ozbox-public-refuse-'));
  if (authToml !== null) writeFileSync(join(dir, 'auth.toml'), authToml);
  const env = { ...process.env, OZBOX_CONFIG: join(dir, 'config.toml'), HOME: dir, OZBOX_SECRET_STORE: 'memory', OZBOX_STATE_DIR: join(dir, 'state') };
  try {
    execFileSync(bin, ['serve', '--port', '0', ...args], { env, stdio: ['ignore', 'ignore', 'pipe'], timeout: 15_000 });
    return { code: 0, stderr: '' };
  } catch (e) {
    const err = e as { status?: number; stderr?: Buffer };
    return { code: err.status ?? -1, stderr: err.stderr?.toString() ?? '' };
  }
}

const PEOPLE = '[[users]]\nid = "owner"\n';

test('start-up is refused without sign-in settings, over plain http, and with a half-set Cloudflare Access', () => {
  const noFile = serveWith(null, ['--public-url', 'https://ozbox.example.com']);
  expect(noFile.code).not.toBe(0);
  expect(noFile.stderr).toContain('auth.toml');

  const http = serveWith(PEOPLE, ['--public-url', 'http://ozbox.example.com']);
  expect(http.code).not.toBe(0);
  expect(http.stderr).toContain('https');

  const ip = serveWith(PEOPLE, ['--public-url', 'https://203.0.113.7']);
  expect(ip.code).not.toBe(0);

  const half = serveWith(`${PEOPLE}\n[access]\nteam_domain = "team.cloudflareaccess.com"\n`, ['--public-url', 'https://ozbox.example.com']);
  expect(half.code).not.toBe(0);
  expect(half.stderr).toContain('Cloudflare Access');
});
