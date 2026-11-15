import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, type Page } from '@playwright/test';

export interface AuthServer {
  origin: string;
  code: string;
  /** The server's environment (state folder, configuration, home): a spec seeds data with `ozbox <command>` under it before anyone signs in. */
  env: NodeJS.ProcessEnv;
  /** The `ozbox` program this server runs. */
  bin: string;
  /** Ends the server and resolves when it has let go of its port, so the next spec's server can take it. */
  stop(): Promise<void>;
}

/**
 * Starts `ozbox serve --public-behind-tunnel` (fake provider, temp state) for `http://localhost:<port>`: the same
 * sign-in a shared machine has, with the passkey step-up window shortened so a test can let it lapse.
 */
export async function startAuthServer(port: number, boxes: string[], stepupMinutes = 0.05, publicUrl?: string, extraEnv: Record<string, string> = {}, usersToml = '[[users]]\nid = "owner"\nlabel = "Owner"\n', codeElsewhere?: () => Promise<string>): Promise<AuthServer> {
  const bin = process.env['OZBOX_BIN'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/debug/ozbox');
  const dir = mkdtempSync(join(tmpdir(), 'ozbox-auth-e2e-'));
  // With `publicUrl` the address comes from --public-url alone: the settings file does not name one.
  const origin = publicUrl ?? `http://localhost:${port}`;
  const env = { ...process.env, OZBOX_STATE_DIR: join(dir, 'state'), OZBOX_CONFIG: join(dir, 'config.toml'), HOME: dir, OZBOX_SECRET_STORE: 'memory', OZBOX_PROFILES: join(dir, 'profiles'), OZBOX_SIM_SPEED: '0', ...extraEnv };
  writeFileSync(join(dir, 'auth.toml'), `${publicUrl ? '' : `public_origin = "${origin}"\n`}stepup_minutes = ${stepupMinutes}\n\n${usersToml}`);
  for (const b of boxes) execFileSync(bin, ['create', b, '--size', 'M', '--yes'], { env, stdio: 'ignore' });
  // `--code-port 0`: the code hosts' listener takes any free port. Each spec's server starts before the last one has let go of
  // the default (7879), and a fixed port made the next spec's server exit at start.
  const child: ChildProcess = spawn(bin, publicUrl ? ['serve', '--public-url', publicUrl, '--port', String(port), '--code-port', '0'] : ['serve', '--public-behind-tunnel', '--port', String(port), '--code-port', '0'], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const code = await new Promise<string>((ok, fail) => {
    let buf = '';
    child.stdout?.on('data', (d: Buffer) => {
      buf += d.toString();
      const m = /setup code[^:]*: ([A-Z0-9]{5}-[A-Z0-9]{5})/.exec(buf);
      if (m?.[1]) ok(m[1]);
    });
    // a dashboard told where a secrets service is hands its setup code to it and prints none: the caller says where to read it
    void codeElsewhere?.().then(ok, fail);
    child.on('exit', (c) => fail(new Error(`ozbox serve exited with ${c}`)));
    setTimeout(() => fail(new Error('ozbox serve did not print a setup code')), 20_000);
  }).catch((e: unknown) => {
    // a server that never gave its code must not keep its port for the retry
    child.kill();
    throw e;
  });
  const stop = () =>
    new Promise<void>((done) => {
      if (child.exitCode !== null || child.signalCode !== null) return done();
      child.once('exit', () => done());
      child.kill();
      setTimeout(() => {
        child.kill('SIGKILL');
        done();
      }, 5_000).unref();
    });
  return { origin, code, env, bin, stop };
}

/** A software authenticator in the browser (Chromium's WebAuthn virtual authenticator): resident keys, user verification on. */
export async function addVirtualAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
}

/** The first sign-in: the setup code, then a passkey is made. Ends with the dashboard open. */
export async function firstSignIn(page: Page, server: Pick<AuthServer, 'origin' | 'code'> & Partial<AuthServer>, user = 'owner'): Promise<void> {
  await page.goto(server.origin + '/');
  await page.getByLabel('Setup code').fill(server.code);
  await page.getByLabel('Your id on the allow-list').fill(user);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Set up your second factor' })).toBeVisible();
  await page.getByTestId('enroll-passkey').click();
  await expect(page.getByRole('button', { name: 'Session menu' })).toBeVisible();
}
