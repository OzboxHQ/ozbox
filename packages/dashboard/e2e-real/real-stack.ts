import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The real-server harness (G7, tiers B and C): a REAL `ozboxd` and a REAL `ozbox serve` started the way a box starts them,
 * with nothing standing in for either. There is no `page.route` here, no stand-in daemon and no fake provider: a spec that
 * passes against this has talked to the program that ships. The only things a spec may fake are the ones nobody can run
 * for real in a test: the tunnel's health probe (it asks Cloudflare) and Telegram's API.
 *
 * `OZBOX_FORCE_BOX=1` stands in for the box's own marker files (a laptop has none); a DEBUG build also honours
 * `OZBOX_DAEMON_SOCKET`, which is how the dashboard's local agent finds the daemon this file started.
 */
export interface RealStack {
  /** `http://127.0.0.1:<port>` */
  origin: string;
  /** The access-link token; empty when the server is signed-in only (`signIn`). */
  token: string;
  /** The first-sign-in setup code, with `signIn`. */
  code: string;
  /** The daemon's `/work`: what the Files page and the terminal act on. */
  work: string;
  dir: string;
  box: string;
  daemon: ChildProcess;
  serve: ChildProcess;
  stop(): Promise<void>;
}

const here = dirname(fileURLToPath(import.meta.url));
export const OZBOX_BIN = (): string => process.env['OZBOX_BIN'] ?? resolve(here, '../../../target/debug/ozbox');
export const OZBOXD_BIN = (): string => process.env['OZBOXD_BIN'] ?? join(dirname(OZBOX_BIN()), 'ozboxd');

function kill(child: ChildProcess): Promise<void> {
  return new Promise<void>((done) => {
    if (child.exitCode !== null || child.signalCode !== null) return done();
    child.once('exit', () => done());
    child.kill();
    setTimeout(() => {
      child.kill('SIGKILL');
      done();
    }, 5_000).unref();
  });
}

async function until(what: string, ok: () => boolean | Promise<boolean>, ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await ok()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${what} did not come up in ${ms} ms`);
}

export interface StackOptions {
  port: number;
  /** The server's own configuration text. The default is a box's: no provider. */
  config?: string;
  /** Skip the daemon (a box whose daemon is down). */
  noDaemon?: boolean;
  /** Serve the way a shared box does (`--public-behind-tunnel`): a passkey sign-in, no access link. */
  signIn?: boolean;
  /** The id of the one person on the sign-in list (`signIn`); default `owner`. A spec that is about who is named uses another. */
  person?: string;
  /** Give the daemon a dashboard socket of its own (a debug-build hook) and point the server at it, so a skill push, which only that socket carries, reaches the real daemon. */
  dashboardSocket?: boolean;
  extraEnv?: Record<string, string>;
  /** Boxes made through the CLI before the server starts (only meaningful with the demo provider in `config`). */
  seedBoxes?: string[];
}

export async function startRealThisBox(opts: StackOptions): Promise<RealStack> {
  for (const b of [OZBOX_BIN(), ...(opts.noDaemon ? [] : [OZBOXD_BIN()])]) {
    if (!existsSync(b)) throw new Error(`${b} is not built: cargo build -p ozbox-cli -p ozboxd (debug), then set OZBOX_BIN / OZBOXD_BIN`);
  }
  // a Unix socket path must fit in 104 bytes on macOS: keep the folder short
  const dir = mkdtempSync(join(tmpdir(), 'ozg7-'));
  const work = join(dir, 'work');
  const sock = join(dir, 'd.sock');
  const dashSock = join(dir, 'dash.sock');
  const box = 'main-box';
  mkdirSync(join(work, 'projects'), { recursive: true });
  writeFileSync(join(work, 'projects', 'hello-g7.txt'), 'written on the box before the dashboard looked\n');

  const daemonToml = [
    `box_name = "${box}"`,
    `socket_path = "${sock}"`,
    `socket_mode = "0660"`,
    `work_dir = "${work}"`,
    `repos_root = "${join(work, 'repos')}"`,
    `state_dir = "${join(work, '.ozbox')}"`,
    `release_file = "${join(dir, 'release')}"`,
    `gpu = false`,
    `sample_interval_s = 1`,
    `[selftest]`,
    `require_mount = false`,
    `[terminal]`,
    `tmux = false`,
    `command = ["/bin/sh"]`,
    '',
  ].join('\n');
  const daemonCfg = join(dir, 'ozboxd.toml');
  writeFileSync(daemonCfg, daemonToml);

  let daemon: ChildProcess | undefined;
  if (!opts.noDaemon) {
    daemon = spawn(OZBOXD_BIN(), ['--config', daemonCfg], { env: { ...process.env, HOME: dir, ...(opts.dashboardSocket ? { OZBOXD_TEST_DASHBOARD_SOCKET: dashSock } : {}) }, stdio: ['ignore', 'ignore', 'inherit'] });
    await until('ozboxd socket', () => existsSync(sock) && (!opts.dashboardSocket || existsSync(dashSock)));
  }

  const config = join(dir, 'config.toml');
  writeFileSync(config, opts.config ?? '# no provider: this is what a box has\n');
  const env = {
    ...process.env,
    OZBOX_STATE_DIR: join(dir, 'state'),
    OZBOX_CONFIG: config,
    HOME: dir,
    OZBOX_SECRET_STORE: 'memory',
    OZBOX_PROFILES: join(dir, 'profiles'),
    OZBOX_FORCE_BOX: '1',
    OZBOX_BOX_NAME: box,
    OZBOX_DAEMON_SOCKET: sock,
    ...(opts.dashboardSocket ? { OZBOX_DAEMON_SUPERVISOR_SOCKET: dashSock } : {}),
    ...opts.extraEnv,
  };
  for (const b of opts.seedBoxes ?? []) execFileSync(OZBOX_BIN(), ['create', b, '--size', 'M', '--yes'], { env, stdio: 'ignore' });
  const origin = opts.signIn ? `http://localhost:${opts.port}` : '';
  if (opts.signIn) writeFileSync(join(dir, 'auth.toml'), `public_origin = "${origin}"\nstepup_minutes = 5\n\n[[users]]\nid = "${opts.person ?? 'owner'}"\nlabel = "Owner"\n`);
  const args = opts.signIn ? ['serve', '--public-behind-tunnel', '--port', String(opts.port), '--code-port', '0'] : ['serve', '--port', String(opts.port), '--code-port', '0'];
  const serve = spawn(OZBOX_BIN(), args, { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const url = await new Promise<string>((ok, fail) => {
    let buf = '';
    serve.stdout?.on('data', (d: Buffer) => {
      buf += d.toString();
      const m = opts.signIn ? /setup code[^:]*: ([A-Z0-9]{5}-[A-Z0-9]{5})/.exec(buf) : /(http:\/\/127\.0\.0\.1:\d+\/#token=[0-9a-f]+)/.exec(buf);
      if (m?.[1]) ok(m[1]);
    });
    serve.on('exit', (code) => fail(new Error(`ozbox serve exited with ${code}`)));
    setTimeout(() => fail(new Error('ozbox serve did not start')), 20_000);
  }).catch(async (e: unknown) => {
    await kill(serve);
    if (daemon) await kill(daemon);
    throw e;
  });
  const u = opts.signIn ? null : new URL(url);
  return {
    origin: u ? u.origin : origin,
    token: u ? u.hash.replace('#token=', '') : '',
    code: opts.signIn ? url : '',
    work,
    dir,
    box,
    daemon: daemon as ChildProcess,
    serve,
    stop: async () => {
      await kill(serve);
      if (daemon) await kill(daemon);
    },
  };
}
