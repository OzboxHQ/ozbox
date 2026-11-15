import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// OZBOX_E2E_PORT lets two runs share a machine (another worktree's suite may hold 4173)
const PORT = Number(process.env['OZBOX_E2E_PORT'] ?? 4173);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error(`OZBOX_E2E_PORT must be a port number, got ${process.env['OZBOX_E2E_PORT']}`);

/**
 * Starts `ozbox serve` (fake provider, temp state) and seeds four boxes. The access URL goes in OZBOX_E2E_URL.
 * OZBOX_DEMO_TELEGRAM=1 gives this simulated server a local stand-in for Telegram, so pairing can be tried without a bot.
 */
export default async function globalSetup(): Promise<void> {
  const bin = process.env['OZBOX_BIN'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/debug/ozbox');
  const dir = mkdtempSync(join(tmpdir(), 'ozbox-e2e-'));
  const env = { ...process.env, OZBOX_STATE_DIR: join(dir, 'state'), OZBOX_CONFIG: join(dir, 'config.toml'), HOME: dir, OZBOX_SECRET_STORE: 'memory', OZBOX_PROFILES: join(dir, 'profiles'), OZBOX_SIM_SPEED: '0', OZBOX_DEMO_TELEGRAM: '1' };
  const run = (...args: string[]) => execFileSync(bin, args, { env, stdio: 'ignore' });
  // The labels steer the simulated provider: light and idle boxes get suggestions, a failing one fails its self-test.
  run('create', 'alpha', '--size', 'M', '--label', 'project=web', '--label', 'sim_profile=light', '--yes');
  run('create', 'bravo', '--size', 'S', '--label', 'project=web', '--label', 'sim_profile=failing', '--yes');
  run('create', 'charlie', '--size', 'L', '--label', 'sim_profile=idle', '--yes');
  run('create', 'delta', '--size', 'S', '--yes');
  run('pause', 'delta', '--yes');

  const child = spawn(bin, ['serve', '--port', String(PORT)], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const url = await new Promise<string>((ok, fail) => {
    let buf = '';
    child.stdout.on('data', (d: Buffer) => {
      buf += d.toString();
      const m = /(http:\/\/127\.0\.0\.1:\d+\/#token=[0-9a-f]+)/.exec(buf);
      if (m?.[1]) ok(m[1]);
    });
    child.on('exit', (code) => fail(new Error(`ozbox serve exited with ${code}`)));
    setTimeout(() => fail(new Error('ozbox serve did not start')), 20_000);
  });
  process.env['OZBOX_E2E_URL'] = url;
  writeFileSync(join(dir, 'pid'), String(child.pid));
  process.env['OZBOX_E2E_PIDFILE'] = join(dir, 'pid');
}
