import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync } from 'node:fs';
import { createConnection, createServer, type Server } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface SecretsService {
  /** The box's socket: what a program on the box (a hook, an agent) files a change request on. Filed by the box user. */
  box: string;
  /** The supervisor's socket: what a dashboard on a box talks to. */
  supervisor: string;
  /** The import socket: what `ozbox secrets receive` hands a request to. */
  importSocket: string;
  /**
   * The first-time dashboard code a dashboard handed to the service. A dashboard that is told where the supervisor is does not
   * print its setup code (it goes to the owner's computer through the ingress route), so this resolves with the code the
   * dashboard handed over, as seen on the way to the service.
   */
  setupCode(): Promise<string>;
  stop(): void;
}

/**
 * Starts the box's real secrets service (`ozbox secrets serve`) on sockets in a temporary folder, sealed under a throwaway
 * passphrase. Nothing is shared with another spec. The dashboard is pointed at it with the environment this returns.
 */
export async function startSecretsService(): Promise<SecretsService & { env: Record<string, string> }> {
  const bin = process.env['OZBOX_BIN'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../../target/debug/ozbox');
  // a short folder: a socket path is limited to about a hundred characters
  const dir = mkdtempSync('/tmp/ozs-');
  const box = join(dir, 'b', 'b.sock');
  const supervisor = join(dir, 's', 's.sock');
  const importSocket = join(dir, 'i', 'i.sock');
  const child: ChildProcess = spawn(
    bin,
    ['secrets', 'serve', '--box-socket', box, '--supervisor-socket', supervisor, '--import-socket', importSocket, '--passphrase-stdin'],
    { env: { ...process.env, OZBOX_SECRET_FILE: join(dir, 'store.json'), OZBOX_SECRET_SCOPE: 'e2e' }, stdio: ['pipe', 'ignore', 'inherit'] },
  );
  child.stdin?.write('e2e-throwaway-passphrase\n');
  child.stdin?.end();
  // sealing the store runs a deliberately slow key derivation in a debug build, which takes several times longer on a loaded
  // machine: wait for the sockets (the loop stops at once if the service exits) rather than for a guess
  const until = Date.now() + 90_000;
  while (!(existsSync(box) && existsSync(supervisor) && existsSync(importSocket))) {
    if (child.exitCode !== null) throw new Error(`the secrets service exited with ${child.exitCode}`);
    if (Date.now() > until) throw new Error('the secrets service did not start');
    await new Promise((r) => setTimeout(r, 100));
  }
  // The dashboard talks to the service through this relay: it passes every line on unchanged and notes the setup code the
  // dashboard hands over, so a spec can sign in without the code ever being printed.
  mkdirSync(join(dir, 'p'));
  const tap = join(dir, 'p', 'p.sock');
  let seen: (code: string) => void = () => undefined;
  const code = new Promise<string>((ok) => (seen = ok));
  const relay: Server = createServer((down) => {
    let buf = '';
    down.on('error', () => undefined);
    down.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      const line = buf.slice(0, buf.indexOf('\n'));
      buf = '';
      try {
        const req = JSON.parse(line) as { op?: string; value?: string };
        if (req.op === 'setup_code_put' && req.value) seen(req.value);
      } catch {
        // not a request the relay needs to read; the service answers it
      }
      const up = createConnection(supervisor);
      up.on('error', () => down.destroy());
      up.on('connect', () => up.write(`${line}\n`));
      up.pipe(down);
    });
  });
  await new Promise<void>((ok) => relay.listen(tap, ok));
  return {
    box,
    supervisor,
    importSocket,
    setupCode: () => code,
    stop: () => {
      relay.close();
      child.kill();
    },
    env: { OZBOX_SECRET_STORE: 'socket', OZBOX_SECRET_SOCKET: tap, OZBOX_BROKER_SOCKET: tap, OZBOX_SUPERVISOR_SOCKET: tap },
  };
}

/** What a service socket answers: `ok`, or `error` in words; a filed request answers with its id inside `result`. */
export interface SocketReply {
  ok: boolean;
  error?: string;
  /** A filed request answers `{ result: { request: { id, state } } }`. */
  result?: { request?: { id: string; state?: string } };
}

/** One JSON line to a service socket and the one line back, the way the box's own programs do it. */
export function callSocket(path: string, req: unknown): Promise<SocketReply> {
  return new Promise((ok, fail) => {
    const s = createConnection(path);
    let buf = '';
    s.on('connect', () => s.write(`${JSON.stringify(req)}\n`));
    s.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\n')) {
        s.end();
        ok(JSON.parse(buf) as SocketReply);
      }
    });
    s.on('error', fail);
    setTimeout(() => fail(new Error('the service did not answer')), 10_000);
  });
}

/** A unified diff with nothing in it the box would call a key: what a commit hook scanned. */
const CLEAN_DIFF = 'diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hello\n+a public url\n';

/**
 * Files a guard-override request on the BOX socket, the way a commit hook does (crates/ozbox-core/src/approval_subject.rs
 * `Subject::GuardOverride`). `tree` is one hex digit, repeated to a git object id: a different digit is a different request
 * (a different digest), the same one files the same change again. Returns the request's id.
 */
export async function fileGuardRequest(box: string, tree: string, reason = 'a public url'): Promise<string> {
  if (!/^[0-9a-f]$/.test(tree)) throw new Error('tree is one hex digit');
  const reply = await callSocket(box, {
    op: 'areq_file',
    subject: { scope: 'guard-override', hook: 'commit', repo_path_hash: '1'.repeat(64), hook_kind: 'pre-commit', tree_id: tree.repeat(40) },
    scanned_text: CLEAN_DIFF,
    reason,
  });
  const id = reply.result?.request?.id;
  if (!reply.ok || !id) throw new Error(`the box socket refused the request: ${reply.error ?? `no id in the answer: ${JSON.stringify(reply)}`}`);
  return id;
}
