/**
 * The desktop coding apps a box can be opened in, and how. One data file: add an entry to add an app.
 *
 * Every box is reached over SSH through its tunnel; `ozbox connect <box> --ssh` prints the config entry
 * (`ozbox-<box>`). An app's own URL scheme is used ONLY where the app's documentation describes one (checked 2026-11-09):
 * VS Code (https://code.visualstudio.com/docs/configure/command-line, "Open a remote resource") and Zed
 * (https://zed.dev/docs/remote-development, the `zed://ssh/` hotlink). The forks of VS Code (Cursor, Antigravity,
 * Windsurf) document no such link, so theirs is marked `unverified` and the sheet says so; JetBrains has no usable link
 * and shows steps. The same builders are in the command line (`ozbox open <box> --in <editor>`).
 */
export interface OpenInApp {
  id: string;
  name: string;
  /** A documented URL scheme that opens the box, or null. Never guessed. */
  uri: ((alias: string, path: string) => string) | null;
  /** True when `uri` is built on the assumption that a fork keeps its parent's handler: nobody documents it. */
  unverified?: boolean;
  /** Ordered steps. `{alias}` is the SSH host entry, `{path}` the work folder. */
  steps: string[];
  /** A command to copy, when the app is terminal based. */
  command?: (alias: string) => string;
  /** Where the steps come from, in words. */
  source: string;
  /** The page the steps follow. */
  doc: string;
}

export const WORK_PATH = '/work/repos';

const remote = (scheme: string) => (alias: string, path: string) => `${scheme}://vscode-remote/ssh-remote+${alias}${path}`;

const REMOTE_SSH_STEPS = [
  'Add the SSH config entry below to ~/.ssh/config (this machine needs the tunnel client installed).',
  'Install the "Remote - SSH" extension if the app does not have it.',
  'Open the command palette and run "Remote-SSH: Connect to Host…", then choose {alias}.',
  'When it connects, use File > Open Folder and choose {path}.',
];

export const OPEN_IN_APPS: OpenInApp[] = [
  {
    id: 'vscode',
    name: 'VS Code',
    uri: remote('vscode'),
    steps: REMOTE_SSH_STEPS,
    source: 'The link follows the "Open a remote resource" section of the VS Code command line documentation; the steps follow its Remote - SSH page.',
    doc: 'https://code.visualstudio.com/docs/remote/ssh',
  },
  {
    id: 'cursor',
    name: 'Cursor',
    uri: remote('cursor'),
    unverified: true,
    steps: REMOTE_SSH_STEPS,
    source: 'A third-party page (Docker) describes Cursor connecting with Remote-SSH: Connect to Host. Cursor documents no link scheme for this.',
    doc: 'https://docs.docker.com/ai/sandboxes/integrations/cursor/',
  },
  {
    id: 'antigravity',
    name: 'Antigravity',
    uri: remote('antigravity'),
    unverified: true,
    steps: REMOTE_SSH_STEPS,
    source: 'NOT VERIFIED: no official page was found for Remote-SSH in Antigravity (the linked page covers a different, Coder-based route). These steps are the VS Code ones; check they work on your version.',
    doc: 'https://coder.com/beta-docs/user-guides/workspace-access/antigravity/',
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    uri: remote('windsurf'),
    unverified: true,
    steps: REMOTE_SSH_STEPS,
    source: 'NOT VERIFIED: Windsurf documents no remote-folder link; it is a VS Code fork, so the same link form is tried and the steps are the VS Code ones.',
    doc: 'https://docs.windsurf.com/',
  },
  {
    id: 'zed',
    name: 'Zed',
    uri: (alias, path) => `zed://ssh/${alias}${path}`,
    steps: ['Add the SSH config entry below to ~/.ssh/config.', 'In Zed, open the command palette and run "projects: Open Remote".', 'Choose {alias}, then open {path}.'],
    source: 'The link is the SSH hotlink described on the Zed remote development page.',
    doc: 'https://zed.dev/docs/remote-development',
  },
  {
    id: 'jetbrains',
    name: 'JetBrains Gateway',
    uri: null,
    steps: ['Add the SSH config entry below to ~/.ssh/config.', 'In JetBrains Gateway choose New Connection, then SSH.', 'Pick the host {alias}, choose your IDE and open {path}.'],
    source: 'JetBrains documents the Gateway link only in older help pages and incompletely, so no link is built.',
    doc: 'https://www.jetbrains.com/help/idea/remote-development-a.html',
  },
  {
    id: 'claude-code',
    name: 'Claude Code (desktop)',
    uri: null,
    steps: ['Add the SSH config entry below to ~/.ssh/config.', 'In a terminal, connect: {command}', 'In the box, start Claude Code in the work folder: cd {path} && claude'],
    command: (alias) => `ssh ${alias}`,
    source: 'The overview documents Claude Code as a terminal tool started with `claude`. It does not describe attaching the desktop app to a remote host over SSH, so this runs it in a terminal on the box.',
    doc: 'https://code.claude.com/docs/en/overview',
  },
  {
    id: 'codex',
    name: 'Codex',
    uri: null,
    steps: ['Add the SSH config entry below to ~/.ssh/config.', 'In a terminal, connect: {command}', 'In the box, start Codex in the work folder: cd {path} && codex'],
    command: (alias) => `ssh ${alias}`,
    source: 'The Codex CLI page documents running `codex` in a terminal. It does not describe SSH, so this runs it in a terminal on the box.',
    doc: 'https://learn.chatgpt.com/docs/codex/cli',
  },
];

export function fillSteps(app: OpenInApp, alias: string): string[] {
  const command = app.command ? app.command(alias) : `ssh ${alias}`;
  return app.steps.map((s) => s.replaceAll('{alias}', alias).replaceAll('{path}', WORK_PATH).replaceAll('{command}', command));
}
