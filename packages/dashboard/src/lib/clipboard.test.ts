import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import { writeClipboard } from './clipboard';

const SRC = join(__dirname, '..');
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.tsx?$/.test(p) && !/\.test\.tsx?$/.test(p) ? [p] : [];
  });
}
const code = (f: string) => readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

describe('writing the clipboard', () => {
  it('writes on a gesture', async () => {
    const writeText = vi.fn(async () => undefined);
    expect(await writeClipboard('x', { writeText }, { isActive: true })).toBe('copied');
    expect(writeText).toHaveBeenCalledWith('x');
  });

  it('never writes without a gesture, even where the browser would allow it', async () => {
    const writeText = vi.fn(async () => undefined);
    expect(await writeClipboard('s3cr3t-sentinel', { writeText }, { isActive: false })).toBe('no_gesture');
    expect(writeText).not.toHaveBeenCalled();
  });

  it('a browser that cannot say leaves it to its own rule; a refusal or no clipboard is a failure, never a throw', async () => {
    expect(await writeClipboard('x', { writeText: async () => undefined }, undefined)).toBe('copied');
    expect(await writeClipboard('x', { writeText: () => Promise.reject(new DOMException('no', 'NotAllowedError')) }, { isActive: true })).toBe('failed');
    expect(await writeClipboard('x', {}, { isActive: true })).toBe('failed');
    expect(await writeClipboard('x', null, { isActive: true })).toBe('failed');
  });
});

describe('sentinel: nothing reaches the clipboard by itself, and no secret silently', () => {
  it('only the clipboard module writes the clipboard, and only the terminal Paste button reads it', () => {
    const writers: string[] = [];
    const readers: string[] = [];
    for (const f of files(SRC)) {
      const c = code(f);
      const rel = relative(SRC, f);
      if (/\.writeText\s*\(|execCommand\s*\(|clipboard\.write\s*\(/.test(c) && rel !== join('lib', 'clipboard.ts')) writers.push(rel);
      if (/\breadText\b|clipboard\.read\s*\(|readClipboardText\(/.test(c)) readers.push(rel);
    }
    expect(writers).toEqual([]);
    // terminal-paste.ts holds the read; the terminal view is its only caller
    expect(readers.sort()).toEqual([join('components', 'terminal', 'terminal-view.tsx'), join('lib', 'terminal-paste.ts')].sort());
    // the terminal reads only inside its Paste button's handler
    const view = code(join(SRC, 'components', 'terminal', 'terminal-view.tsx'));
    expect(view.match(/readClipboardText\(/g)?.length).toBe(1);
    expect(view).toMatch(/const paste = async \(\) => \{\s*const r = await readClipboardText\(navigator\.clipboard\)/);
  });

  it('every copy of a secret is marked as one, so the person is told it is on their clipboard', () => {
    const secrets: [string, string][] = [
      [join('pages', 'triggers-page.tsx'), 'trigger.secret'],
      [join('pages', 'settings-secret-approvals.tsx'), 'minted.code'],
      [join('pages', 'orchestrations-page.tsx'), 'snippet'],
      [join('components', 'files', 'files-sheets.tsx'), 'url'],
    ];
    for (const [f, what] of secrets) {
      const c = code(join(SRC, f));
      const calls = [...c.matchAll(/copyAndSay\(([^,]+),\s*\{([^}]*)\}/g)];
      const mine = calls.filter((m) => (m[1] ?? '').includes(what));
      expect(mine.length, `${f} copies ${what}`).toBeGreaterThan(0);
      for (const m of mine) expect(m[2], `${f}: ${what}`).toContain("kind: 'secret'");
    }
  });
});
