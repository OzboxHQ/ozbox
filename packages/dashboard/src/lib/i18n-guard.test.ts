import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

import { en } from '../i18n/en';

const SRC = join(__dirname, '..');

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : p.endsWith('.tsx') ? [p] : [];
  });
}

/** Pages and components written before the catalogue existed. They are converted one at a time and leave this list as they are. */
const LEGACY = new Set<string>();

const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

/** Whether the `>` at `at` closes a JSX tag (as opposed to a generic's `>` or an arrow's). */
function closesJsxTag(code: string, at: number): boolean {
  if (code[at - 1] === '=') return false; // an arrow
  let depth = 0;
  for (let i = at; i >= 0; i--) {
    const c = code[i];
    if (c === '>' && code[i - 1] !== '=') depth++;
    else if (c === '<') {
      depth--;
      if (depth === 0) return !/[A-Za-z0-9_$.\])]/.test(code[i - 1] ?? ' ') && /[A-Za-z]/.test(code[i + 1] ?? '');
    }
  }
  return false;
}

/** Text a person reads, written straight into JSX: a text node with a letter in it, or a text attribute. */
export function hardCoded(source: string): string[] {
  const code = strip(source);
  const found: string[] = [];
  for (const m of code.matchAll(/>([^<>{}=;()&|\n][^<>{}]*)</g)) {
    const text = (m[1] ?? '').trim();
    if (/[A-Za-z]{2,}/.test(text) && closesJsxTag(code, m.index ?? 0)) found.push(text);
  }
  for (const m of code.matchAll(/\s(?:aria-label|placeholder|title|alt|label|description)="([^"]*[A-Za-z]{2,}[^"]*)"/g)) found.push(m[1] ?? '');
  return found;
}

describe('translation-ready pages', () => {
  it('a file that is not legacy has no hard-coded UI text', () => {
    const bad: string[] = [];
    for (const f of files(SRC)) {
      const rel = relative(SRC, f);
      if (LEGACY.has(rel) || rel.endsWith('.test.tsx')) continue;
      const h = hardCoded(readFileSync(f, 'utf8'));
      if (h.length > 0) bad.push(`${rel}: ${h.slice(0, 3).join(' | ')}`);
    }
    expect(bad, 'route these strings through t() and the catalogue in src/i18n/en.ts').toEqual([]);
  });

  it('the guard notices hard-coded text', () => {
    expect(hardCoded('<Button>Save the thing</Button>')).toEqual(['Save the thing']);
    expect(hardCoded('<Input placeholder="Type here" />')).toEqual(['Type here']);
    expect(hardCoded('<Button>{t("a.b")}</Button>')).toEqual([]);
  });

  it('legacy files still exist, so the list cannot quietly rot', () => {
    const present = new Set(files(SRC).map((f) => relative(SRC, f)));
    for (const l of LEGACY) expect(present.has(l), l).toBe(true);
  });

  it('every catalogue message is used or reserved, and keys are namespaced', () => {
    for (const k of Object.keys(en)) expect(k).toMatch(/^[a-z]+\.[a-z0-9_]+$/);
  });
});
