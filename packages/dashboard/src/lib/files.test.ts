import { describe, expect, it } from 'vitest';

import { baseName, breadcrumbs, checkUploads, collapseDiff, diffLines, diffStats, entryIcon, joinPath, parentOf, restoredName, validName, within } from './files';

describe('paths', () => {
  it('joins, finds parents and names', () => {
    expect(joinPath('/work/', 'a.txt')).toBe('/work/a.txt');
    expect(parentOf('/work/a/b.txt')).toBe('/work/a');
    expect(parentOf('/work')).toBe('/');
    expect(baseName('/work/a/')).toBe('a');
  });

  it('builds a breadcrumb trail from the root', () => {
    expect(breadcrumbs('/work', '/work/projects/demo')).toEqual([
      { label: 'work', path: '/work' },
      { label: 'projects', path: '/work/projects' },
      { label: 'demo', path: '/work/projects/demo' },
    ]);
    expect(breadcrumbs('/work', '/work')).toHaveLength(1);
    // a path outside the root never produces crumbs beyond the root
    expect(breadcrumbs('/work', '/etc')).toHaveLength(1);
  });

  it('knows what is inside a root', () => {
    expect(within('/work', '/work/a')).toBe(true);
    expect(within('/work', '/workshop')).toBe(false);
  });

  it('names a restored item beside the original', () => {
    expect(restoredName('/work/a/report.txt', 'restored')).toBe('/work/a/report (restored).txt');
    expect(restoredName('/work/a/Makefile', 'restored')).toBe('/work/a/Makefile (restored)');
    expect(restoredName('/work/.env.local', 'x')).toBe('/work/.env (x).local');
  });

  it('validates names', () => {
    for (const ok of ['a.txt', 'my folder', '.hidden']) expect(validName(ok)).toBe(true);
    for (const bad of ['', '.', '..', 'a/b', 'a\\b', 'a\nb', 'x'.repeat(256)]) expect(validName(bad)).toBe(false);
  });
});

describe('uploads', () => {
  it('separates files over the limit', () => {
    const f = (n: string, size: number) => ({ name: n, size }) as File;
    const r = checkUploads([f('a', 10), f('b', 5000), f('c', 1000)], 1000);
    expect(r.ok.map((x) => x.name)).toEqual(['a', 'c']);
    expect(r.tooLarge.map((x) => x.name)).toEqual(['b']);
  });
});

describe('diffLines', () => {
  it('reports no change as all same', () => {
    expect(diffStats(diffLines('a\nb', 'a\nb'))).toEqual({ added: 0, removed: 0 });
  });

  it('finds an edit in the middle with line numbers', () => {
    const d = diffLines('one\ntwo\nthree\nfour', 'one\n2\nthree\nfour');
    expect(d.filter((l) => l.kind !== 'same')).toEqual([
      { kind: 'del', text: 'two', oldNo: 2, newNo: null },
      { kind: 'add', text: '2', oldNo: null, newNo: 2 },
    ]);
    expect(d.find((l) => l.text === 'four')).toMatchObject({ oldNo: 4, newNo: 4 });
  });

  it('handles insertions, deletions and empty sides', () => {
    expect(diffStats(diffLines('a\nc', 'a\nb\nc'))).toEqual({ added: 1, removed: 0 });
    expect(diffStats(diffLines('a\nb\nc', 'a\nc'))).toEqual({ added: 0, removed: 1 });
    expect(diffStats(diffLines('', 'x\ny'))).toEqual({ added: 2, removed: 0 });
    expect(diffStats(diffLines('x\ny', ''))).toEqual({ added: 0, removed: 2 });
  });

  it('matches a shuffled block exactly rather than replacing everything', () => {
    const d = diffLines('a\nb\nc\nd\ne', 'a\nc\nb\nd\ne');
    expect(diffStats(d)).toEqual({ added: 1, removed: 1 });
  });

  it('falls back to remove-then-add for a huge changed middle', () => {
    const a = Array.from({ length: 1600 }, (_, i) => `a${i}`).join('\n');
    const b = Array.from({ length: 1600 }, (_, i) => `b${i}`).join('\n');
    expect(diffStats(diffLines(a, b))).toEqual({ added: 1600, removed: 1600 });
  });

  it('collapses unchanged runs to a gap marker', () => {
    const lines = Array.from({ length: 30 }, (_, i) => `l${i}`);
    const after = [...lines];
    after[15] = 'changed';
    const c = collapseDiff(diffLines(lines.join('\n'), after.join('\n')), 2);
    expect(c.filter((l) => l.kind === 'gap')).toEqual([
      { kind: 'gap', hidden: 13 },
      { kind: 'gap', hidden: 12 },
    ]);
  });
});

describe('entryIcon', () => {
  it('picks a lock for blocked entries and a type for the rest', () => {
    const e = (name: string, extra = {}) => ({ name, path: `/work/${name}`, kind: 'file' as const, size: 1, modified_ms: 0, symlink: false, ...extra });
    expect(entryIcon(e('.env', { blocked: 'secret_blocked' }))).toBe('lock');
    expect(entryIcon(e('a.PNG'))).toBe('image');
    expect(entryIcon(e('a.pdf'))).toBe('pdf');
    expect(entryIcon(e('a.ts'))).toBe('text');
    expect(entryIcon(e('d', { kind: 'dir' }))).toBe('folder');
    expect(entryIcon(e('blob.bin'))).toBe('file');
  });
});

describe('route', () => {
  it('parses the per-box files page', async () => {
    const { parseRoute, hrefs } = await import('./router');
    expect(parseRoute('/boxes/alpha/files')).toEqual({ page: 'files', name: 'alpha' });
    expect(parseRoute('/boxes/a%20b/files')).toEqual({ page: 'files', name: 'a b' });
    expect(parseRoute('/boxes/alpha/other')).toEqual({ page: 'missing' });
    expect(hrefs.files('a b')).toBe('/boxes/a%20b/files');
  });
});
