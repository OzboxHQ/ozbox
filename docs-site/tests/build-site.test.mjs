import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmp, write, run } from './helpers.mjs';
import { convertMarkdown } from '../scripts/lib/convert.mjs';
import { compileAll } from '../scripts/compile-check.mjs';

const BASE = {
  repoUrl: 'https://example.com/org/repo',
  placement: { architecture: 'architecture', releasing: 'project' },
  navigation: {
    tabs: [
      { tab: 'Docs', groups: [{ group: 'Start', pages: ['index'] }, { group: 'Use cases', pages: ['$use-cases'] }, { group: 'Guides', pages: ['$section:guides'] }] },
      { tab: 'Arch', groups: [{ group: 'A', pages: ['$section:architecture'] }, { group: 'ADR', pages: ['$adr'] }, { group: 'P', pages: ['$section:project'] }] },
    ],
  },
};

function fixture(extra = {}) {
  const root = tmp('build-site-');
  write(root, {
    'LICENSE': 'x',
    'infra/README.md': 'infra',
    'docs/architecture.md': '# Architecture\n\nHow it fits. See [the ADR](adr/0001-a.md#why) and [infra](../infra/README.md).\n',
    'docs/use-cases/README.md': '# Use cases\n\nIntro paragraph.\n\n| Guide | For |\n|---|---|\n| [Second](second.md) | b |\n| [First](first.md) | a |\n',
    'docs/use-cases/first.md': '# First\n\nFirst guide.\n\n## Why\n\nBack to [all](README.md).\n',
    'docs/use-cases/second.md': '# Second\n\nSecond guide with {braces} and <angle> and <https://example.com/x>.\n\n<!-- a comment -->\n\n```\n{ keep } <this>\n```\n',
    'docs/adr/README.md': '# ADRs\n\nIndex.\n\n[one](0001-a.md)\n',
    'docs/adr/0001-a.md': '# 0001 - A\n\n**Decision.** Do a.\n\n## Why\n\nBecause. See [LICENSE](../../LICENSE).\n',
    ...extra,
  });
  const site = tmp('build-site-out-');
  write(site, { 'docs.base.json': JSON.stringify(BASE), 'index.mdx': '---\ntitle: "Home"\ndescription: "d"\n---\n\nHi.\n' });
  return { root, site };
}

const build = (f, ...a) => run('build-site.mjs', ['--repo', f.root, '--site', f.site, ...a]);

test('builds pages, an ADR index, ordered use cases and navigation', () => {
  const f = fixture();
  const r = build(f);
  assert.equal(r.code, 0, r.out);
  const docs = JSON.parse(readFileSync(join(f.site, 'docs.json'), 'utf8'));
  const groups = Object.fromEntries(docs.navigation.tabs.flatMap((t) => t.groups.map((g) => [g.group, g.pages])));
  assert.deepEqual(groups['Use cases'], ['use-cases/index', 'use-cases/second', 'use-cases/first']); // README table order
  assert.deepEqual(groups.ADR, ['adr/index', 'adr/0001-a']);
  assert.deepEqual(groups.A, ['architecture']);
  assert.equal(groups.Guides, undefined); // empty groups are dropped
  assert.equal('placement' in docs, false);
});

test('rewrites links between docs, to repo files and to directories', () => {
  const f = fixture();
  build(f);
  const arch = readFileSync(join(f.site, 'architecture.mdx'), 'utf8');
  assert.match(arch, /\]\(\/adr\/0001-a#why\)/);
  assert.match(arch, /\]\(https:\/\/example\.com\/org\/repo\/blob\/main\/infra\/README\.md\)/);
  assert.match(readFileSync(join(f.site, 'use-cases/first.mdx'), 'utf8'), /\]\(\/use-cases\)/);
  assert.match(readFileSync(join(f.site, 'adr/0001-a.mdx'), 'utf8'), /blob\/main\/LICENSE/);
});

test('escapes MDX hazards outside code, drops comments, keeps code verbatim, and the result compiles', async () => {
  const f = fixture();
  build(f);
  const mdx = readFileSync(join(f.site, 'use-cases/second.mdx'), 'utf8');
  assert.match(mdx, /with \\\{braces\\\} and &lt;angle> and \[https:\/\/example\.com\/x\]/);
  assert.doesNotMatch(mdx, /a comment/);
  assert.match(mdx, /^\{ keep \} <this>$/m);
  const { failures } = await compileAll(f.site);
  assert.deepEqual(failures, []);
});

test('title and description come from the H1 and first paragraph', () => {
  const mdx = convertMarkdown('# My *title*\n\nFirst [para](x.md) with `code`.\n\nSecond.\n', { sourcePath: 'docs/x.md', linkMap: new Map([['docs/x.md', 'x']]), repoRoot: '/', repoUrl: 'u' });
  assert.match(mdx, /^title: "My title"$/m);
  assert.match(mdx, /^description: "First para with code\."$/m);
});

test('--check passes when in sync, fails on drift, on a missing file and on a stale file', () => {
  const f = fixture();
  assert.equal(build(f, '--check').code, 1); // nothing built yet
  build(f);
  assert.equal(build(f, '--check').code, 0);
  writeFileSync(join(f.root, 'docs/use-cases/first.md'), '# First\n\nChanged.\n');
  const drift = build(f, '--check');
  assert.equal(drift.code, 1);
  assert.match(drift.out, /out of date: use-cases\/first\.mdx/);
  build(f);
  rmSync(join(f.root, 'docs/use-cases/second.md'));
  writeFileSync(join(f.root, 'docs/use-cases/README.md'), '# Use cases\n\nIntro.\n\n[First](first.md)\n');
  const stale = build(f, '--check');
  assert.match(stale.out, /stale: use-cases\/second\.mdx/);
  build(f);
  assert.equal(build(f, '--check').code, 0);
});

test('a new docs/*.md appears in the navigation without editing the generator', () => {
  const f = fixture({ 'docs/releasing.md': '# Releasing\n\nHow.\n', 'docs/mesh.md': '# Mesh\n\nWhat.\n' });
  assert.equal(build(f).code, 0);
  const docs = JSON.parse(readFileSync(join(f.site, 'docs.json'), 'utf8'));
  const groups = Object.fromEntries(docs.navigation.tabs.flatMap((t) => t.groups.map((g) => [g.group, g.pages])));
  assert.deepEqual(groups.P, ['releasing']);
  assert.deepEqual(groups.Guides, ['mesh']);
});

test('a link to a file that does not exist fails the build', () => {
  const f = fixture({ 'docs/bad.md': '# Bad\n\nSee [x](nope.md).\n' });
  const r = build(f);
  assert.equal(r.code, 1);
  assert.match(r.out, /nope\.md/);
});

test('a doc that would overwrite a hand-written page fails the build', () => {
  const f = fixture({ 'docs/install.md': '# Install\n\nx.\n' });
  assert.equal(build(f).code, 1);
});
