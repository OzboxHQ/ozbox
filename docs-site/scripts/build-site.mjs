#!/usr/bin/env node
/**
 * Build the docs site from the single source of truth.
 *
 *   docs/architecture.md, docs/<other>.md   -> docs-site/<name>.mdx
 *   docs/use-cases/*.md                     -> docs-site/use-cases/*.mdx   (README.md -> index.mdx)
 *   docs/adr/*.md                           -> docs-site/adr/*.mdx         (README.md -> index.mdx)
 *   SECURITY.md, ROADMAP.md                 -> docs-site/security-policy.mdx, roadmap.mdx
 *   docs.base.json + the pages above        -> docs-site/docs.json
 *
 * The generated files are committed (Mintlify reads this folder from the repository). `--check` writes nothing and
 * fails when any generated file is missing, differs, or is stale (a generated file whose source is gone).
 *
 * Usage: node scripts/build-site.mjs [--check] [--repo <dir>] [--site <dir>]
 */
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { convertMarkdown, GENERATED_MARK } from './lib/convert.mjs';
import { walk, rel } from './lib/site-lib.mjs';

const HAND_WRITTEN = new Set(['index', 'install', 'cli-reference', 'changelog']);
const SENTINEL_SECTION = /^\$section:(.+)$/;

const mdIn = (dir) =>
  existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.md') && statSync(join(dir, f)).isFile()).sort() : [];

/** Every source file and the site page it becomes: [{ source, page, kind }] */
export function collectSources(repoRoot) {
  const out = [];
  const docs = join(repoRoot, 'docs');
  for (const f of mdIn(docs)) out.push({ source: `docs/${f}`, page: f.replace(/\.md$/, ''), kind: 'doc' });
  for (const [dir, kind] of [['use-cases', 'use-cases'], ['adr', 'adr']]) {
    for (const f of mdIn(join(docs, dir))) {
      const name = f.replace(/\.md$/, '');
      out.push({ source: `docs/${dir}/${f}`, page: name === 'README' ? `${dir}/index` : `${dir}/${name}`, kind });
    }
  }
  if (existsSync(join(repoRoot, 'SECURITY.md'))) out.push({ source: 'SECURITY.md', page: 'security-policy', kind: 'doc' });
  if (existsSync(join(repoRoot, 'ROADMAP.md'))) out.push({ source: 'ROADMAP.md', page: 'roadmap', kind: 'doc' });
  for (const s of out) {
    if (s.kind === 'doc' && HAND_WRITTEN.has(s.page)) {
      throw new Error(`${s.source} would become the page "${s.page}", which is hand-written in docs-site. Rename the source.`);
    }
  }
  return out;
}

/** Use-case guides in the order of the table in docs/use-cases/README.md, then any others alphabetically. */
function orderUseCases(repoRoot, pages) {
  const readme = join(repoRoot, 'docs/use-cases/README.md');
  const order = [];
  if (existsSync(readme)) {
    for (const m of readFileSync(readme, 'utf8').matchAll(/\]\(([\w-]+)\.md(?:#[^)]*)?\)/g)) {
      const p = `use-cases/${m[1]}`;
      if (pages.includes(p) && !order.includes(p)) order.push(p);
    }
  }
  return [...order, ...pages.filter((p) => !order.includes(p)).sort()];
}

export function buildNavigation(base, sources, repoRoot) {
  const pages = sources.map((s) => s.page);
  const useCases = orderUseCases(repoRoot, pages.filter((p) => p.startsWith('use-cases/') && p !== 'use-cases/index'));
  const adrs = pages.filter((p) => p.startsWith('adr/') && p !== 'adr/index').sort();
  const placement = base.placement ?? {};
  const sections = {};
  for (const p of pages.filter((p) => p.includes('/') === false)) {
    const key = placement[p] ?? base.defaultSection ?? 'guides';
    (sections[key] ??= []).push(p);
  }
  for (const k of Object.keys(sections)) sections[k].sort();

  const expand = (entries) =>
    entries.flatMap((e) => {
      if (typeof e !== 'string') return [e];
      if (e === '$use-cases') return pages.includes('use-cases/index') ? ['use-cases/index', ...useCases] : useCases;
      if (e === '$adr') return pages.includes('adr/index') ? ['adr/index', ...adrs] : adrs;
      const m = SENTINEL_SECTION.exec(e);
      if (m) return sections[m[1]] ?? [];
      return [e];
    });

  const nav = structuredClone(base.navigation);
  nav.tabs = nav.tabs
    .map((tab) => ({ ...tab, groups: tab.groups.map((g) => ({ ...g, pages: expand(g.pages) })).filter((g) => g.pages.length) }))
    .filter((tab) => tab.groups.length);
  const used = new Set(nav.tabs.flatMap((t) => t.groups.flatMap((g) => g.pages)));
  const unplaced = pages.filter((p) => !used.has(p));
  if (unplaced.length) throw new Error(`generated pages not placed in the navigation: ${unplaced.join(', ')}`);
  return nav;
}

/** The full expected output: Map of site-relative path -> content. */
export function buildAll({ repoRoot, siteRoot }) {
  const baseFile = join(siteRoot, 'docs.base.json');
  const base = JSON.parse(readFileSync(baseFile, 'utf8'));
  const sources = collectSources(repoRoot);
  const linkMap = new Map(sources.map((s) => [s.source, s.page]));
  const repoUrl = (base.repoUrl ?? 'https://github.com/OzboxHQ/ozbox').replace(/\/$/, '');
  const out = new Map();
  for (const s of sources) {
    const mdx = convertMarkdown(readFileSync(join(repoRoot, s.source), 'utf8'), {
      sourcePath: s.source,
      linkMap,
      repoRoot,
      repoUrl,
    });
    out.set(`${s.page}.mdx`, mdx);
  }
  const { placement, defaultSection, repoUrl: _r, ...mintlify } = base;
  mintlify.navigation = buildNavigation(base, sources, repoRoot);
  out.set('docs.json', `${JSON.stringify(mintlify, null, 2)}\n`);
  return out;
}

/** Files carrying the generated marker that no source produces any more. */
function staleFiles(siteRoot, expected) {
  return walk(siteRoot, ['.mdx'])
    .map((f) => rel(siteRoot, f))
    .filter((f) => !expected.has(f) && readFileSync(join(siteRoot, f), 'utf8').includes(GENERATED_MARK));
}

export function run({ repoRoot, siteRoot, check }) {
  const expected = buildAll({ repoRoot, siteRoot });
  const stale = staleFiles(siteRoot, expected);
  const problems = [];
  for (const [path, content] of expected) {
    const full = join(siteRoot, path);
    const current = existsSync(full) ? readFileSync(full, 'utf8') : null;
    if (current === content) continue;
    problems.push(`${current === null ? 'missing' : 'out of date'}: ${path}`);
    if (!check) {
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, content);
    }
  }
  for (const f of stale) {
    problems.push(`stale: ${f}`);
    if (!check) rmSync(join(siteRoot, f));
  }
  return { problems, count: expected.size };
}

function main() {
  const argv = process.argv.slice(2);
  const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? resolve(argv[i + 1]) : null; };
  const here = dirname(dirname(fileURLToPath(import.meta.url)));
  const siteRoot = arg('--site') ?? here;
  const repoRoot = arg('--repo') ?? dirname(siteRoot);
  const check = argv.includes('--check');
  const { problems, count } = run({ repoRoot, siteRoot, check });
  if (check) {
    if (problems.length) {
      console.error(problems.map((p) => `  ${p}`).join('\n'));
      console.error('\nThe generated pages are not in sync with docs/. Run `npm run build` in docs-site and commit the result.');
      process.exit(1);
    }
    console.log(`build-site: ${count} generated files are up to date.`);
  } else {
    console.log(`build-site: wrote ${problems.length} of ${count} files${problems.length ? ':' : '.'}`);
    for (const p of problems) console.log(`  ${p}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
