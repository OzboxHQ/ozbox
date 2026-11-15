#!/usr/bin/env node
/**
 * Validate the docs site the way Mintlify's hosted build will see it.
 *
 *   - docs.json parses; every page in the navigation is an .mdx file; no page appears twice
 *   - every .mdx file (except snippets/) is reachable from the navigation
 *   - every page has a title and a description
 *   - no HTML comments (MDX has no syntax for them: the hosted build 404s the whole page)
 *   - no private names, hostnames or account ids
 *   - every internal link, anchor and image resolves
 *   - --strict-dates: no changelog entry still dated with a [Release date] placeholder
 *
 * Usage: node scripts/validate-docs.mjs [rootDir] [--strict-dates]
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { walk, rel, navPages, readDocsJson, parseFrontmatter, stripCode } from './lib/site-lib.mjs';
import { FORBIDDEN_ANYWHERE, FORBIDDEN_IN_PROSE } from './lib/vocabulary.mjs';
import { checkLinks } from './check-links.mjs';

const PLACEHOLDER_LABEL = /<Update\s+label=["']\[[^\]\n]*\]["']/g;

export function validate(root, { strictDates = false } = {}) {
  const problems = [];
  let docs;
  try {
    docs = readDocsJson(root);
  } catch (e) {
    return [`docs.json: ${e.message}`];
  }
  if (!docs.navigation) problems.push('docs.json: no "navigation"');
  const pages = navPages(docs.navigation ?? {});
  const seen = new Set();
  for (const p of pages) {
    if (seen.has(p)) problems.push(`docs.json: page "${p}" is listed more than once`);
    seen.add(p);
    if (!existsSync(join(root, `${p}.mdx`))) problems.push(`docs.json: page "${p}" has no ${p}.mdx file`);
  }

  const files = walk(root, ['.mdx']);
  for (const file of files) {
    const name = rel(root, file);
    const page = name.replace(/\.mdx$/, '');
    if (!page.startsWith('snippets/') && !seen.has(page)) problems.push(`${name}: not in the navigation (orphan page)`);
    const text = readFileSync(file, 'utf8');
    const { data, hasFrontmatter } = parseFrontmatter(text);
    if (!hasFrontmatter || !data.title) problems.push(`${name}: missing front matter title`);
    if (!hasFrontmatter || !data.description) problems.push(`${name}: missing front matter description`);

    const prose = stripCode(text);
    const lines = prose.split('\n');
    lines.forEach((line, i) => {
      if (line.includes('<!--')) problems.push(`${name}:${i + 1}: HTML comment (use {/* */}; <!-- --> makes the hosted build reject the page)`);
      for (const [what, re] of FORBIDDEN_IN_PROSE) if (re.test(line)) problems.push(`${name}:${i + 1}: ${what}`);
    });
    text.split('\n').forEach((line, i) => {
      for (const [what, re] of FORBIDDEN_ANYWHERE) if (re.test(line)) problems.push(`${name}:${i + 1}: mentions ${what}`);
    });
    if (strictDates && PLACEHOLDER_LABEL.test(text)) {
      problems.push(`${name}: a changelog entry is still dated with a placeholder (run \`npm run stamp-release\`)`);
    }
    PLACEHOLDER_LABEL.lastIndex = 0;
  }
  problems.push(...checkLinks(root));
  return problems;
}

function main() {
  const argv = process.argv.slice(2);
  const root = resolve(argv.find((a) => !a.startsWith('--')) || join(dirname(fileURLToPath(import.meta.url)), '..'));
  const problems = validate(root, { strictDates: argv.includes('--strict-dates') });
  if (problems.length) {
    console.error(problems.map((p) => `  ${p}`).join('\n'));
    console.error(`\nvalidate-docs: ${problems.length} problem${problems.length === 1 ? '' : 's'}.`);
    process.exit(1);
  }
  console.log('validate-docs: navigation, pages, front matter, vocabulary and links are valid.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
