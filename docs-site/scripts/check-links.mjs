#!/usr/bin/env node
/**
 * Offline link checker. Every internal link, in-page anchor and image in every page must resolve.
 * (`mint broken-links` needs the network and a hosted toolchain; this is the hard gate.)
 *
 * Usage: node scripts/check-links.mjs [rootDir]
 */
import { readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { walk, rel, parseFrontmatter, headingSlugs, extractLinks, resolveSiteTarget, splitAnchor, isExternal } from './lib/site-lib.mjs';

/** Returns an array of problem strings. */
export function checkLinks(root) {
  const problems = [];
  const slugCache = new Map();
  const slugsOf = (file) => {
    if (!slugCache.has(file)) slugCache.set(file, headingSlugs(parseFrontmatter(readFileSync(file, 'utf8')).body));
    return slugCache.get(file);
  };
  for (const file of walk(root, ['.mdx'])) {
    const text = readFileSync(file, 'utf8');
    for (const { target, line, image } of extractLinks(text)) {
      if (isExternal(target) || target.startsWith('{')) continue;
      const here = `${rel(root, file)}:${line}`;
      const [pathPart, anchor] = splitAnchor(target);
      const r = resolveSiteTarget(root, target, file);
      if (!r.file) {
        problems.push(`${here}: ${image ? 'image' : 'link'} ${target} does not resolve to a page or file`);
        continue;
      }
      if (image && r.isPage) problems.push(`${here}: image ${target} is a page, not an image`);
      if (anchor && r.isPage) {
        let a = anchor;
        try { a = decodeURIComponent(anchor); } catch { /* keep */ }
        if (!slugsOf(r.file).has(a)) problems.push(`${here}: ${target} - no heading with the anchor #${a} in ${rel(root, r.file)}`);
      }
      void pathPart;
    }
  }
  return problems;
}

function main() {
  const root = resolve(process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..'));
  const problems = checkLinks(root);
  if (problems.length) {
    console.error(problems.map((p) => `  ${p}`).join('\n'));
    console.error(`\n${problems.length} broken link${problems.length === 1 ? '' : 's'}.`);
    process.exit(1);
  }
  console.log('check-links: every internal link, anchor and image resolves.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
