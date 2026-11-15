#!/usr/bin/env node
/**
 * Stamp the release date into every changelog entry that still carries a placeholder.
 *
 * Entries are written while the work is built, dated `[Release date]`. They must never be published that way:
 * `validate-docs.mjs --strict-dates` refuses them. This is the release step that resolves them.
 *
 * Usage (from docs-site/):
 *   npm run stamp-release                          # today, written out ("November 10, 2026")
 *   npm run stamp-release -- --date "November 10, 2026"
 *   npm run stamp-release -- --check               # list what would change, write nothing
 *
 * Only the `label` of an `<Update>` whose whole value is one bracketed placeholder is changed.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { walk } from './lib/site-lib.mjs';

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const PLACEHOLDER_LABEL = /(<Update\s+label=)(["'])\[[^\]\n]*\]\2/g;
const WRITTEN_DATE = /^(January|February|March|April|May|June|July|August|September|October|November|December) ([1-9]|[12]\d|3[01]), (20\d\d)$/;

export const writtenOut = (d) => `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;

export function stampText(text, date) {
  let count = 0;
  const out = text.replace(PLACEHOLDER_LABEL, (_m, open, q) => {
    count += 1;
    return `${open}${q}${date}${q}`;
  });
  return { text: out, count };
}

function main() {
  const argv = process.argv.slice(2);
  const check = argv.includes('--check');
  const di = argv.indexOf('--date');
  const date = di >= 0 ? argv[di + 1] : writtenOut(new Date());
  if (!date || !WRITTEN_DATE.test(date)) {
    console.error(`--date must be written out like "November 10, 2026" (got ${JSON.stringify(date)}).`);
    process.exit(2);
  }
  const given = argv.find((a, i) => !a.startsWith('--') && argv[i - 1] !== '--date');
  const root = resolve(given ?? join(dirname(fileURLToPath(import.meta.url)), '..'));
  const dir = join(root, 'changelog');
  let total = 0;
  for (const file of existsSync(dir) ? walk(dir, ['.mdx']) : []) {
    const { text, count } = stampText(readFileSync(file, 'utf8'), date);
    if (!count) continue;
    total += count;
    console.log(`${check ? 'would stamp' : 'stamped'} ${count} entr${count === 1 ? 'y' : 'ies'} in ${file} -> ${date}`);
    if (!check) writeFileSync(file, text);
  }
  if (!total) console.log('No placeholder dates found.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
