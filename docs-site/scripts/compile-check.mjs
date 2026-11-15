#!/usr/bin/env node
/**
 * Compile every MDX file the way Mintlify's hosted build does. `mint dev` tolerates syntax the hosted build rejects
 * (HTML comments; prose like {n}, which MDX parses as a JavaScript expression), so a site can work on a laptop and
 * 404 every page once published. Running the real compiler is the only honest check.
 *
 * Usage: node scripts/compile-check.mjs [rootDir]
 */
import { compile, createProcessor } from '@mdx-js/mdx';
import remarkGfm from 'remark-gfm';
import remarkFrontmatter from 'remark-frontmatter';
import { readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { walk, rel } from './lib/site-lib.mjs';

const OPTIONS = { remarkPlugins: [remarkFrontmatter, remarkGfm], development: false, jsx: true };

/** Prose expressions that are not comments: `{x}` compiles, then fails (or renders nothing) when the page is served. */
function proseExpressions(tree, out = []) {
  if (tree.type === 'mdxFlowExpression' || tree.type === 'mdxTextExpression') {
    if (tree.value.replace(/\/\*[\s\S]*?\*\//g, '').trim() !== '') out.push(tree);
  }
  for (const child of tree.children ?? []) proseExpressions(child, out);
  return out;
}

export async function compileAll(root) {
  const failures = [];
  const files = walk(root, ['.mdx']);
  for (const file of files) {
    try {
      const text = readFileSync(file, 'utf8');
      await compile(text, OPTIONS);
      for (const node of proseExpressions(createProcessor(OPTIONS).parse(text))) {
        failures.push(`${rel(root, file)}: {${node.value.trim().slice(0, 40)}} in prose is a JavaScript expression (line ${node.position?.start.line}); escape the braces`);
      }
    } catch (e) {
      failures.push(`${rel(root, file)}: ${String(e.reason || e.message).slice(0, 200)}${e.line ? ` (line ${e.line}, column ${e.column})` : ''}`);
    }
  }
  return { count: files.length, failures };
}

async function main() {
  const root = resolve(process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..'));
  const { count, failures } = await compileAll(root);
  if (failures.length) {
    console.error(failures.map((f) => `  ${f}`).join('\n'));
    console.error(`\n${count} files checked, ${failures.length} failed to compile.\nEscape literal braces in prose as \\{like this\\}.`);
    process.exit(1);
  }
  console.log(`compile-check: ${count} files compile.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
