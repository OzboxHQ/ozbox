import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');

export function tmp(prefix = 'docs-site-') {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function write(root, files) {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

export const page = (title, body = 'Body text.') => `---\ntitle: "${title}"\ndescription: "About ${title}."\n---\n\n${body}\n`;

/** A minimal, valid site: index + a second page, both in the navigation. */
export function site(extra = {}, nav = ['index', 'other']) {
  return write(tmp(), {
    'docs.json': JSON.stringify({ name: 'T', navigation: { tabs: [{ tab: 'Docs', groups: [{ group: 'G', pages: nav }] }] } }),
    'index.mdx': page('Home', 'See [other](/other).'),
    'other.mdx': page('Other', '## A heading\n\nText.'),
    ...extra,
  });
}

export function run(script, args = [], opts = {}) {
  const r = spawnSync(process.execPath, [join(SCRIPTS, script), ...args], { encoding: 'utf8', ...opts });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}
