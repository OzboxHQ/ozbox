// Shared helpers for the docs-site scripts: file walking, navigation, front matter, headings, links.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, dirname, posix, sep } from 'node:path';

export const SKIP_DIRS = new Set(['node_modules', '.git', '.mint', 'scripts', 'tests']);

export function walk(dir, exts, out = [], root = dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(full, exts, out, root);
    } else if (exts.some((e) => entry.endsWith(e))) {
      out.push(full);
    }
  }
  return out;
}

export const toPosix = (p) => p.split(sep).join('/');
export const rel = (root, p) => toPosix(relative(root, p));

/** All page names in a docs.json navigation, in order. */
export function navPages(nav) {
  const out = [];
  const visit = (node) => {
    if (typeof node === 'string') return void out.push(node);
    if (Array.isArray(node)) return node.forEach(visit);
    if (node && typeof node === 'object') {
      for (const key of ['tabs', 'groups', 'pages']) if (node[key]) visit(node[key]);
    }
  };
  visit(nav);
  return out;
}

export function readDocsJson(root) {
  const file = join(root, 'docs.json');
  return JSON.parse(readFileSync(file, 'utf8'));
}

/** Split `---` front matter. Returns { data, body } with a flat string map (enough for title and description). */
export function parseFrontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { data: {}, body: text, hasFrontmatter: false };
  const data = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    if (!kv) continue;
    let v = kv[2].trim();
    if (v.startsWith('"')) {
      try { v = JSON.parse(v); } catch { /* keep raw */ }
    } else if (v.startsWith("'") && v.endsWith("'")) v = v.slice(1, -1);
    data[kv[1]] = v;
  }
  return { data, body: text.slice(m[0].length), hasFrontmatter: true };
}

/**
 * Blank out fenced code blocks and inline code spans, keeping line structure (so line numbers survive).
 * Used for every "must not appear in prose" check.
 */
export function stripCode(text) {
  const lines = text.split('\n');
  let fence = null;
  return lines
    .map((line) => {
      const f = /^\s*(`{3,}|~{3,})/.exec(line);
      if (fence) {
        if (f && f[1][0] === fence[0] && f[1].length >= fence.length && /^\s*(`{3,}|~{3,})\s*$/.test(line)) fence = null;
        return '';
      }
      if (f) {
        fence = f[1];
        return '';
      }
      return line.replace(/(`+)[^\n]*?\1/g, (s) => ' '.repeat(s.length));
    })
    .join('\n');
}

/** GitHub-style heading slugs for a page body (what Mintlify uses for in-page anchors). */
export function headingSlugs(body) {
  const slugs = new Set();
  const seen = new Map();
  for (const line of stripFencesOnly(body).split('\n')) {
    const m = /^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    let base = slugify(m[1]);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    slugs.add(n === 0 ? base : `${base}-${n}`);
  }
  return slugs;
}

function stripFencesOnly(text) {
  let fence = null;
  return text
    .split('\n')
    .map((line) => {
      const f = /^\s*(`{3,}|~{3,})/.exec(line);
      if (fence) {
        if (f && f[1][0] === fence[0] && f[1].length >= fence.length) fence = null;
        return '';
      }
      if (f) { fence = f[1]; return ''; }
      return line;
    })
    .join('\n');
}

export function slugify(heading) {
  return heading
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*_~]/g, '')
    .replace(/<[^>]+>/g, '')
    .replace(/\\([{}<>])/g, '$1')
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .replace(/\s/g, '-');
}

/** Internal and external link targets in prose (markdown links, images, href=/src= attributes). */
export function extractLinks(text) {
  const prose = stripCode(text);
  const out = [];
  const lines = prose.split('\n');
  lines.forEach((line, i) => {
    for (const m of line.matchAll(/(!?)\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) {
      out.push({ target: m[2], image: m[1] === '!', line: i + 1 });
    }
    for (const m of line.matchAll(/\b(href|src)=["']([^"']+)["']/g)) {
      out.push({ target: m[2], image: m[1] === 'src', line: i + 1 });
    }
  });
  return out;
}

/** Map a site path ("/use-cases/one-box#x") to the page file it serves, or null. Pages first, then static files. */
export function resolveSiteTarget(root, target, fromFile) {
  const [pathPart, anchor = ''] = splitAnchor(target);
  let p;
  if (pathPart === '') p = rel(root, fromFile);
  else if (pathPart.startsWith('/')) p = pathPart.slice(1);
  else p = posix.normalize(posix.join(posix.dirname(rel(root, fromFile)), pathPart));
  p = p.replace(/\/$/, '');
  if (p.startsWith('..')) return { file: null, anchor };
  const candidates = p === '' || p === '.' ? ['index.mdx'] : [`${p}.mdx`, `${p}/index.mdx`, p];
  for (const c of candidates) {
    const full = join(root, c);
    if (existsSync(full) && statSync(full).isFile()) return { file: full, anchor, isPage: c.endsWith('.mdx') };
  }
  return { file: null, anchor };
}

export function splitAnchor(target) {
  const i = target.indexOf('#');
  return i < 0 ? [target, ''] : [target.slice(0, i), target.slice(i + 1)];
}

export const isExternal = (t) => /^([a-z][a-z0-9+.-]*:|\/\/)/i.test(t);

export { readFileSync, existsSync, dirname, join, posix };
