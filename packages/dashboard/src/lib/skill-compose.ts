// Building a skill's files in the browser, before they are sent. The server (and the box's own daemon) check everything again with
// the same rules; this only saves a round trip and says what is wrong in the person's words. The limits mirror
// `ozbox_core::skill_pack`.

export const MAX_FILES = 50;
export const MAX_FILE_BYTES = 128 * 1024;
export const MAX_TOTAL_BYTES = 512 * 1024;
export const TEXT_EXTENSIONS = ['md', 'txt', 'json', 'yaml', 'yml', 'toml', 'sh', 'py', 'js', 'ts', 'rs', 'sql', 'html', 'css', 'csv'] as const;
const SCRIPT_EXTENSIONS = ['sh', 'py', 'js', 'ts', 'rs', 'sql'];

export type FileKind = 'instructions' | 'script' | 'text';

export function fileKind(path: string): FileKind {
  if (path === 'SKILL.md') return 'instructions';
  const ext = path.split('.').pop() ?? '';
  return SCRIPT_EXTENSIONS.includes(ext) ? 'script' : 'text';
}

const NAME = /^[A-Za-z0-9_-]{1,64}$/;
const COMPONENT = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;
// Characters a reviewer cannot see or that change how text reads: control characters other than newline, return and tab,
// zero-width and direction marks, variation selectors and tag characters. The same set the server refuses.
const HIDDEN_RANGES: [number, number][] = [
  [0x00, 0x08], [0x0b, 0x0c], [0x0e, 0x1f], [0x7f, 0x9f], [0xad, 0xad], [0x180e, 0x180e], [0x200b, 0x200f], [0x202a, 0x202e],
  [0x2060, 0x2064], [0x2066, 0x2069], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xe0000, 0xe007f],
];
export const hasHidden = (text: string): boolean => {
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0;
    if (HIDDEN_RANGES.some(([a, b]) => c >= a && c <= b)) return true;
  }
  return false;
};

export const skillNameOk = (n: string): boolean => NAME.test(n);

export interface Fields {
  name: string;
  description: string;
  version: string;
  license: string;
  instructions: string;
}

/** The `SKILL.md` for a skill written on the page. A front-matter value is one line, so line breaks become spaces. */
export function composeSkillMd(f: Fields): string {
  const one = (s: string) => s.replace(/\s+/g, ' ').trim();
  const lines = ['---', `name: ${one(f.name)}`, `description: ${one(f.description)}`];
  if (one(f.version)) lines.push(`version: ${one(f.version)}`);
  if (one(f.license)) lines.push(`license: ${one(f.license)}`);
  lines.push('---', '', f.instructions.replace(/\s+$/, ''), '');
  return lines.join('\n');
}

export type Problem =
  | { code: 'name' }
  | { code: 'description' }
  | { code: 'no_skill_md' }
  | { code: 'too_many'; max: number }
  | { code: 'too_big'; max: number }
  | { code: 'file_too_big'; path: string; max: number }
  | { code: 'file_type'; path: string }
  | { code: 'file_name'; path: string }
  | { code: 'hidden'; path: string };

const bytes = (s: string) => new TextEncoder().encode(s).length;

/** What is wrong with these files, in the order a person would fix it; empty when they may be sent. */
export function checkFiles(files: Record<string, string>): Problem[] {
  const out: Problem[] = [];
  const paths = Object.keys(files);
  if (paths.length > MAX_FILES) out.push({ code: 'too_many', max: MAX_FILES });
  const total = paths.reduce((n, p) => n + bytes(files[p] ?? ''), 0);
  if (total > MAX_TOTAL_BYTES) out.push({ code: 'too_big', max: MAX_TOTAL_BYTES / 1024 });
  for (const p of paths) {
    const parts = p.split('/');
    if (parts.length > 4 || !parts.every((c) => COMPONENT.test(c))) out.push({ code: 'file_name', path: p });
    else if (!(TEXT_EXTENSIONS as readonly string[]).includes(p.split('.').pop() ?? '')) out.push({ code: 'file_type', path: p });
    const text = files[p] ?? '';
    if (bytes(text) > MAX_FILE_BYTES) out.push({ code: 'file_too_big', path: p, max: MAX_FILE_BYTES / 1024 });
    if (hasHidden(text)) out.push({ code: 'hidden', path: p });
  }
  if (!('SKILL.md' in files)) out.push({ code: 'no_skill_md' });
  return out;
}

/** `name:` and `description:` from a SKILL.md's front matter, the way the server reads them. */
export function readFrontMatter(md: string): { name: string; description: string; version: string } {
  const out = { name: '', description: '', version: '' };
  const lines = md.split(/\r?\n/);
  if (lines[0]?.trim() !== '---') return out;
  for (const l of lines.slice(1)) {
    if (l.trim() === '---') break;
    const i = l.indexOf(':');
    if (i < 0) continue;
    const k = l.slice(0, i).trim();
    const v = l.slice(i + 1).trim().replace(/^["']|["']$/g, '');
    if (k === 'name' || k === 'description' || k === 'version') out[k] = v;
  }
  return out;
}

/** The problems with files from the page's two ways of making a skill; a name or description the server would refuse comes first. */
export function checkSkill(files: Record<string, string>): Problem[] {
  const fm = readFrontMatter(files['SKILL.md'] ?? '');
  const out: Problem[] = [];
  if ('SKILL.md' in files) {
    if (!skillNameOk(fm.name)) out.push({ code: 'name' });
    if (!fm.description || [...fm.description].length > 1024) out.push({ code: 'description' });
  }
  return [...out, ...checkFiles(files)];
}

/** Paths from a folder or file picker. A folder's own name is dropped: the skill's files sit at its top. */
export function pickedPaths(list: { name: string; webkitRelativePath?: string }[]): string[] {
  const rels = list.map((f) => (f.webkitRelativePath && f.webkitRelativePath.includes('/') ? f.webkitRelativePath : f.name));
  const top = rels.every((r) => r.includes('/')) ? rels[0]?.split('/')[0] : undefined;
  return rels.map((r) => (top && r.startsWith(`${top}/`) ? r.slice(top.length + 1) : r));
}
