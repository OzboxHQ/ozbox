import type { FileEntry } from '../api/files';

/** A file bigger than this opens read-only: the quick editor is for small text. */
export const EDIT_MAX_BYTES = 256 * 1024;

/** Share links: the choices offered, in seconds. The box enforces 10 seconds to 24 hours. */
export const SHARE_TTLS = [
  { id: '15m', seconds: 15 * 60 },
  { id: '1h', seconds: 60 * 60 },
  { id: '24h', seconds: 24 * 60 * 60 },
] as const;

export function joinPath(dir: string, name: string): string {
  return `${dir.replace(/\/+$/, '')}/${name}`;
}

export function parentOf(path: string): string {
  const trimmed = path.replace(/\/+$/, '');
  const i = trimmed.lastIndexOf('/');
  return i <= 0 ? '/' : trimmed.slice(0, i);
}

export function baseName(path: string): string {
  const trimmed = path.replace(/\/+$/, '');
  return trimmed.slice(trimmed.lastIndexOf('/') + 1);
}

export interface Crumb {
  label: string;
  path: string;
}

/** The path bar: the root first (`/work`), then one entry per folder below it. */
export function breadcrumbs(root: string, path: string): Crumb[] {
  const r = root.replace(/\/+$/, '');
  const crumbs: Crumb[] = [{ label: baseName(r) || r, path: r }];
  if (path !== r && path.startsWith(`${r}/`)) {
    let acc = r;
    for (const part of path.slice(r.length + 1).split('/').filter(Boolean)) {
      acc = `${acc}/${part}`;
      crumbs.push({ label: part, path: acc });
    }
  }
  return crumbs;
}

/** Whether `path` is `root` or inside it. */
export function within(root: string, path: string): boolean {
  const r = root.replace(/\/+$/, '');
  return path === r || path.startsWith(`${r}/`);
}

/** A name for a restored item when the original place is taken: `report (restored).txt`. */
export function restoredName(original: string, suffix: string): string {
  const dir = parentOf(original);
  const name = baseName(original);
  const dot = name.lastIndexOf('.');
  const next = dot > 0 ? `${name.slice(0, dot)} (${suffix})${name.slice(dot)}` : `${name} (${suffix})`;
  return joinPath(dir, next);
}

export interface UploadCheck {
  ok: File[];
  tooLarge: File[];
}

export function checkUploads(files: File[], maxBytes: number): UploadCheck {
  const ok: File[] = [];
  const tooLarge: File[] = [];
  for (const f of files) (f.size > maxBytes ? tooLarge : ok).push(f);
  return { ok, tooLarge };
}

/** A valid name for a new folder or a rename: one component, nothing the box would refuse. */
export function validName(name: string): boolean {
  return name.length > 0 && name.length <= 255 && name !== '.' && name !== '..' && ![...name].some((c) => c === '/' || c === '\\' || c.charCodeAt(0) < 32);
}

export type KnownError =
  | 'secret_blocked'
  | 'internal'
  | 'git_internal'
  | 'symlink_escape'
  | 'outside_root'
  | 'not_regular'
  | 'stale'
  | 'exists'
  | 'too_large'
  | 'not_text'
  | 'no_space'
  | 'link_invalid'
  | 'bad_name'
  | 'not_found'
  | 'cross_device'
  | 'into_itself'
  | 'too_many_tokens'
  | 'too_many_transfers'
  | 'permission';

const KNOWN: ReadonlySet<string> = new Set<KnownError>([
  'secret_blocked', 'internal', 'git_internal', 'symlink_escape', 'outside_root', 'not_regular', 'stale', 'exists', 'too_large', 'not_text',
  'no_space', 'link_invalid', 'bad_name', 'not_found', 'cross_device', 'into_itself', 'too_many_tokens', 'too_many_transfers', 'permission',
]);

export function isKnownError(code: string): code is KnownError {
  return KNOWN.has(code);
}

// ---- diff -------------------------------------------------------------------------------------------------------

export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
  /** 1-based line numbers in the old and new text. */
  oldNo: number | null;
  newNo: number | null;
}

const MAX_MIDDLE = 1500;

/** A line diff. Common start and end are trimmed first; the changed middle is matched exactly when small. */
export function diffLines(before: string, after: string): DiffLine[] {
  const a = before === '' ? [] : before.split('\n');
  const b = after === '' ? [] : after.split('\n');
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const out: DiffLine[] = [];
  for (let i = 0; i < start; i++) out.push({ kind: 'same', text: a[i] ?? '', oldNo: i + 1, newNo: i + 1 });
  const ma = a.slice(start, endA);
  const mb = b.slice(start, endB);
  let oi = start + 1;
  let ni = start + 1;
  const del = (t: string) => out.push({ kind: 'del', text: t, oldNo: oi++, newNo: null });
  const add = (t: string) => out.push({ kind: 'add', text: t, oldNo: null, newNo: ni++ });
  const same = (t: string) => out.push({ kind: 'same', text: t, oldNo: oi++, newNo: ni++ });
  if (ma.length > MAX_MIDDLE || mb.length > MAX_MIDDLE) {
    ma.forEach(del);
    mb.forEach(add);
  } else {
    // Longest common subsequence of the middle.
    const n = ma.length;
    const m = mb.length;
    const w = m + 1;
    const lcs = new Uint32Array((n + 1) * w);
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        lcs[i * w + j] = ma[i] === mb[j] ? (lcs[(i + 1) * w + j + 1] ?? 0) + 1 : Math.max(lcs[(i + 1) * w + j] ?? 0, lcs[i * w + j + 1] ?? 0);
      }
    }
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (ma[i] === mb[j]) {
        same(ma[i] ?? '');
        i++;
        j++;
      } else if ((lcs[(i + 1) * w + j] ?? 0) >= (lcs[i * w + j + 1] ?? 0)) {
        del(ma[i] ?? '');
        i++;
      } else {
        add(mb[j] ?? '');
        j++;
      }
    }
    while (i < n) del(ma[i++] ?? '');
    while (j < m) add(mb[j++] ?? '');
  }
  for (let k = endA; k < a.length; k++) same(a[k] ?? '');
  return out;
}

export function diffStats(lines: DiffLine[]): { added: number; removed: number } {
  return { added: lines.filter((l) => l.kind === 'add').length, removed: lines.filter((l) => l.kind === 'del').length };
}

/** Keep changed lines with `context` lines around them; a gap becomes one marker line. */
export function collapseDiff(lines: DiffLine[], context = 3): (DiffLine | { kind: 'gap'; hidden: number })[] {
  const keep = new Array<boolean>(lines.length).fill(false);
  lines.forEach((l, i) => {
    if (l.kind !== 'same') for (let k = Math.max(0, i - context); k <= Math.min(lines.length - 1, i + context); k++) keep[k] = true;
  });
  const out: (DiffLine | { kind: 'gap'; hidden: number })[] = [];
  let hidden = 0;
  lines.forEach((l, i) => {
    if (keep[i]) {
      if (hidden > 0) out.push({ kind: 'gap', hidden });
      hidden = 0;
      out.push(l);
    } else hidden++;
  });
  if (hidden > 0) out.push({ kind: 'gap', hidden });
  return out;
}

/** Entries that can be selected, moved or downloaded: not blocked, not odd file types. */
export function usable(e: FileEntry): boolean {
  return !e.blocked && e.kind !== 'other';
}

export function entryIcon(e: FileEntry): 'folder' | 'image' | 'pdf' | 'text' | 'lock' | 'file' {
  if (e.blocked) return 'lock';
  if (e.kind === 'dir') return 'folder';
  const n = e.name.toLowerCase();
  if (/\.(png|jpe?g|gif|webp|bmp|ico)$/.test(n)) return 'image';
  if (n.endsWith('.pdf')) return 'pdf';
  if (/\.(txt|md|csv|json|ya?ml|toml|log|ts|tsx|js|jsx|rs|py|sh|html|css)$/.test(n)) return 'text';
  return 'file';
}
