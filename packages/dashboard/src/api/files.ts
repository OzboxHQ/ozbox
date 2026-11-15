import type { Transport, UploadHandle } from './transport';

export type { UploadHandle };

export type EntryKind = 'file' | 'dir' | 'other';

export interface FileEntry {
  name: string;
  path: string;
  kind: EntryKind;
  size: number;
  modified_ms: number;
  symlink: boolean;
  /** Why the box will not show or move this: a code such as `secret_blocked`. Absent for ordinary files. */
  blocked?: string;
}

export interface ListResponse {
  path: string;
  root: string;
  entries: FileEntry[];
  total: number;
  offset: number;
  limit: number;
  truncated: boolean;
}

export type PreviewKind = 'text' | 'image' | 'pdf' | 'binary';

export interface FilePreview {
  path: string;
  name: string;
  size: number;
  modified_ms: number;
  kind: PreviewKind;
  mime: string;
  editable: boolean;
  /** The content hash to send back when saving; null when the file is too large to edit. */
  hash: string | null;
  text?: string;
  truncated?: boolean;
}

export interface FilesRoots {
  /** What the box's answer is made of: `simulated` is a demo folder, never the box's own files. */
  source?: 'live' | 'simulated';
  roots: { label: string; path: string }[];
  limits: { max_upload: number; max_edit: number; max_zip: number; trash_days: number };
}

export interface TrashItem {
  id: string;
  original: string;
  name: string;
  kind: 'file' | 'dir';
  size: number;
  deleted_ms: number;
  expires_ms: number;
}

export interface ShareToken {
  id: string;
  label: string;
  kind: 'file' | 'zip';
  inline: boolean;
  created_ms: number;
  expires_ms: number;
  count: number;
}

export interface CreatedToken {
  id: string;
  token: string;
  expires_ms: number;
  kind: 'file' | 'zip';
  label: string;
}

export interface SearchHit {
  path: string;
  name: string;
  kind: EntryKind;
  size?: number;
  line?: number;
  snippet?: string;
}

export interface SearchResponse {
  results: SearchHit[];
  truncated: boolean;
  timed_out: boolean;
  visited: number;
}

export type SortKey = 'name' | 'size' | 'modified' | 'kind';

export interface ListOptions {
  sort?: SortKey;
  order?: 'asc' | 'desc';
  hidden?: boolean;
  offset?: number;
  limit?: number;
}

export interface UploadOptions {
  overwrite?: boolean;
  onProgress?: (loaded: number, total: number) => void;
}

export interface FilesApi {
  roots(box: string, signal?: AbortSignal): Promise<FilesRoots>;
  list(box: string, path: string, opts?: ListOptions, signal?: AbortSignal): Promise<ListResponse>;
  preview(box: string, path: string, signal?: AbortSignal): Promise<FilePreview>;
  /** `ifMatch` is the hash of the version the editor opened, or `none` for a new file. A stale one is refused with 409. */
  write(box: string, path: string, text: string, ifMatch: string, signal?: AbortSignal): Promise<{ hash: string; size: number }>;
  mkdir(box: string, path: string, signal?: AbortSignal): Promise<void>;
  rename(box: string, from: string, to: string, signal?: AbortSignal): Promise<{ path: string }>;
  remove(box: string, paths: string[], signal?: AbortSignal): Promise<{ deleted: { id: string; original: string }[]; failed: { path: string; code: string; message: string }[] }>;
  trash(box: string, signal?: AbortSignal): Promise<{ items: TrashItem[]; retention_days: number }>;
  restore(box: string, id: string, to?: string, signal?: AbortSignal): Promise<{ path: string }>;
  emptyTrash(box: string, ids?: string[], signal?: AbortSignal): Promise<{ removed: number }>;
  search(box: string, path: string, q: string, content: boolean, signal?: AbortSignal): Promise<SearchResponse>;
  createToken(box: string, paths: string[], ttlS: number, inline?: boolean, signal?: AbortSignal): Promise<CreatedToken>;
  tokens(box: string, signal?: AbortSignal): Promise<{ tokens: ShareToken[] }>;
  revokeToken(box: string, id: string, signal?: AbortSignal): Promise<void>;
  /** A URL a browser can follow with nothing else: the link is its own credential. */
  downloadUrl(box: string, token: string): string;
  /** Streams one file to the box. Progress is reported as bytes sent; `abort` stops it. */
  upload(box: string, dir: string, file: File, opts?: UploadOptions): UploadHandle;
}

const enc = encodeURIComponent;

/** The file browser's calls, over the dashboard's one transport. */
export function createFilesApi(tr: Transport): FilesApi {
  const call = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, body?: unknown, signal?: AbortSignal, raw?: string): Promise<T> =>
    raw !== undefined ? tr.requestText<T>(method, url, raw, signal) : tr.request<T>(method, url, body, signal);

  const f = (box: string, op: string) => `/v1/boxes/${enc(box)}/files/${op}`;
  const q = (params: Record<string, string | number | boolean | undefined>) =>
    Object.entries(params)
      .filter(([, v]) => v !== undefined && v !== false)
      .map(([k, v]) => `${enc(k)}=${enc(v === true ? '1' : String(v))}`)
      .join('&');

  return {
    roots: (b, s) => call('GET', f(b, 'roots'), undefined, s),
    list: (b, path, o = {}, s) =>
      call('GET', `${f(b, 'list')}?${q({ path, sort: o.sort, order: o.order, hidden: o.hidden, offset: o.offset, limit: o.limit })}`, undefined, s),
    preview: (b, path, s) => call('GET', `${f(b, 'preview')}?${q({ path })}`, undefined, s),
    write: (b, path, text, ifMatch, s) => call('PUT', `${f(b, 'write')}?${q({ path, if_match: ifMatch })}`, undefined, s, text),
    mkdir: async (b, path, s) => {
      await call('POST', f(b, 'mkdir'), { path }, s);
    },
    rename: (b, from, to, s) => call('POST', f(b, 'rename'), { from, to }, s),
    remove: (b, paths, s) => call('POST', f(b, 'delete'), { paths }, s),
    trash: (b, s) => call('GET', f(b, 'trash'), undefined, s),
    restore: (b, id, to, s) => call('POST', f(b, 'trash/restore'), to ? { id, to } : { id }, s),
    emptyTrash: (b, ids, s) => call('POST', f(b, 'trash/empty'), ids ? { ids } : {}, s),
    search: (b, path, qs, content, s) => call('GET', `${f(b, 'search')}?${q({ path, q: qs, content, limit: 100 })}`, undefined, s),
    createToken: (b, paths, ttlS, inline, s) => call('POST', f(b, 'tokens'), { paths, ttl_s: ttlS, inline: inline === true }, s),
    tokens: (b, s) => call('GET', f(b, 'tokens'), undefined, s),
    revokeToken: async (b, id, s) => {
      await call('DELETE', `${f(b, 'tokens')}/${enc(id)}`, undefined, s);
    },
    downloadUrl: (b, token) => tr.url(`/dl/${enc(b)}/${enc(token)}`),
    upload: (b, dir, file, o = {}) => tr.upload(`${f(b, 'upload')}?${q({ path: dir, name: file.name, overwrite: o.overwrite })}`, file, o.onProgress ? { onProgress: o.onProgress } : {}),
  };
}
