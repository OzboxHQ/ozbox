// Agent memory and reviewed skills. The shapes are the ones `/v1/memory` and `/v1/skills` answer with (see
// crates/ozbox-cli/src/serve/memory_routes.rs). Times are milliseconds since the Unix epoch.

export type NoteState = 'pending' | 'approved';

export interface MemNote {
  id: string;
  scope: string;
  title: string;
  body: string;
  tags: string[];
  state: NoteState;
  created_ms: number;
  updated_ms: number;
  expires_ms: number | null;
  expired: boolean;
  revision: number;
  written_by: string;
  by_agent: boolean;
  run: string | null;
  reviewed_by: string | null;
  reviewed_ms: number | null;
}

/** Where the notes and skills are kept, as the server says it. A server older than this field sends none. */
export interface StoreInfo {
  /** False when there was no settings file to sit beside: the folder is this server run's own and is forgotten when it stops. */
  persisted: boolean;
  /** Whether the server runs on a box, and that box's name. */
  on_a_box: boolean;
  host: string | null;
}

export interface MemList {
  notes: MemNote[];
  stats: { total: number; pending: number; approved: number; expired: number };
  person: string;
  store?: StoreInfo;
}

export interface NewNote {
  scope: string;
  title: string;
  body: string;
  tags?: string[];
  expires_days?: number;
}

export interface EditNote {
  title?: string;
  body?: string;
  tags?: string[];
  /** Days from now; `null` clears the expiry. */
  expires_days?: number | null;
}

export type InstallStatus = 'approved' | 'needs_review' | 'modified';

export interface SkillInstall {
  scope: string;
  hash: string;
  source: string;
  status: InstallStatus;
  installed_by: string;
  installed_ms: number;
  update_available: boolean;
}

export interface SkillItem {
  name: string;
  description: string;
  version: string;
  hash: string;
  source: 'bundled' | 'library' | 'removed';
  files: { path: string; bytes: number }[];
  approved: boolean;
  installs: SkillInstall[];
}

export interface SkillReview {
  name: string;
  description: string;
  version: string;
  hash: string;
  approved: boolean;
  files: { path: string; text: string }[];
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createMemoryApi(request: Req) {
  const id = (x: string) => encodeURIComponent(x);
  return {
    list: (q: { q?: string; scope?: string; state?: NoteState | 'all' }, s?: AbortSignal) => {
      const p = new URLSearchParams();
      if (q.q) p.set('q', q.q);
      if (q.scope) p.set('scope', q.scope);
      if (q.state && q.state !== 'all') p.set('state', q.state);
      const qs = p.toString();
      return request<MemList>('GET', `/v1/memory${qs ? `?${qs}` : ''}`, undefined, s);
    },
    add: (b: NewNote) => request<MemNote>('POST', '/v1/memory', b),
    edit: (noteId: string, b: EditNote) => request<MemNote>('PUT', `/v1/memory/${id(noteId)}`, b),
    approve: (noteId: string) => request<MemNote>('POST', `/v1/memory/${id(noteId)}/approve`),
    forget: (noteId: string) => request<{ forgotten: string }>('DELETE', `/v1/memory/${id(noteId)}`),
    skills: (s?: AbortSignal) => request<{ skills: SkillItem[]; store?: StoreInfo }>('GET', '/v1/skills', undefined, s),
    review: (name: string, s?: AbortSignal) => request<SkillReview>('GET', `/v1/skills/${id(name)}/review`, undefined, s),
    install: (name: string, scope: string) => request<SkillInstall>('POST', `/v1/skills/${id(name)}/install`, { scope }),
    uninstall: (name: string, scope: string) => request<{ removed: string }>('POST', `/v1/skills/${id(name)}/uninstall`, { scope }),
    approveSkill: (name: string, hash: string) => request<{ approved: string }>('POST', `/v1/skills/${id(name)}/approve`, { hash }),
    revoke: (name: string) => request<{ revoked: string }>('POST', `/v1/skills/${id(name)}/revoke`),
  };
}

export type MemoryApi = ReturnType<typeof createMemoryApi>;
