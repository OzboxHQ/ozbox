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
  /** The folder on that computer that holds the notes and skills. A server older than this field sends none. */
  folder?: string;
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

export type FileKind = 'instructions' | 'script' | 'text';

export interface SkillFileInfo {
  path: string;
  bytes: number;
  kind: FileKind;
}

/** Where a skill came from. `via` is how a person's own skill got into the library. */
export interface Provenance {
  origin: 'bundled' | 'library' | 'removed';
  by?: string;
  via?: 'page_upload' | 'page_editor' | 'cli' | 'restore' | 'folder';
  ms?: number;
}

/** What was last recorded when a skill was put on a box; the box's own answer (`BoxHoldings`) is the truth. */
export interface SkillPush {
  box_name: string;
  hash: string;
  agents: string[];
  pushed_by: string;
  pushed_ms: number;
  matches_library: boolean;
}

export interface SkillItem {
  name: string;
  description: string;
  version: string;
  license?: string;
  hash: string;
  source: 'bundled' | 'library' | 'removed';
  files: SkillFileInfo[];
  approved: boolean;
  /** What it asks an agent program to do that needs acknowledging (`SkillAskKey`s); empty for a plain skill. */
  asks: SkillAskKey[];
  installs: SkillInstall[];
  provenance: Provenance;
  shadows_bundled: boolean;
  pushes: SkillPush[];
  /** Earlier versions of a skill of your own, kept so they can be read and restored. */
  revisions: number;
}

/** What a skill asks an agent program to do that needs its own acknowledgement. */
export type SkillAskKey = 'hooks' | 'allowed-tools' | 'shell' | 'agent' | 'shell-injection';

export interface SkillAsks {
  /** Commands it runs or permissions it widens: each must be acknowledged before the skill can be approved. */
  acknowledge: { key: SkillAskKey; detail: string[] }[];
  /** Other documented settings it declares, as `[field, value]`. */
  shown: [string, string][];
  /** Fields in its front matter that nothing this page knows reads. */
  unknown: string[];
}

export interface SkillReview {
  name: string;
  description: string;
  version: string;
  hash: string;
  approved: boolean;
  asks: SkillAsks;
  provenance: Provenance;
  files: { path: string; text: string; kind: FileKind }[];
}

export interface SkillRevision {
  hash: string;
  version: string;
  by: string;
  via: string;
  ms: number;
  current: boolean;
  approved: boolean;
}

/** One folder a box's coding agents read skills from. */
export interface BoxAgentFolder {
  id: string;
  label: string;
  reaches: string;
  folder: string;
  present: boolean;
}

export type HoldState = 'intact' | 'modified' | 'missing';

export interface BoxHold {
  agent: string;
  /** Read from the box's disk against the box's own record. */
  state: HoldState;
  /** What the box's record says was put there. The box user can edit that record; `origin` is not taken from it. */
  hash: string;
  /** What the files on the box's disk hash to now, when they can be read. */
  disk_hash: string | null;
  /** `dashboard` only when this dashboard's own push record names the same hash; anything else is `box`: put there on the box. */
  origin: 'dashboard' | 'box';
  /** The box's files are exactly the library's current ones. `null` when the library no longer has the skill. */
  matches_library: boolean | null;
}

export interface BoxSkills {
  box: string;
  /** `ok`, or why it is not known: `stopped` and `unreachable` are never read as "holds nothing". */
  state: 'ok' | 'stopped' | 'unreachable';
  /** Whether this dashboard can put a skill on the box's disk or take one off. Only a dashboard on the box can; another one only reads. */
  can_write?: boolean;
  reason?: string;
  code?: string | null;
  agents?: BoxAgentFolder[];
  skills?: { name: string; in_library: boolean; places: BoxHold[] }[];
  /** Skills in those folders that Oz Box did not put there, by folder. */
  others?: Record<string, string[]>;
  source?: 'live' | 'simulated';
}

export interface AddSkillBody {
  files: Record<string, string>;
  /** The hash of the library's skill of this name the page was looking at, when replacing it. */
  replaces?: string;
  shadow_bundled?: boolean;
  via?: 'page_upload' | 'page_editor';
}

export interface PushResult {
  ok: boolean;
  name: string;
  hash: string;
  results: { agent: string; ok: boolean; code?: string; message?: string }[];
  source?: 'live' | 'simulated';
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
    skills: (s?: AbortSignal) => request<{ skills: SkillItem[]; unreadable?: { name: string; reason: string }[]; store?: StoreInfo }>('GET', '/v1/skills', undefined, s),
    review: (name: string, s?: AbortSignal, hash?: string) => request<SkillReview>('GET', `/v1/skills/${id(name)}/review${hash ? `?hash=${id(hash)}` : ''}`, undefined, s),
    install: (name: string, scope: string) => request<SkillInstall>('POST', `/v1/skills/${id(name)}/install`, { scope }),
    uninstall: (name: string, scope: string) => request<{ removed: string }>('POST', `/v1/skills/${id(name)}/uninstall`, { scope }),
    approveSkill: (name: string, hash: string, acknowledged: string[] = []) =>
      request<{ approved: string }>('POST', `/v1/skills/${id(name)}/approve`, { hash, acknowledged }),
    revoke: (name: string) => request<{ revoked: string }>('POST', `/v1/skills/${id(name)}/revoke`),
    addSkill: (b: AddSkillBody) => request<SkillItem>('POST', '/v1/skills', b),
    deleteSkill: (name: string) => request<{ removed: string }>('DELETE', `/v1/skills/${id(name)}`),
    skillHistory: (name: string, s?: AbortSignal) => request<{ revisions: SkillRevision[] }>('GET', `/v1/skills/${id(name)}/history`, undefined, s),
    restoreSkill: (name: string, hash: string) => request<SkillItem>('POST', `/v1/skills/${id(name)}/restore`, { hash }),
    holdings: (s?: AbortSignal) => request<{ boxes: BoxSkills[]; source: 'live' | 'simulated' }>('GET', '/v1/skills/holdings', undefined, s),
    pushSkill: (box: string, name: string, hash: string, agents?: string[]) =>
      request<PushResult>('PUT', `/v1/boxes/${id(box)}/skills/${id(name)}`, { hash, ...(agents ? { agents } : {}) }),
    pullSkill: (box: string, name: string) => request<{ ok: boolean }>('DELETE', `/v1/boxes/${id(box)}/skills/${id(name)}`),
  };
}

export type MemoryApi = ReturnType<typeof createMemoryApi>;
