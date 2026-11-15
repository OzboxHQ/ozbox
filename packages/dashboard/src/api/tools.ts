// The tool catalog, a box's tools, install jobs, agent requests and box profiles (see crates/ozbox-catalog and ozboxd).

export type Verification =
  | 'apt_archive'
  | 'apt_key_fingerprint'
  | 'vendor_checksum'
  | 'registry_integrity'
  | 'client_managed'
  | 'unverified';

export interface CatalogTool {
  id: string;
  name: string;
  group: string;
  description: string;
  homepage: string;
  source: string;
  verified: boolean;
  default?: boolean;
  unverified_reason?: string | null;
  verification: Verification;
  size_mb: number;
  updates: { how: 'self_update' | 'apt' | 'manual' | 'client'; detail: string };
  requires: string[];
  post_install?: string | null;
}

export interface Catalog {
  schema: number;
  version: string;
  groups: { id: string; name: string }[];
  bundles: { id: string; name: string; description: string; tools: string[] }[];
  tools: CatalogTool[];
}

export interface ToolState {
  id: string;
  installed: boolean;
  version: string | null;
  managed_by_client: boolean;
}

export interface BoxTools {
  /** `simulated` when the server made the tools up (the demo); `live` for a real box. */
  source: 'live' | 'simulated';
  catalog_version: string;
  arch: string;
  tools: ToolState[];
  active_job: string | null;
  /** Tools chosen when the box was created, waiting to be installed. */
  pending: string[];
}

export interface ToolSelection {
  install?: string[];
  remove?: string[];
}

export interface PlanTool {
  id: string;
  name: string;
  op: 'install' | 'remove';
  size_mb: number;
  reason: string;
  post_install: string | null;
}

export interface ToolPlanStep {
  index: number;
  tool: string;
  op: 'install' | 'remove';
  title: string;
  privilege: 'root' | 'user';
}

export interface ToolPlan {
  catalog_version: string;
  arch: string;
  tools: PlanTool[];
  steps: ToolPlanStep[];
  already_installed: string[];
  not_installed: string[];
  total_size_mb: number;
  needs_root: boolean;
  hash: string;
}

export type JobState = 'queued' | 'running' | 'succeeded' | 'failed';

export interface JobStep {
  index: number;
  title: string;
  state: 'pending' | 'running' | 'ok' | 'failed';
}

export interface ToolJob {
  job: { id: string; state: JobState; steps: JobStep[]; error: string | null; started_ms: number | null; ended_ms: number | null };
  tools: PlanTool[] | null;
  requested_by: string | null;
  log: string[];
  source?: 'live' | 'simulated';
}

export interface ToolRequest {
  id: string;
  tool: string;
  reason: string;
  requested_by: string;
  created_ms: number;
  state: 'pending' | 'approved' | 'denied';
  decision: string | null;
  job_id: string | null;
}

export type Decision = 'approve_once' | 'approve_always' | 'deny';

export interface ProfileBox {
  size?: string;
  disk_gb?: number;
  auto_pause_minutes?: number;
  always_on?: boolean;
  labels?: Record<string, string>;
}

export interface BoxProfile {
  name: string;
  description?: string | null;
  tools: string[];
  box?: ProfileBox;
  /** Present when the file could not be used: what is wrong with it. */
  error?: string;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface ToolsApi {
  catalog(signal?: AbortSignal): Promise<Catalog>;
  box(name: string, signal?: AbortSignal): Promise<BoxTools>;
  /** Never changes anything. */
  plan(name: string, selection: ToolSelection, signal?: AbortSignal): Promise<ToolPlan>;
  /** Applies the plan whose hash is given; the box refuses one that has gone stale. */
  apply(name: string, selection: ToolSelection, planHash: string, signal?: AbortSignal): Promise<{ job_id: string | null; noop?: boolean }>;
  job(name: string, id: string, signal?: AbortSignal): Promise<ToolJob>;
  requests(name: string, signal?: AbortSignal): Promise<{ requests: ToolRequest[]; always_allowed: string[] }>;
  decide(name: string, id: string, decision: Decision, signal?: AbortSignal): Promise<ToolRequest>;
  setPending(name: string, tools: string[], signal?: AbortSignal): Promise<string[]>;
  clearPending(name: string, signal?: AbortSignal): Promise<void>;
  profiles(signal?: AbortSignal): Promise<BoxProfile[]>;
  saveProfile(body: { name: string; from_box: string; description?: string; overwrite?: boolean }, signal?: AbortSignal): Promise<BoxProfile>;
  deleteProfile(name: string, signal?: AbortSignal): Promise<void>;
}

export function createToolsApi(request: Request): ToolsApi {
  const box = (n: string) => `/v1/boxes/${encodeURIComponent(n)}/tools`;
  return {
    catalog: async (s) => (await request<{ catalog: Catalog }>('GET', '/v1/catalog', undefined, s)).catalog,
    box: (n, s) => request('GET', box(n), undefined, s),
    plan: async (n, sel, s) => (await request<{ plan: ToolPlan }>('POST', `${box(n)}/plan`, sel, s)).plan,
    apply: (n, sel, hash, s) => request('POST', `${box(n)}/apply`, { ...sel, plan_hash: hash }, s),
    job: (n, id, s) => request('GET', `${box(n)}/jobs/${encodeURIComponent(id)}`, undefined, s),
    requests: (n, s) => request('GET', `${box(n)}/requests`, undefined, s),
    decide: async (n, id, decision, s) =>
      (await request<{ request: ToolRequest }>('POST', `${box(n)}/requests/${encodeURIComponent(id)}/decision`, { decision }, s)).request,
    setPending: async (n, tools, s) => (await request<{ pending: string[] }>('PUT', `${box(n)}/pending`, { tools }, s)).pending,
    clearPending: async (n, s) => {
      await request('DELETE', `${box(n)}/pending`, undefined, s);
    },
    profiles: async (s) => (await request<{ profiles: BoxProfile[] }>('GET', '/v1/profiles', undefined, s)).profiles,
    saveProfile: async (b, s) => (await request<{ profile: BoxProfile }>('POST', '/v1/profiles', b, s)).profile,
    deleteProfile: async (name, s) => {
      await request('DELETE', `/v1/profiles/${encodeURIComponent(name)}`, undefined, s);
    },
  };
}
