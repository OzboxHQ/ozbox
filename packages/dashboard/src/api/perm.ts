// Permissions and the audit log: modes, rules, time-boxed Production grants, and the tamper-evident chain. The shapes are
// the ones `/v1/permissions` and `/v1/audit` answer with (see crates/ozbox-cli/src/serve/perm_routes.rs). Times are
// milliseconds since the epoch.

export type Mode = 'ask' | 'plan_only' | 'accept_edits' | 'auto';
export const MODES: Mode[] = ['ask', 'plan_only', 'accept_edits', 'auto'];

export type Effect = 'allow' | 'ask' | 'deny';
export const EFFECTS: Effect[] = ['allow', 'ask', 'deny'];

export type Scope = 'person' | 'box' | 'project' | 'orchestration' | 'run';
export const SCOPES: Scope[] = ['person', 'box', 'project', 'orchestration', 'run'];
/** What a Production grant may be bound to: never everything. */
export const GRANT_SCOPES: Scope[] = ['box', 'project', 'orchestration', 'run'];

export type Environment = 'sandbox' | 'staging' | 'production';
export const ENVIRONMENTS: Environment[] = ['sandbox', 'staging', 'production'];

export interface Rule {
  id: string;
  effect: Effect;
  action: string;
  scope: Scope;
  scope_id: string | null;
  path: string | null;
  command: string | null;
  env: Environment | null;
  tool: string | null;
  server: string | null;
  note: string;
}

export interface ModeSetting {
  scope: Scope;
  scope_id: string | null;
  mode: Mode;
}

export interface PermSettings {
  default_mode: Mode;
  modes: ModeSetting[];
  rules: Rule[];
  /** Hosts the browser tools may fetch besides the box's own localhost. */
  browser_hosts: string[];
}

export type ToolWrites = 'read' | 'write' | 'depends';

export interface HostTool {
  name: string;
  server: string;
  writes: ToolWrites;
  summary: string;
  effect: Effect;
  reason: string;
  rule: string | null;
}

export interface HostToolsView {
  env: Environment;
  mode: Mode;
  tools: HostTool[];
}

export type GrantState = 'active' | 'expired' | 'revoked' | 'used';
export type SecondFactor = 'step_up' | 'typed_confirmation' | 'no_sign_in';

export interface Grant {
  id: string;
  granted_by: string;
  scope: Scope;
  scope_id: string;
  actions: string[];
  reason: string;
  created_ms: number;
  expires_ms: number;
  factor: SecondFactor;
  factor_is_real: boolean;
  allow_unattended: boolean;
  max_uses: number | null;
  uses: number;
  revoked_ms: number | null;
  revoked_by: string | null;
  state: GrantState;
}

export interface PermView {
  source: string;
  settings: PermSettings;
  grants: Grant[];
  now_ms: number;
  max_grant_minutes: number;
  /** Behind a sign-in: a grant needs a passkey. Signed out: it needs the name typed back. */
  signed_in: boolean;
  actions: string[];
}

export interface NewGrantBody {
  scope: Scope;
  scope_id: string;
  actions: string[];
  reason: string;
  minutes: number;
  allow_unattended: boolean;
  max_uses?: number;
  confirm?: string;
}

export interface AuditEntry {
  seq: number;
  ts_ms: number;
  actor: string;
  action: string;
  subject: string | null;
  detail: string;
  prev: string;
  hash: string;
}

export interface AuditList {
  source: string;
  entries: AuditEntry[];
  total: number;
  head_seq: number;
  head_hash: string;
}

export interface VerifyReport {
  ok: boolean;
  entries: number;
  checkpoints: number;
  head_seq: number;
  head_hash: string;
  altered: number[];
  deleted: { after_seq: number; before_seq: number }[];
  out_of_order: number[];
  bad_seals: number[];
  truncated: { sealed_seq: number; last_seq: number } | null;
  unreadable_lines: number[];
  unsealed_tail: number;
  seals_checked: boolean;
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createPermApi(request: Req) {
  return {
    view: (s?: AbortSignal) => request<PermView>('GET', '/v1/permissions', undefined, s),
    save: (settings: PermSettings) => request<{ settings: PermSettings }>('PUT', '/v1/permissions', settings),
    grant: (b: NewGrantBody) => request<Grant>('POST', '/v1/permissions/grants', b),
    revoke: (id: string) => request<{ id: string }>('POST', `/v1/permissions/grants/${encodeURIComponent(id)}/revoke`, {}),
    audit: (limit: number, action: string, s?: AbortSignal) =>
      request<AuditList>('GET', `/v1/audit?limit=${limit}${action ? `&action=${encodeURIComponent(action)}` : ''}`, undefined, s),
    hostTools: (env: Environment, s?: AbortSignal) => request<HostToolsView>('GET', `/v1/host-tools?env=${env}`, undefined, s),
    verify: (s?: AbortSignal) => request<{ checked_ms: number; report: VerifyReport }>('GET', '/v1/audit/verify', undefined, s),
    seal: () => request<{ sealed: boolean }>('POST', '/v1/audit/seal', {}),
  };
}

export type PermApi = ReturnType<typeof createPermApi>;
