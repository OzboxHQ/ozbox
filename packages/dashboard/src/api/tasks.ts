// Agent runs ("tasks"): the board, one run, what a person can do to it, the approval requests agents raise, and the policy
// and spend limits. The shapes are the ones `/v1/tasks`, `/v1/approval-requests`, `/v1/approval-policy` and `/v1/spend-caps`
// answer with (see crates/ozbox-cli/src/serve/runs_routes.rs). Money is in US cents, time in seconds.

export type TaskState = 'queued' | 'running' | 'needs_you' | 'review' | 'done' | 'failed' | 'cancelled';

export const TASK_STATES: TaskState[] = ['queued', 'running', 'needs_you', 'review', 'done', 'failed', 'cancelled'];

export type Needs =
  | { kind: 'spend_cap' }
  | { kind: 'time_cap' }
  | { kind: 'token_cap' }
  | { kind: 'monthly_cap'; scope: string }
  | { kind: 'paused' }
  | { kind: 'approval'; approval_id: string };

export interface ResultLink {
  kind: string;
  label: string;
  url: string;
}

export type DeliverTo = 'pull_request' | 'alert';

export interface TaskCaps {
  max_runtime_s: number | null;
  max_spend_cents: number | null;
  max_tokens: number | null;
}

/** A provider (by its id in Settings -> Models) and one of its models. */
export interface ModelRef {
  provider_id: string;
  model: string;
}

/** The model a run uses. `fell_back_from` is set once the provider refused the run and it switched. */
export interface RunModel extends ModelRef {
  fallback: ModelRef | null;
  fell_back_from: ModelRef | null;
  fallback_reason: string | null;
}

/** Where the cost figure comes from: counted from tokens and the price table, or reported by the engine. */
export type CostSource = 'estimated' | 'reported';

export interface Task {
  id: string;
  state: TaskState;
  engine: string;
  box: string;
  repo: string | null;
  branch: string | null;
  skill: string | null;
  prompt: string;
  person: string;
  origin: { kind: 'manual' } | { kind: 'chat' } | { kind: 'schedule'; id: string } | { kind: 'trigger'; id: string };
  created_ms: number;
  started_ms: number | null;
  finished_ms: number | null;
  elapsed_s: number;
  spend_cents: number;
  cost_source?: CostSource | null;
  tokens: number;
  model?: RunModel | null;
  requested_model?: ModelRef | null;
  caps: TaskCaps;
  deliver_to: DeliverTo[];
  needs: Needs | null;
  queue_reason: string | null;
  wip_branch: string | null;
  links: ResultLink[];
  summary: string | null;
  error: string | null;
  retry_of: string | null;
  cancelling: boolean;
  /** A conversation: the agent stays open between messages. */
  interactive?: boolean;
  awaiting_input?: boolean;
  turns?: number;
  last_reply?: string | null;
  approval_id?: string;
  approvals?: ApprovalRequest[];
}

export interface TasksResponse {
  source: 'live' | 'simulated';
  rev: number;
  counts: Partial<Record<TaskState, number>>;
  items: Task[];
}

export interface NewTask {
  engine: string;
  prompt: string;
  box: string;
  skill?: string;
  repo?: string;
  branch?: string;
  caps?: { max_runtime_s?: number; max_spend_cents?: number; max_tokens?: number };
  deliver_to?: DeliverTo[];
  model?: ModelRef;
  dry_run?: boolean;
}

export interface NewTaskPreview {
  dry_run: true;
  would_queue: { engine: string; box: string; repo: string | null; branch: string | null; person: string; caps: Partial<TaskCaps>; deliver_to: DeliverTo[] };
  queued_ahead: number;
  note: string;
}

export interface TaskFilter {
  box?: string;
  engine?: string;
  person?: string;
  states?: TaskState[];
  since_ms?: number;
  until_ms?: number;
}

export type BulkAction = 'cancel' | 'retry' | 'review';

export interface BulkResult {
  results: { id: string; ok: boolean; result_id?: string; error?: string }[];
}

export type ActionKind = 'push_protected_branch' | 'open_pr_to_main' | 'ask_command' | 'outbound_message' | 'spend_above_threshold' | 'production_resource' | 'tool_call';

export const ACTION_KINDS: ActionKind[] = ['push_protected_branch', 'open_pr_to_main', 'ask_command', 'outbound_message', 'spend_above_threshold', 'production_resource'];

export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalRequest {
  id: string;
  task_id: string;
  kind: ActionKind;
  /** The exact action, as the agent will run it. */
  action: string;
  box: string;
  asked_by: string;
  production: boolean;
  needs_step_up: boolean;
  state: ApprovalState;
  created_ms: number;
  expires_ms: number;
  expires_in_s: number;
  decided_by: string | null;
  decided_ms: number | null;
  decided_with_step_up: boolean;
  can_decide: boolean;
}

export interface ApprovalPolicy {
  ask: ActionKind[];
  protected_branches: string[];
  ask_commands: string[];
  spend_threshold_cents: number | null;
  expiry_s: number;
  approvers: string[];
  allow_requester: boolean;
  step_up: ActionKind[];
}

export interface SpendCaps {
  fleet_monthly_cents: number | null;
  person_monthly_cents: number | null;
  per_person: Record<string, number>;
}

export interface SpendLedger {
  month: string;
  fleet_cents: number;
  by_person: Record<string, number>;
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

function query(f: TaskFilter): string {
  const q = new URLSearchParams();
  if (f.box) q.set('box', f.box);
  if (f.engine) q.set('engine', f.engine);
  if (f.person) q.set('person', f.person);
  if (f.states && f.states.length > 0) q.set('state', f.states.join(','));
  if (f.since_ms !== undefined) q.set('since_ms', String(f.since_ms));
  if (f.until_ms !== undefined) q.set('until_ms', String(f.until_ms));
  const s = q.toString();
  return s ? `?${s}` : '';
}

export function createTasksApi(request: Req) {
  const id = (x: string) => encodeURIComponent(x);
  return {
    list: (f: TaskFilter = {}, s?: AbortSignal) => request<TasksResponse>('GET', `/v1/tasks${query(f)}`, undefined, s),
    get: (taskId: string, s?: AbortSignal) => request<Task>('GET', `/v1/tasks/${id(taskId)}`, undefined, s),
    logs: (taskId: string, s?: AbortSignal) => request<{ id: string; lines: string[] }>('GET', `/v1/tasks/${id(taskId)}/logs`, undefined, s),
    preview: (b: NewTask, s?: AbortSignal) => request<NewTaskPreview>('POST', '/v1/tasks', { ...b, dry_run: true }, s),
    start: (b: NewTask, s?: AbortSignal) => request<{ id: string; state: TaskState; created: boolean }>('POST', '/v1/tasks', b, s),
    cancel: (taskId: string) => request<{ id: string }>('POST', `/v1/tasks/${id(taskId)}/cancel`),
    retry: (taskId: string) => request<{ id: string; retry_of: string }>('POST', `/v1/tasks/${id(taskId)}/retry`),
    review: (taskId: string) => request<{ id: string }>('POST', `/v1/tasks/${id(taskId)}/review`),
    accept: (taskId: string) => request<{ id: string }>('POST', `/v1/tasks/${id(taskId)}/accept`),
    resume: (taskId: string, add: { add_cents?: number; add_minutes?: number; add_tokens?: number }) => request<{ id: string }>('POST', `/v1/tasks/${id(taskId)}/resume`, add),
    bulk: (action: BulkAction, ids: string[]) => request<BulkResult>('POST', '/v1/tasks/bulk', { action, ids }),
    approvals: (all = false, s?: AbortSignal) => request<{ source: string; items: ApprovalRequest[] }>('GET', `/v1/approval-requests${all ? '?state=all' : ''}`, undefined, s),
    approve: (approvalId: string) => request<{ id: string; state: ApprovalState }>('POST', `/v1/approval-requests/${id(approvalId)}/approve`),
    deny: (approvalId: string) => request<{ id: string; state: ApprovalState }>('POST', `/v1/approval-requests/${id(approvalId)}/deny`),
    policy: (s?: AbortSignal) => request<ApprovalPolicy>('GET', '/v1/approval-policy', undefined, s),
    savePolicy: (p: ApprovalPolicy) => request<ApprovalPolicy>('PUT', '/v1/approval-policy', p),
    caps: (s?: AbortSignal) => request<{ caps: SpendCaps; ledger: SpendLedger }>('GET', '/v1/spend-caps', undefined, s),
    saveCaps: (c: SpendCaps) => request<{ caps: SpendCaps }>('PUT', '/v1/spend-caps', c),
  };
}

export type TasksApi = ReturnType<typeof createTasksApi>;
