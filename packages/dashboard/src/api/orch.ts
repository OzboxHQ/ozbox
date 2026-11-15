import type { MetricsSource } from './types';

// Orchestrations: one agent (the conductor) hands features to worker boxes. The shapes are the ones `/v1/orchestrations`
// answers with (see crates/ozbox-cli/src/serve/orch_routes.rs). Money is in US cents, time in milliseconds.

export type OrchState = 'active' | 'paused' | 'done' | 'stopped';

export type FeatureState = 'planned' | 'starting' | 'working' | 'blocked' | 'ready_to_merge' | 'in_queue' | 'merged' | 'conflict_returned' | 'paused' | 'stopped' | 'failed';

export type MergeState = 'waiting' | 'rebasing' | 'testing' | 'awaiting_approval' | 'merging' | 'merged' | 'conflict' | 'tests_failed' | 'failed';

export interface OrchSummary {
  id: string;
  goal: string;
  state: OrchState;
  paused_reason: string | null;
  conductor_box: string;
  requested_by: string;
  spent_cents: number;
  cap_cents: number | null;
  features: number;
  open_features: number;
  needs_you: boolean;
  updated_ms: number;
}

export interface OrchFeature {
  id: string;
  title: string;
  state: FeatureState;
  box: string;
  branch: string;
  claims: string[];
  contracts: { id: string; version: number }[];
  after: string[];
  engine: string;
  model: string | null;
  sub_agents: number;
  task_id: string | null;
  task_state: string | null;
  spent_cents: number;
  wip_branch: string | null;
  blocked_on: number | null;
  keep: boolean;
}

export interface OrchMessage {
  seq: number;
  ts_ms: number;
  from: string;
  to: string;
  kind: 'question' | 'answer' | 'status' | 'contract_changed' | 'blocked' | 'approval' | 'instruction' | 'note';
  feature: string | null;
  text: string;
  resolved: boolean;
  needs_person: boolean;
}

export interface OrchContract {
  id: string;
  name: string;
  kind: string;
  version: number;
  agreed: boolean;
  paths: string[];
}

export interface MergeEntry {
  feature_id: string;
  queued_ms: number;
  state: MergeState;
  detail: string;
  approval_id: string | null;
}

export interface OrchApproval {
  id: string;
  kind: string;
  action: string;
  box: string;
  needs_person: boolean;
  needs_step_up: boolean;
  expires_in_s: number;
}

export interface OrchPolicy {
  max_workers: number;
  max_sub_agents: number;
  spend_cap_cents: number | null;
  merge_approval: 'none' | 'conductor' | 'person';
  test_command: string[];
  base_branch: string;
  notes: string[];
}

export interface Orch extends Omit<OrchSummary, 'features' | 'open_features' | 'needs_you'> {
  conductor_task: string | null;
  created_ms: number;
  policy: OrchPolicy;
  features: OrchFeature[];
  contracts: OrchContract[];
  messages: OrchMessage[];
  open_questions: OrchMessage[];
  merge_queue: MergeEntry[];
  approvals: OrchApproval[];
  spare_boxes: string[];
}

export interface NewOrch {
  goal: string;
  conductor_box: string;
  rules?: string;
  max_workers?: number;
  max_sub_agents?: number;
  max_spend_usd?: number;
  start_conductor?: boolean;
}

export interface McpToken {
  url: string;
  token: string;
  expires_in_s: number;
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createOrchApi(request: Req) {
  const id = (x: string) => encodeURIComponent(x);
  return {
    list: (s?: AbortSignal) => request<{ source: MetricsSource; rev: number; items: OrchSummary[] }>('GET', '/v1/orchestrations', undefined, s),
    get: (orchId: string, s?: AbortSignal) => request<Orch>('GET', `/v1/orchestrations/${id(orchId)}`, undefined, s),
    start: (b: NewOrch) => request<{ id: string; conductor_task: string | null }>('POST', '/v1/orchestrations', b),
    pause: (orchId: string) => request<{ id: string }>('POST', `/v1/orchestrations/${id(orchId)}/pause`),
    resume: (orchId: string) => request<{ id: string }>('POST', `/v1/orchestrations/${id(orchId)}/resume`),
    stop: (orchId: string) => request<{ id: string }>('POST', `/v1/orchestrations/${id(orchId)}/stop`),
    addBudget: (orchId: string, addUsd: number) => request<{ cap_cents: number }>('POST', `/v1/orchestrations/${id(orchId)}/budget`, { add_usd: addUsd }),
    feature: (orchId: string, featureId: string, verb: 'pause' | 'resume' | 'stop') => request<{ feature: string }>('POST', `/v1/orchestrations/${id(orchId)}/features/${id(featureId)}/${verb}`),
    reassign: (orchId: string, featureId: string, box: string) => request<{ feature: string }>('POST', `/v1/orchestrations/${id(orchId)}/features/${id(featureId)}/reassign`, { box }),
    answer: (orchId: string, question: number, text: string) => request<{ answered: number }>('POST', `/v1/orchestrations/${id(orchId)}/answer`, { question, text }),
    message: (orchId: string, feature: string, text: string) => request<{ message: number }>('POST', `/v1/orchestrations/${id(orchId)}/message`, { feature, text }),
    queue: (orchId: string, featureId: string) => request<{ position: number }>('POST', `/v1/orchestrations/${id(orchId)}/merge/${id(featureId)}`),
    token: () => request<McpToken>('POST', '/v1/orchestrations/mcp-token'),
  };
}

export type OrchApi = ReturnType<typeof createOrchApi>;
