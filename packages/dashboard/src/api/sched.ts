import type { MetricsSource } from './types';

// Schedules and triggers: scheduled agent runs in the person's own time zone, and signed inbound webhooks. A trigger's
// secret is returned once, when it is made, and never again; nothing here can read one back.

export interface WhenInstant {
  ms: number;
  /** In the schedule's own time zone, with UTC beside it: `2026-11-09 09:00 WAT (08:00 UTC)`. */
  local: string;
  utc: string;
}

export type When = { kind: 'cron'; expr: string } | { kind: 'every'; minutes: number };

export interface Target {
  box_name: string | null;
  profile: string | null;
}

export interface Caps {
  max_spend_cents: number | null;
  max_minutes: number | null;
}

export type RunStatus = 'starting' | 'running' | 'succeeded' | 'failed' | 'skipped' | 'missed';

export interface SchedRun {
  id: string;
  owner_id: string;
  name?: string | null;
  /** `schedule`, `manual` or `trigger`. */
  source: string;
  slot_ms: number | null;
  started_ms: number;
  finished_ms: number | null;
  status: RunStatus;
  detail: string;
  /** A reason code the dashboard words itself (`overlap`, `missed`, `caught_up`, ...). */
  reason: string;
  args: Record<string, string>;
  box_name: string | null;
  woke_box: boolean;
  cost: number | null;
  result_url: string | null;
}

export interface WakeCost {
  currency: string | null;
  per_run: number;
  per_month: number;
  runs_per_month: number;
  avg_run_minutes: number;
  auto_pause_minutes: number;
  estimate: true;
}

export interface ScheduleItem {
  id: string;
  name: string;
  when: When;
  plain: string | null;
  time_zone: string;
  owner: string;
  engine: string;
  prompt: string | null;
  skill: string | null;
  target: Target;
  caps: Caps;
  results_to: string[];
  catch_up_minutes: number;
  enabled: boolean;
  heartbeat: boolean;
  next: WhenInstant | null;
  last_run: SchedRun | null;
  running: boolean;
  cost: WakeCost | null;
}

export interface SchedulesResponse {
  schedules: ScheduleItem[];
  lease: { holder_is_me: boolean; epoch: number; expires_ms: number } | null;
  time_zone: string;
  now_ms: number;
  run_system_connected: boolean;
  /** `simulated` when this server is a demo: a run it starts uses the demo agent. */
  source: MetricsSource;
  catch_up_default_minutes: number;
}

export interface SchedulePreview {
  cron: string;
  time_zone: string;
  next: WhenInstant[];
}

export interface ScheduleInput {
  name: string;
  when_text?: string;
  cron?: string;
  every_minutes?: number;
  time_zone?: string;
  owner?: string;
  engine: string;
  prompt?: string;
  skill?: string;
  target: Target;
  caps: Caps;
  results_to: string[];
  catch_up_minutes?: number;
  enabled?: boolean;
  heartbeat?: boolean;
}

export type Scheme = 'github' | 'generic' | 'stripe';

export interface Delivery {
  id: string;
  trigger_id: string;
  ts_ms: number;
  /** `accepted`, `refused`, `ignored` or `test`. */
  outcome: string;
  /** `bad_signature`, `expired`, `replayed`, `too_large`, ... */
  reason: string;
  delivery_id: string | null;
  event: string | null;
  size: number;
  run_id: string | null;
}

export interface TriggerItem {
  id: string;
  name: string;
  scheme: Scheme;
  engine: string;
  template: string;
  skill: string | null;
  target: Target;
  caps: Caps;
  results_to: string[];
  events: string[];
  enabled: boolean;
  owner: string;
  path: string;
  url: string | null;
  secret_set: boolean;
  last_delivery: Delivery | null;
  /** After a rotation the old secret still works until this time (ms since the epoch). */
  previous_secret_until_ms?: number | null;
  /** Present once: in the answer to the request that made the trigger, or that rotated its secret. */
  secret?: string;
}

export interface TriggersResponse {
  triggers: TriggerItem[];
  public_url_set: boolean;
  max_body_bytes: number;
  /** `simulated` when this server is a demo: a run it starts uses the demo agent. */
  source: MetricsSource;
}

export interface TriggerInput {
  name: string;
  scheme: Scheme;
  engine: string;
  template: string;
  skill?: string;
  target: Target;
  caps: Caps;
  results_to: string[];
  events: string[];
}

export interface TestResult {
  ok: boolean;
  verified: boolean;
  scheme: Scheme;
  prompt_preview: string;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface SchedApi {
  list(signal?: AbortSignal): Promise<SchedulesResponse>;
  preview(input: { when_text?: string; cron?: string; time_zone?: string; owner?: string }, signal?: AbortSignal): Promise<SchedulePreview>;
  create(input: ScheduleInput, signal?: AbortSignal): Promise<ScheduleItem>;
  update(id: string, input: Partial<ScheduleInput>, signal?: AbortSignal): Promise<ScheduleItem>;
  setEnabled(id: string, on: boolean, signal?: AbortSignal): Promise<ScheduleItem>;
  runNow(id: string, signal?: AbortSignal): Promise<void>;
  remove(id: string, signal?: AbortSignal): Promise<void>;
  runs(id: string, signal?: AbortSignal): Promise<SchedRun[]>;
  triggers(signal?: AbortSignal): Promise<TriggersResponse>;
  createTrigger(input: TriggerInput, signal?: AbortSignal): Promise<TriggerItem>;
  setTriggerEnabled(id: string, on: boolean, signal?: AbortSignal): Promise<TriggerItem>;
  removeTrigger(id: string, signal?: AbortSignal): Promise<void>;
  rotateTriggerSecret(id: string, signal?: AbortSignal): Promise<TriggerItem>;
  deliveries(id: string, signal?: AbortSignal): Promise<Delivery[]>;
  testTrigger(id: string, signal?: AbortSignal): Promise<TestResult>;
}

export function createSchedApi(request: Request): SchedApi {
  const s = (id: string) => `/v1/schedules/${encodeURIComponent(id)}`;
  const g = (id: string) => `/v1/triggers/${encodeURIComponent(id)}`;
  return {
    list: (sig) => request('GET', '/v1/schedules', undefined, sig),
    preview: (b, sig) => request('POST', '/v1/schedules/preview', b, sig),
    create: (b, sig) => request('POST', '/v1/schedules', b, sig),
    update: (id, b, sig) => request('PUT', s(id), b, sig),
    setEnabled: (id, on, sig) => request('POST', `${s(id)}/${on ? 'resume' : 'pause'}`, undefined, sig),
    runNow: async (id, sig) => {
      await request('POST', `${s(id)}/run-now`, undefined, sig);
    },
    remove: async (id, sig) => {
      await request('DELETE', s(id), undefined, sig);
    },
    runs: async (id, sig) => (await request<{ runs: SchedRun[] }>('GET', `${s(id)}/runs`, undefined, sig)).runs,
    triggers: (sig) => request('GET', '/v1/triggers', undefined, sig),
    createTrigger: (b, sig) => request('POST', '/v1/triggers', b, sig),
    setTriggerEnabled: (id, on, sig) => request('POST', `${g(id)}/${on ? 'enable' : 'disable'}`, undefined, sig),
    removeTrigger: async (id, sig) => {
      await request('DELETE', g(id), undefined, sig);
    },
    rotateTriggerSecret: (id, sig) => request('POST', `${g(id)}/rotate-secret`, undefined, sig),
    deliveries: async (id, sig) => (await request<{ deliveries: Delivery[] }>('GET', `${g(id)}/deliveries`, undefined, sig)).deliveries,
    testTrigger: (id, sig) => request('POST', `${g(id)}/test`, undefined, sig),
  };
}
