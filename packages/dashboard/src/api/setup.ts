// First-run setup: the same steps as `ozbox init`. Checks only read; a step that changes something is planned first and
// the plan is applied once, exactly as shown.

import type { Change } from './types';

export type SetupProvider = 'fake' | 'aws' | 'hcloud';

export interface SetupTarget {
  provider: SetupProvider;
  profile?: string | null;
  region?: string | null;
}

export interface Identity {
  account: string;
  arn: string;
  kind: 'root' | 'iam_user' | 'sso_role' | 'assumed_role' | 'federated' | 'other';
  user?: string;
}

export interface Probe {
  id: string;
  label: string;
  state: 'allowed' | 'denied' | 'unknown';
  detail?: string;
}

export interface RegionCandidate {
  region: string;
  name: string;
  ms: number | null;
  offers_sizes: boolean | null;
}

export interface SecurityItem {
  id: string;
  state: 'pass' | 'fail' | 'reminder';
  message: string;
}

export interface Guardrails {
  budget_set: boolean;
  monthly_usd: number | null;
  channels: string[];
  alert_ready: boolean;
  ok: boolean;
}

export interface SetupStatus {
  summary: { available: boolean; completed: boolean; needed: boolean; require_guardrails: boolean };
  provider: string | null;
  region: string | null;
  profile: string | null;
  state_bucket: boolean;
  network: boolean;
  mfa_ack: boolean;
  guardrails: Guardrails;
  providers: string[];
  hcloud_token_present: boolean;
}

export type CheckKind = 'sign_in' | 'permissions' | 'regions' | 'security';

export interface CheckResult {
  identity?: Identity;
  report?: { probes?: Probe[]; ok?: boolean; candidates?: RegionCandidate[]; suggested?: string | null; items?: SecurityItem[]; blocking?: boolean; needs_ack?: boolean };
  locations?: string[];
}

export interface SetupPlan {
  plan_id: string;
  step: 'state_bucket' | 'network';
  summary: string;
  changes: Change[];
  notes: string[];
  estimate_usd_month: number | null;
  noop: boolean;
  expires_in_s: number;
}

export interface SetupApi {
  status(signal?: AbortSignal): Promise<SetupStatus>;
  check(check: CheckKind, target: SetupTarget, signal?: AbortSignal): Promise<CheckResult>;
  /** Never changes anything in the cloud. */
  plan(step: SetupPlan['step'], target: SetupTarget, signal?: AbortSignal): Promise<SetupPlan>;
  apply(planId: string, signal?: AbortSignal): Promise<{ applied: boolean; result: { step: string; bucket?: string; subnet_id?: string } }>;
  finish(target: SetupTarget, mfaAck: boolean, signal?: AbortSignal): Promise<{ completed: boolean; restart_required: boolean }>;
  sandbox(signal?: AbortSignal): Promise<{ completed: boolean; restart_required: boolean }>;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createSetupApi(request: Request): SetupApi {
  return {
    status: (s) => request('GET', '/v1/setup', undefined, s),
    check: (check, target, s) => request('POST', '/v1/setup/check', { check, ...target }, s),
    plan: (step, target, s) => request('POST', '/v1/setup/plan', { step, ...target }, s),
    apply: (plan_id, s) => request('POST', '/v1/setup/apply', { plan_id }, s),
    finish: (target, mfa_ack, s) => request('POST', '/v1/setup/finish', { ...target, mfa_ack }, s),
    sandbox: (s) => request('POST', '/v1/setup/sandbox', undefined, s),
  };
}
