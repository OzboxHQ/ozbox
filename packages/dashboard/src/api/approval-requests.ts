// Change requests (ADR 0041): a request filed on the box waits here for a person to approve or deny it. Every string a card
// carries was cleaned by the server and is rendered as text only. Nothing here carries a value, a token or a code.

import type { AssertionJson, RequestJson } from '../lib/webauthn';

export const REQUEST_SCOPES = ['import', 'policy', 'tunnel-token', 'guard-override', 'signer-enroll', 'box-secrets', 'host-guard', 'setup-code', 'kek-export', 'worker-keys'] as const;
export type RequestScope = (typeof REQUEST_SCOPES)[number];

export const REQUEST_STATES = ['pending', 'approved', 'spending', 'spent', 'denied', 'cancelled', 'superseded', 'expired'] as const;
export type RequestState = (typeof REQUEST_STATES)[number];

export type DisplaySource = 'service' | 'root-helper' | 'from the box';

export interface DisplayRow {
  label: string;
  value: string;
  source: DisplaySource;
}

export type RequesterKind = 'box-user' | 'supervisor' | 'root-helper' | 'hub-agent' | 'laptop-key';

export interface Requester {
  kind: RequesterKind;
  uid: number | null;
  key_id: string | null;
  run_id: string | null;
  engine: string | null;
  /** The requester's own word for who it is. Never shown as fact. */
  claimed: string | null;
}

export type DecisionOutcome = 'approve' | 'deny' | 'revoke';
export type DecisionSurface = 'dashboard' | 'laptop' | 'telegram' | 'root' | 'bootstrap' | 'hub-relay';

export interface Decision {
  outcome: DecisionOutcome;
  decider: string;
  role: 'owner' | 'member' | null;
  surface: DecisionSurface;
  /** `passkey`, `authenticator`, `laptop-key:<id>`, `laptop-key:<id> (no user presence)`, `root`, `bootstrap`, `chat-deny`. */
  factor_label: string;
  presence: 'proved' | 'no-presence' | 'not-applicable';
  at_ms: number;
}

export interface CanDecide {
  allowed: boolean;
  /** A sentence for the person when `allowed` is false: shown as it is. */
  reason: string | null;
}

export interface RequestCard {
  id: string;
  scope: RequestScope;
  state: RequestState;
  origin: string;
  subject_digest: string;
  display: DisplayRow[];
  reason: string | null;
  requester: Requester;
  filed_at_ms: number;
  expires_at_ms: number;
  /** After now: cooling-off, the request cannot be spent yet. */
  not_before_ms: number;
  decision: Decision | null;
  replaces: string | null;
  superseded_by: string | null;
  void_reason: string | null;
  can: { approve: CanDecide; deny: CanDecide };
}

export type ViewerRole = 'owner' | 'member' | 'viewer';

export interface RequestList {
  /** False: the box's secrets service keeps no approval requests (an older box, or no service). */
  available: boolean;
  /** `role: null`: this dashboard has no sign-in, so nobody can decide here. */
  viewer: { role: ViewerRole | null };
  epoch: string;
  requests: RequestCard[];
}

export interface DecideChallenge {
  options: RequestJson;
  outcome: 'approve';
  subject_digest: string;
}

export type KeyType = 'ed25519' | 'sk-ssh-ed25519' | 'ecdsa-sk' | 'webauthn-p256';

export interface LaptopKey {
  id: string;
  key_type: KeyType;
  /** `proved`: a hardware key whose attestation verified. Everything else is a software key. */
  presence: 'proved' | 'none';
  /** `pinned`, `root`, `passkey`, `laptop-key:<id>`, or null for an older key. */
  enrolled_via: string | null;
  attested: boolean;
  /** When the cooling-off ends. */
  active_from_ms: number | null;
}

export interface ApproverKeys {
  available: boolean;
  laptop_keys: LaptopKey[];
  ever_had_laptop_key: boolean;
  ever_had_presence_key: boolean;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface ApprovalRequestsApi {
  list(signal?: AbortSignal): Promise<RequestList>;
  get(id: string, signal?: AbortSignal): Promise<{ request: RequestCard }>;
  /** One challenge names one request, its digest and the outcome: one assertion decides one request. */
  challenge(id: string, signal?: AbortSignal): Promise<DecideChallenge>;
  approve(id: string, assertion: AssertionJson, signal?: AbortSignal): Promise<{ request: RequestCard }>;
  /**
   * For a person with no passkey: an authenticator-app code approves instead. The dashboard and the box's secrets service
   * both check it; the record says `authenticator`, never `passkey`. The code is sent once and kept nowhere.
   */
  approveWithCode(id: string, code: string, signal?: AbortSignal): Promise<{ request: RequestCard }>;
  /** Needs no passkey (a deny is fail safe). Also revokes an approved request that was not spent. */
  deny(id: string, signal?: AbortSignal): Promise<{ request: RequestCard }>;
  keys(signal?: AbortSignal): Promise<ApproverKeys>;
  /** Owner only; a `step_up_required` answer is for the caller to resolve. */
  revokeKey(id: string, signal?: AbortSignal): Promise<{ ok: true }>;
}

export function createApprovalRequestsApi(request: Request): ApprovalRequestsApi {
  const one = (id: string) => `/v1/approvals/requests/${encodeURIComponent(id)}`;
  return {
    list: (s) => request('GET', '/v1/approvals/requests', undefined, s),
    get: (id, s) => request('GET', one(id), undefined, s),
    challenge: (id, s) => request('POST', `${one(id)}/challenge`, {}, s),
    approve: (id, assertion, s) => request('POST', `${one(id)}/approve`, { assertion }, s),
    approveWithCode: (id, code, s) => request('POST', `${one(id)}/approve-authenticator`, { code: code.replace(/\s/g, '') }, s),
    deny: (id, s) => request('POST', `${one(id)}/deny`, {}, s),
    keys: (s) => request('GET', '/v1/approvals/keys', undefined, s),
    revokeKey: (id, s) => request('POST', `/v1/approvals/keys/${encodeURIComponent(id)}/revoke`, {}, s),
  };
}
