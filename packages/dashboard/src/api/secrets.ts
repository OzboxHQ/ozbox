// Approvals for changes to a box's secrets: a person who has just shown a passkey asks for a short-lived code, and the code
// is spent by the one change it is for (see crates/ozbox-cli/src/serve/approvals.rs). The code is shown once; nothing here
// returns a secret value, and the list of recent uses holds scope, project, environment and how, nothing else.

// The same scopes the box's secrets service accepts (crates/ozbox-cli/src/secrets_approval.rs SCOPES): a Rust test compares
// the two lists, so a scope added there is offered here.
export const APPROVAL_SCOPES = ['import', 'policy', 'tunnel-token', 'guard-override', 'signer-enroll', 'setup-code', 'kek-export', 'box-secrets', 'host-guard'] as const;
export type ApprovalScope = (typeof APPROVAL_SCOPES)[number];

export interface ApprovalUse {
  at_ms: number;
  outcome: 'minted' | 'allowed' | 'refused';
  scope: string;
  project: string;
  env: string;
  /** How the change was allowed: `dashboard-stepup`, `bootstrap` (no second factor yet), or `none` (refused). */
  via: string;
}

export interface ApprovalsStatus {
  /** This dashboard keeps its secrets in a box's secrets service, so there is something to approve for. */
  available: boolean;
  /** A second factor is on record there: from now on a change needs an approval. */
  enrolled: boolean;
  signed_in: boolean;
  recent: ApprovalUse[];
}

export interface MintRequest {
  scope: ApprovalScope;
  project: string;
  env: string;
}

export interface Minted {
  code: string;
  scope: ApprovalScope;
  project: string;
  env: string;
  expires_in_seconds: number;
  expires_at_ms: number;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface SecretsApi {
  approvals(signal?: AbortSignal): Promise<ApprovalsStatus>;
  /** Needs a passkey shown a moment ago: a `step_up_required` answer is for the caller to resolve. */
  mint(body: MintRequest, signal?: AbortSignal): Promise<Minted>;
}

export function createSecretsApi(request: Request): SecretsApi {
  return {
    approvals: (s) => request('GET', '/v1/secrets/approvals', undefined, s),
    mint: (body, s) => request('POST', '/v1/secrets/approvals', body, s),
  };
}
