// The owner's opt-in to hand one engine's own subscription sign-in to that engine's runs (ADR 0055), the vendor's device
// sign-in started from the dashboard, and revoking it. The shapes `/v1/models/subscriptions` answers with (see
// crates/ozbox-cli/src/serve/subscription_routes.rs). Nothing here ever carries the sign-in itself.

export interface SubscriptionOptInState {
  id: string;
  engine: string;
  opted_in: boolean;
  signed_in: boolean;
  /** Where a sign-in started from here stands, if one did since the server started. */
  sign_in: SignInPhase | null;
  /** What the person types to turn the opt-in on. */
  confirm: string;
  /** The vendor's page where the sign-in is revoked for good. */
  revoke_at: string;
}

export type SignInPhase = 'starting' | 'waiting' | 'done' | 'failed';

export interface SignInState {
  id: string;
  sign_in: SignInPhase | null;
  started_ms?: number;
  /** The vendor's own page to open, and the one-time code to type there (while `waiting`). */
  link?: string;
  code?: string;
  /** Why it failed, as a code (`models.signin_failed_<reason>`). */
  reason?: string;
}

export interface RevokeResult {
  id: string;
  /** Runs that were handed the sign-in and are still going: each keeps its copy until it ends. */
  runs_holding: string[];
  revoke_at: string;
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createSubscriptionsApi(request: Req) {
  const base = '/v1/models/subscriptions';
  return {
    list: (signal?: AbortSignal) => request<{ subscriptions: SubscriptionOptInState[] }>('GET', base, undefined, signal),
    /** Needs a passkey shown a moment ago and the confirmation typed back. */
    optIn: (id: string, confirm: string) => request<{ id: string; opted_in: boolean }>('POST', `${base}/${encodeURIComponent(id)}/opt-in`, { confirm }),
    /** Starts the vendor's device sign-in; read its link and code with `signInState`. Needs a passkey. */
    startSignIn: (id: string) => request<{ id: string; sign_in: SignInPhase }>('POST', `${base}/${encodeURIComponent(id)}/sign-in`),
    signInState: (id: string, signal?: AbortSignal) => request<SignInState>('GET', `${base}/${encodeURIComponent(id)}/sign-in`, undefined, signal),
    /** Deletes the sign-in and turns the opt-in off. */
    revoke: (id: string) => request<RevokeResult>('DELETE', `${base}/${encodeURIComponent(id)}`),
  };
}

export type SubscriptionsApi = ReturnType<typeof createSubscriptionsApi>;
