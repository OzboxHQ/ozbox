/** The sign-in endpoints of a dashboard served behind a tunnel (`/auth/...`). Cookies go by themselves; a change carries the CSRF token. */
import type { AssertionJson, CreationJson, RegistrationJson, RequestJson } from '../lib/webauthn';
import type { Role } from './people';
import { createTransport, type Method } from './transport';

export type SessionState = 'signed_out' | 'needs_second_factor' | 'enroll_required' | 'signed_in';

export interface Methods {
  passkey: boolean;
  github: boolean;
  google: boolean;
  access: boolean;
  setup_code: boolean;
}

export interface SessionStatus {
  mode: 'session';
  state: SessionState;
  methods: Methods;
  stepup_window_s: number;
  user?: { id: string; label: string };
  csrf?: string;
  second_factors?: { passkey: boolean; totp: boolean };
  stepup_fresh?: boolean;
  /** What this person may do (ADR 0039), by capability name. */
  role?: Role;
  can?: Record<string, boolean>;
}

export interface TokenMode {
  mode: 'token';
}

export interface PasskeyInfo {
  id: string;
  name: string;
  created_ms: number;
  last_used_ms: number;
}

export interface SessionInfo {
  id: string;
  created_ms: number;
  last_seen_ms: number;
  via: string;
  current: boolean;
}

export interface Account {
  user: { id: string; label: string | null };
  passkeys: PasskeyInfo[];
  totp: boolean;
  sessions: SessionInfo[];
  people: { id: string; label: string; github?: string | null; google?: string | null; role: Role }[];
  /** Only an owner changes how people sign in; the server refuses anyone else. */
  can_configure_providers: boolean;
  providers: {
    github: { client_id: string | null };
    google: { client_id: string | null; secret_set: boolean };
    access: { team_domain: string } | null;
  };
  public_origin: string;
  callback_url: string;
  stepup_fresh: boolean;
}

export interface Ceremony<O> {
  ceremony: string;
  options: O;
}

export interface GithubStart {
  flow: string;
  user_code: string;
  verification_uri: string;
  interval: number;
  expires_in: number;
}

export type GithubPoll = { status: 'pending' | 'slow_down'; interval: number } | { status: 'expired' | 'denied' } | SessionStatus;

export interface SessionApi {
  status(signal?: AbortSignal): Promise<SessionStatus | TokenMode>;
  csrf(): string;
  loginOptions(): Promise<Ceremony<RequestJson>>;
  loginVerify(ceremony: string, credential: AssertionJson): Promise<SessionStatus>;
  setupCode(code: string, user: string): Promise<SessionStatus>;
  registerOptions(): Promise<Ceremony<CreationJson>>;
  registerVerify(ceremony: string, credential: RegistrationJson, name: string): Promise<SessionStatus | { ok: true }>;
  secondOptions(): Promise<Ceremony<RequestJson>>;
  secondVerify(ceremony: string, credential: AssertionJson): Promise<SessionStatus>;
  stepUpOptions(): Promise<Ceremony<RequestJson>>;
  stepUpVerify(ceremony: string, credential: AssertionJson): Promise<SessionStatus>;
  stepUpTotp(code: string): Promise<SessionStatus>;
  secondTotp(code: string): Promise<SessionStatus>;
  totpSetup(): Promise<{ secret: string; otpauth_uri: string }>;
  totpConfirm(code: string): Promise<SessionStatus | { ok: true }>;
  totpRemove(): Promise<void>;
  githubStart(): Promise<GithubStart>;
  githubPoll(flow: string): Promise<GithubPoll>;
  /** Cloudflare Access: exchange the verified Access token (the browser's request carries it) for a session. */
  accessExchange(): Promise<SessionStatus>;
  account(signal?: AbortSignal): Promise<Account>;
  removePasskey(id: string): Promise<void>;
  revokeSession(id: string): Promise<void>;
  signOut(everywhere: boolean): Promise<void>;
  setGithub(clientId: string): Promise<void>;
  /** Write-only: the secret is sent once and never read back. */
  setGoogle(clientId: string, clientSecret: string): Promise<void>;
  /** The address Google sends the person back to. */
}

export function createSessionApi(opts: { fetchImpl?: typeof fetch; base?: string } = {}): SessionApi {
  let csrf = '';
  // The same transport as every other call, with one difference: signing in has no session to lose, so a 401 is just an answer.
  const tr = createTransport({ csrf: () => csrf, ...(opts.base ? { baseUrl: opts.base } : {}), ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}), sessionEnds: false });

  async function call<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    const v = await tr.request<T>(method as Method, path, body, signal);
    const c = (v as { csrf?: unknown }).csrf;
    if (typeof c === 'string') csrf = c;
    return v;
  }
  const none = async (method: string, path: string, body?: unknown) => {
    await call<unknown>(method, path, body);
  };
  const enc = encodeURIComponent;
  return {
    status: (s) => call('GET', '/auth/session', undefined, s),
    csrf: () => csrf,
    loginOptions: () => call('POST', '/auth/passkey/login/options', {}),
    loginVerify: (ceremony, credential) => call('POST', '/auth/passkey/login/verify', { ceremony, credential }),
    setupCode: (code, user) => call('POST', '/auth/bootstrap', { code, user }),
    registerOptions: () => call('POST', '/auth/passkey/register/options', {}),
    registerVerify: (ceremony, credential, name) => call('POST', '/auth/passkey/register/verify', { ceremony, credential, name }),
    secondOptions: () => call('POST', '/auth/second/passkey/options', {}),
    secondVerify: (ceremony, credential) => call('POST', '/auth/second/passkey/verify', { ceremony, credential }),
    stepUpOptions: () => call('POST', '/auth/stepup/options', {}),
    stepUpVerify: (ceremony, credential) => call('POST', '/auth/stepup/verify', { ceremony, credential }),
    stepUpTotp: (code) => call('POST', '/auth/stepup/totp', { code }),
    secondTotp: (code) => call('POST', '/auth/second/totp', { code }),
    totpSetup: () => call('POST', '/auth/totp/setup', {}),
    totpConfirm: (code) => call('POST', '/auth/totp/confirm', { code }),
    totpRemove: () => none('DELETE', '/auth/totp'),
    githubStart: () => call('POST', '/auth/github/start', {}),
    githubPoll: (flow) => call('POST', '/auth/github/poll', { flow }),
    accessExchange: () => call('POST', '/auth/access/exchange', {}),
    account: (s) => call('GET', '/auth/account', undefined, s),
    removePasskey: (id) => none('DELETE', `/auth/passkeys/${enc(id)}`),
    revokeSession: (id) => none('DELETE', `/auth/sessions/${enc(id)}`),
    signOut: (everywhere) => none('POST', everywhere ? '/auth/signout-all' : '/auth/signout', {}),
    setGithub: (clientId) => none('PUT', '/auth/config/github', { client_id: clientId }),
    setGoogle: (clientId, clientSecret) => none('PUT', '/auth/config/google', { client_id: clientId, ...(clientSecret ? { client_secret: clientSecret } : {}) }),
  };
}
