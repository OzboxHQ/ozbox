// Telegram links and delegations (ADR 0050). Every shape is the one `/v1/telegram` answers with (see
// crates/ozbox-cli/src/serve/telegram_link.rs). Nothing here carries a token, a code of the bot or a message: a link is shown by
// the tail of its account number and the label its person gave it.

import type { AssertionJson, RequestJson } from '../lib/webauthn';

export type LinkState = 'active' | 'locked' | 'revoked' | 'not_genuine';
export type DelegationState = 'active' | 'waiting' | 'pending_owner' | 'expired' | 'lapsed' | 'not_yet' | 'not_genuine' | 'revoked';

export interface TgDelegation {
  id: string;
  acts: string[];
  boxes: string[];
  issued_ms: number;
  expires_ms: number;
  last_used_ms: number;
  state: DelegationState;
  hub_ack: boolean;
  with_link: boolean;
}

export interface TgLink {
  id: string;
  person: string;
  label: string;
  /** The tail of Telegram's numeric id, as `…1234`. */
  account: string;
  state: LinkState;
  created_ms: number;
  expires_ms: number;
  last_seen_ms: number;
  ended: string | null;
  delegations: TgDelegation[];
}

export interface TgPendingOwner {
  id: string;
  person: string;
  boxes: string[];
  acts: string[];
  expires_ms: number;
}

export interface TgStatus {
  /** The signed-in person (their links are the ones they can renew, delegate and unlock). */
  me: string;
  enabled: boolean;
  signed_in: boolean;
  /** A dashboard with no sign-in has no passkey to link or delegate with. */
  needs_sign_in: boolean;
  public_address: boolean;
  bot: string | null;
  running: boolean;
  halted: { code: string; since_ms: number; message: string } | null;
  store_error: string | null;
  transcript_error: string | null;
  window: { person: string; expires_in_s: number; code_offered: boolean; account_found: boolean; account: { id_tail: string; first_name: string } | null } | null;
  links: TgLink[];
  /** Chats linked before passkey links: they read and are told things, nothing more. */
  legacy_chats: { id: number; name: string; person: string | null }[];
  pending_owner: TgPendingOwner[];
  counters: { unlinked: number; unlinked_last_ms: number; too_old: number; replays: number };
  marks: { production: string[]; hub: string | null };
  wait_hours: number;
}

export interface Challenge {
  options: RequestJson;
}

export interface LinkSummary {
  account: string;
  label: string;
  expires_ms: number;
  converse: { boxes: string[]; expires_ms: number } | null;
  needs_owner: boolean;
}

export interface TranscriptLine {
  link_id: string;
  ts_ms: number;
  dir: 'in' | 'out';
  text: string;
  mac: string;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface ConverseWish {
  boxes: string[];
  days?: number;
  hub_ack?: boolean;
}

export interface TelegramApi {
  status(signal?: AbortSignal): Promise<TgStatus>;
  /** Step 1: a passkey opens a pairing window for ten minutes. */
  windowChallenge(): Promise<Challenge & { bot: string; window_minutes: number }>;
  windowOpen(assertion: AssertionJson): Promise<{ bot: string | null; expires_in_s: number }>;
  windowClose(): Promise<{ closed: boolean }>;
  /** Step 2: the code the bot sent. The answer shows the account that was bound; nothing is linked yet. */
  candidate(code: string): Promise<{ account: { id_tail: string; first_name: string } }>;
  /** Step 3: one passkey confirms the link and, when asked for, converse on the named boxes. */
  linkChallenge(label: string, converse: ConverseWish | null): Promise<Challenge & { summary: LinkSummary }>;
  linkConfirm(assertion: AssertionJson): Promise<{ link: TgLink }>;
  lock(id: string): Promise<{ link: TgLink }>;
  unlockChallenge(id: string): Promise<Challenge>;
  unlock(id: string, assertion: AssertionJson): Promise<{ link: TgLink }>;
  unlink(id: string): Promise<{ removed: boolean }>;
  renewChallenge(id: string): Promise<Challenge & { expires_ms: number }>;
  renew(id: string, assertion: AssertionJson): Promise<{ link: TgLink }>;
  delegationChallenge(id: string, wish: { acts: string[]; boxes: string[]; days?: number; hub_ack?: boolean; caps?: { max_size?: string | null; daily_usd?: number } }): Promise<Challenge & { summary: { boxes: string[]; acts: string[]; expires_ms: number; needs_owner: boolean } }>;
  delegationCreate(id: string, assertion: AssertionJson): Promise<{ link: TgLink }>;
  delegationRevoke(id: string): Promise<{ link: TgLink }>;
  cosignChallenge(id: string): Promise<Challenge & { person: string; boxes: string[] }>;
  cosign(id: string, assertion: AssertionJson): Promise<{ cosigned: boolean }>;
  lockAll(): Promise<{ locked: number }>;
  resume(): Promise<{ resumed: boolean }>;
  setMarks(production: string[], hub: string | null): Promise<{ marks: { production: string[]; hub: string | null } }>;
  transcript(id: string): Promise<{ link: string; lines: TranscriptLine[]; kept_days: number }>;
  /** What a pointer link from a chat names. Opening it changes nothing and spends nothing. */
  openPointer(token: string): Promise<{ path: string }>;
}

export function createTelegramApi(request: Request): TelegramApi {
  const link = (id: string) => `/v1/telegram/links/${encodeURIComponent(id)}`;
  return {
    status: (s) => request('GET', '/v1/telegram', undefined, s),
    windowChallenge: () => request('POST', '/v1/telegram/window/challenge', {}),
    windowOpen: (assertion) => request('POST', '/v1/telegram/window', { assertion }),
    windowClose: () => request('DELETE', '/v1/telegram/window'),
    candidate: (code) => request('POST', '/v1/telegram/link/candidate', { code }),
    linkChallenge: (label, converse) => request('POST', '/v1/telegram/link/challenge', converse ? { label, converse } : { label }),
    linkConfirm: (assertion) => request('POST', '/v1/telegram/link', { assertion }),
    lock: (id) => request('POST', `${link(id)}/lock`, {}),
    unlockChallenge: (id) => request('POST', `${link(id)}/unlock/challenge`, {}),
    unlock: (id, assertion) => request('POST', `${link(id)}/unlock`, { assertion }),
    unlink: (id) => request('DELETE', link(id)),
    renewChallenge: (id) => request('POST', `${link(id)}/renew/challenge`, {}),
    renew: (id, assertion) => request('POST', `${link(id)}/renew`, { assertion }),
    delegationChallenge: (id, wish) => request('POST', `${link(id)}/delegations/challenge`, wish),
    delegationCreate: (id, assertion) => request('POST', `${link(id)}/delegations`, { assertion }),
    delegationRevoke: (id) => request('DELETE', `/v1/telegram/delegations/${encodeURIComponent(id)}`),
    cosignChallenge: (id) => request('POST', `/v1/telegram/delegations/${encodeURIComponent(id)}/cosign/challenge`, {}),
    cosign: (id, assertion) => request('POST', `/v1/telegram/delegations/${encodeURIComponent(id)}/cosign`, { assertion }),
    lockAll: () => request('POST', '/v1/telegram/lock-all', {}),
    resume: () => request('POST', '/v1/telegram/resume', {}),
    setMarks: (production, hub) => request('PUT', '/v1/telegram/marks', { production, hub }),
    transcript: (id) => request('GET', `${link(id)}/transcript`),
    openPointer: (token) => request('POST', '/v1/chat/links/open', { token }),
  };
}
