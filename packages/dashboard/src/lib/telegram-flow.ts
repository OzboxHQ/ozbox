// Small pure helpers for the Telegram pages: the words for a state, and the checks a form makes before it asks for a passkey.

import type { DelegationState, LinkState } from '../api/telegram';
import { t } from './i18n';

export const LINK_STATE_KEY: Record<LinkState, string> = {
  active: 'tg.state_active',
  locked: 'tg.state_locked',
  revoked: 'tg.state_revoked',
  not_genuine: 'tg.state_not_genuine',
};

export const DELEGATION_STATE_KEY: Record<DelegationState, string> = {
  active: 'tg.d_active',
  waiting: 'tg.d_waiting',
  pending_owner: 'tg.d_pending_owner',
  expired: 'tg.d_expired',
  lapsed: 'tg.d_lapsed',
  not_yet: 'tg.d_not_yet',
  not_genuine: 'tg.d_not_genuine',
  revoked: 'tg.d_revoked',
};

export function linkStateText(s: LinkState): string {
  return t(LINK_STATE_KEY[s] as 'tg.state_active');
}

export function delegationStateText(s: DelegationState): string {
  return t(DELEGATION_STATE_KEY[s] as 'tg.d_active');
}

/** A link a person can still act on: reduce (lock, unlink) is always open; anything else needs it not to be ended or forged. */
export function linkIsLive(state: LinkState): boolean {
  return state === 'active' || state === 'locked';
}

/** The days a delegation may last, as the server takes them: 1 to 30, whole. */
export function validDays(raw: string): number | null {
  if (!/^\d{1,2}$/.test(raw.trim())) return null;
  const n = Number(raw);
  return n >= 1 && n <= 30 ? n : null;
}

/** The codes the bot sends are eight letters and digits without look-alikes; this only trims and upper-cases what was typed. */
export function normaliseCode(raw: string): string {
  return raw.replace(/\s+/g, '').toUpperCase();
}

/** Whether a pointer link's fragment holds a token the server could have made (48 hex characters). */
export function pointerToken(hash: string): string | null {
  const m = /^#([0-9a-fA-F]{48})$/.exec(hash);
  return m ? (m[1] ?? null) : null;
}

/** A path the server named for a pointer link is a path inside this dashboard and nothing else. */
export function safeInternalPath(p: string): string | null {
  return /^\/[A-Za-z0-9/_-]*$/.test(p) && !p.startsWith('//') ? p : null;
}
