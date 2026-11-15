// Pure helpers for change requests (ADR 0041). Every string the server sent is passed through as text and never parsed or
// rendered as HTML; the helpers only choose which words surround it.

import type { DisplayRow, LaptopKey, RequestCard, RequestScope, RequestState, Requester, ViewerRole } from '../api/approval-requests';
import { t, type MessageKey } from './i18n';

const SCOPE_NAME: Record<RequestScope, MessageKey> = {
  import: 'areq.scope_import',
  policy: 'areq.scope_policy',
  'tunnel-token': 'areq.scope_tunnel_token',
  'guard-override': 'areq.scope_guard_override',
  'signer-enroll': 'areq.scope_signer_enroll',
  'box-secrets': 'areq.scope_box_secrets',
  'host-guard': 'areq.scope_host_guard',
  'setup-code': 'areq.scope_setup_code',
  'kek-export': 'areq.scope_kek_export',
  'worker-keys': 'areq.scope_worker_keys',
};

/** The scope in words. A scope this dashboard does not know (a newer box) is shown as the box sent it. */
export function scopeName(scope: string): string {
  const key = (SCOPE_NAME as Record<string, MessageKey | undefined>)[scope];
  return key ? t(key) : scope;
}

const STATE_KEY: Record<RequestState, MessageKey> = {
  pending: 'areq.state_pending',
  approved: 'areq.state_approved',
  spending: 'areq.state_spending',
  spent: 'areq.state_spent',
  denied: 'areq.state_denied',
  cancelled: 'areq.state_cancelled',
  superseded: 'areq.state_superseded',
  expired: 'areq.state_expired',
};

export function stateLabel(state: string): string {
  const key = (STATE_KEY as Record<string, MessageKey | undefined>)[state];
  return key ? t(key) : state;
}

export type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline';

/** Waiting asks for attention, approved and used are done well, a refusal is red, everything else is quiet. */
export function stateVariant(state: string): BadgeVariant {
  switch (state) {
    case 'pending':
      return 'default';
    case 'approved':
    case 'spending':
    case 'spent':
      return 'secondary';
    case 'denied':
      return 'destructive';
    default:
      return 'outline';
  }
}

/** A request someone may still decide (approve it, or deny / revoke it). */
export const isOpen = (s: string): boolean => s === 'pending' || s === 'approved';

const group = (s: string): number => (s === 'pending' ? 0 : s === 'approved' || s === 'spending' ? 1 : 2);

/** Pending first, then approved (and being used), then everything finished; newest first inside each group. */
export function sortRequests(list: readonly RequestCard[]): RequestCard[] {
  return [...list].sort((a, b) => group(a.state) - group(b.state) || b.filed_at_ms - a.filed_at_ms || a.id.localeCompare(b.id));
}

export function shortDigest(digest: string): string {
  return digest.slice(0, 16);
}

export function fmtSpan(ms: number): string {
  const minutes = Math.floor(Math.max(0, ms) / 60_000);
  if (minutes < 1) return t('areq.time_less_than_minute');
  if (minutes < 60) return t('areq.time_minutes', { n: minutes });
  return t('areq.time_hours', { h: Math.floor(minutes / 60), m: minutes % 60 });
}

export type TimeLeft = { kind: 'cooling'; ms: number } | { kind: 'left'; ms: number } | { kind: 'expired' } | { kind: 'none' };

/** What the clock says about a request: cooling-off, time left, expired, or nothing (it is finished). */
export function timeLeft(card: Pick<RequestCard, 'state' | 'expires_at_ms' | 'not_before_ms'>, now: number): TimeLeft {
  if (!isOpen(card.state)) return { kind: 'none' };
  if (card.expires_at_ms <= now) return { kind: 'expired' };
  if (card.not_before_ms > now) return { kind: 'cooling', ms: card.not_before_ms - now };
  return { kind: 'left', ms: card.expires_at_ms - now };
}

export function timeText(card: Pick<RequestCard, 'state' | 'expires_at_ms' | 'not_before_ms'>, now: number): string | null {
  const left = timeLeft(card, now);
  switch (left.kind) {
    case 'cooling':
      return t('areq.time_cooling', { time: fmtSpan(left.ms) });
    case 'left':
      return t('areq.time_left', { time: fmtSpan(left.ms) });
    case 'expired':
      return t('areq.time_expired');
    default:
      return null;
  }
}

export type Rule = 'passkey' | 'owner-only' | null;

/**
 * The rule line, from what the server says this viewer may do. Allowed to approve: it takes the viewer's passkey. A member
 * refused is told it is for owners. Anything else (a viewer, no sign-in, a rule only the server knows) shows no rule of our
 * own: the server's sentence is shown instead, as it is.
 */
export function ruleFor(card: Pick<RequestCard, 'state' | 'can'>, role: ViewerRole | null): Rule {
  if (card.state === 'pending' && card.can.approve.allowed) return 'passkey';
  if (isOpen(card.state) && role === 'member' && !card.can.approve.allowed) return 'owner-only';
  return null;
}

export function ruleText(rule: Rule): string | null {
  return rule === 'passkey' ? t('areq.rule_passkey') : rule === 'owner-only' ? t('areq.rule_owner_only') : null;
}

/** What the viewer cannot do on a card, in the server's own words, for a card that can still be decided. */
export function refusals(card: RequestCard): string[] {
  if (!isOpen(card.state)) return [];
  const out: string[] = [];
  const add = (c: { allowed: boolean; reason: string | null }) => {
    if (!c.allowed && c.reason && !out.includes(c.reason)) out.push(c.reason);
  };
  if (card.state === 'pending') add(card.can.approve);
  add(card.can.deny);
  return out;
}

/** Nothing to press on this card: show it read only. */
export function readOnly(card: RequestCard): boolean {
  if (card.state === 'pending') return !card.can.approve.allowed && !card.can.deny.allowed;
  if (card.state === 'approved') return !card.can.deny.allowed;
  return true;
}

export function howDecided(factor: string): string {
  if (factor === 'passkey') return t('areq.how_passkey');
  if (factor === 'root') return t('areq.how_root');
  if (factor === 'bootstrap') return t('areq.how_bootstrap');
  if (factor === 'chat-deny') return t('areq.how_chat_deny');
  const noPresence = /^laptop-key:(.+) \(no user presence\)$/.exec(factor);
  if (noPresence?.[1]) return t('areq.how_laptop_key_no_presence', { id: noPresence[1] });
  const key = /^laptop-key:(.+)$/.exec(factor);
  if (key?.[1]) return t('areq.how_laptop_key', { id: key[1] });
  return t('areq.how_other', { label: factor });
}

export function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/** "approved by Alice, passkey, 12:03". `fmt` is for tests. */
export function decisionLine(card: Pick<RequestCard, 'decision'>, fmt: (ms: number) => string = clock): string | null {
  const d = card.decision;
  if (!d) return null;
  const key: MessageKey = d.outcome === 'approve' ? 'areq.decision_approve' : d.outcome === 'deny' ? 'areq.decision_deny' : 'areq.decision_revoke';
  return t(key, { who: d.decider, how: howDecided(d.factor_label), at: fmt(d.at_ms) });
}

export interface Fact {
  key: 'kind' | 'uid' | 'key_id' | 'run_id' | 'engine' | 'claimed';
  label: string;
  value: string;
  /** The requester's own word, never shown as a fact. */
  claimed: boolean;
}

const KIND_KEY: Record<string, MessageKey> = {
  'box-user': 'areq.kind_box_user',
  supervisor: 'areq.kind_supervisor',
  'root-helper': 'areq.kind_root_helper',
  'hub-agent': 'areq.kind_hub_agent',
  'laptop-key': 'areq.kind_laptop_key',
};

const SOCKET_KINDS: ReadonlySet<string> = new Set(['box-user', 'supervisor', 'root-helper']);

/**
 * Who filed it, each fact on its own line, exactly as the server sent it. A fact the server left empty is not shown, except the
 * user id of a requester that came over a socket (a box user, the supervisor, the root helper): where the operating system gives
 * no peer credential (a service not on Linux) the card says "not reported" rather than dropping the row, so a request with no
 * verified user is never taken for one that has it. A key-identified requester (a laptop key, a hub agent) has no user id to report.
 */
export function requesterFacts(r: Requester): Fact[] {
  const out: Fact[] = [{ key: 'kind', label: t('areq.requester_kind'), value: KIND_KEY[r.kind] ? t(KIND_KEY[r.kind] as MessageKey) : r.kind, claimed: false }];
  if (r.uid !== null) out.push({ key: 'uid', label: t('areq.requester_uid'), value: String(r.uid), claimed: false });
  else if (SOCKET_KINDS.has(r.kind)) out.push({ key: 'uid', label: t('areq.requester_uid'), value: t('areq.requester_uid_none'), claimed: false });
  if (r.key_id !== null) out.push({ key: 'key_id', label: t('areq.requester_key'), value: r.key_id, claimed: false });
  if (r.run_id !== null) out.push({ key: 'run_id', label: t('areq.requester_run'), value: r.run_id, claimed: false });
  if (r.engine !== null) out.push({ key: 'engine', label: t('areq.requester_engine'), value: r.engine, claimed: false });
  if (r.claimed !== null) out.push({ key: 'claimed', label: t('areq.requester_claimed'), value: r.claimed, claimed: true });
  return out;
}

export function sourceLabel(source: DisplayRow['source'] | string): string {
  if (source === 'service') return t('areq.source_service');
  if (source === 'root-helper') return t('areq.source_root_helper');
  if (source === 'from the box') return t('areq.source_box');
  return source;
}

export function originText(origin: string): string {
  return origin === 'local' ? t('areq.origin_local') : origin;
}

/** The request a link points at: `/approvals?request=<id>`. */
export function requestFromSearch(search: string): string | null {
  const id = new URLSearchParams(search).get('request');
  return id && id.length <= 128 ? id : null;
}

export function keyPresenceText(k: Pick<LaptopKey, 'presence'>): { label: string; help: string } {
  return k.presence === 'proved' ? { label: t('approvers.presence_proved'), help: t('approvers.presence_proved_help') } : { label: t('approvers.presence_none'), help: t('approvers.presence_none_help') };
}

export function enrolledViaText(via: string | null): string {
  if (via === null) return t('approvers.via_older');
  if (via === 'pinned') return t('approvers.via_pinned');
  if (via === 'root') return t('approvers.via_root');
  if (via === 'passkey') return t('approvers.via_passkey');
  const key = /^laptop-key:(.+)$/.exec(via);
  return key?.[1] ? t('approvers.via_laptop_key', { id: key[1] }) : via;
}

/** Cooling-off: a key whose activation is after now cannot decide yet. */
export function coolingUntil(k: Pick<LaptopKey, 'active_from_ms'>, now: number): number | null {
  return k.active_from_ms !== null && k.active_from_ms > now ? k.active_from_ms : null;
}
