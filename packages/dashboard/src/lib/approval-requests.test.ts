import { describe, expect, it } from 'vitest';

import type { RequestCard } from '../api/approval-requests';
import { REQUEST_SCOPES } from '../api/approval-requests';
import { en } from '../i18n/en';
import {
  coolingUntil,
  decisionLine,
  enrolledViaText,
  howDecided,
  readOnly,
  refusals,
  requestFromSearch,
  requesterFacts,
  ruleFor,
  scopeName,
  shortDigest,
  sortRequests,
  stateVariant,
  timeLeft,
  timeText,
} from './approval-requests';

const can = (approve: boolean, deny: boolean, ar: string | null = null, dr: string | null = null) => ({ approve: { allowed: approve, reason: ar }, deny: { allowed: deny, reason: dr } });

function card(over: Partial<RequestCard> = {}): RequestCard {
  return {
    id: 'r1',
    scope: 'guard-override',
    state: 'pending',
    origin: 'local',
    subject_digest: 'ab'.repeat(32),
    display: [{ label: 'Repository', value: 'web', source: 'service' }],
    reason: 'a public url',
    requester: { kind: 'box-user', uid: 1000, key_id: null, run_id: 'run-1', engine: 'claude', claimed: 'I am the build agent' },
    filed_at_ms: 1000,
    expires_at_ms: 100_000,
    not_before_ms: 0,
    decision: null,
    replaces: null,
    superseded_by: null,
    void_reason: null,
    can: can(true, true),
    ...over,
  };
}

describe('scope names', () => {
  it('has a name for every scope the box can send, and passes an unknown one through as sent', () => {
    for (const s of REQUEST_SCOPES) expect(scopeName(s), s).not.toBe(s);
    expect(scopeName('something-new')).toBe('something-new');
  });
  it('every scope has its catalogue key', () => {
    for (const s of REQUEST_SCOPES) expect(Object.keys(en)).toContain(`areq.scope_${s.replace(/-/g, '_')}`);
  });
});

describe('sorting', () => {
  it('puts pending first, then approved, then finished, newest first in each', () => {
    const list = [
      card({ id: 'a', state: 'denied', filed_at_ms: 9 }),
      card({ id: 'b', state: 'approved', filed_at_ms: 1 }),
      card({ id: 'c', state: 'pending', filed_at_ms: 2 }),
      card({ id: 'd', state: 'pending', filed_at_ms: 5 }),
      card({ id: 'e', state: 'spent', filed_at_ms: 3 }),
      card({ id: 'f', state: 'spending', filed_at_ms: 8 }),
    ];
    expect(sortRequests(list).map((c) => c.id)).toEqual(['d', 'c', 'f', 'b', 'a', 'e']);
  });
  it('does not change the list it is given', () => {
    const list = [card({ id: 'a', state: 'denied' }), card({ id: 'b' })];
    sortRequests(list);
    expect(list[0]?.id).toBe('a');
  });
});

describe('badges', () => {
  it('maps a state to a variant', () => {
    expect(stateVariant('pending')).toBe('default');
    expect(stateVariant('approved')).toBe('secondary');
    expect(stateVariant('denied')).toBe('destructive');
    expect(stateVariant('expired')).toBe('outline');
    expect(stateVariant('from-the-future')).toBe('outline');
  });
});

describe('time', () => {
  it('says cooling-off before not_before, time left after, expired at the end, nothing when finished', () => {
    expect(timeLeft(card({ not_before_ms: 5000 }), 1000)).toEqual({ kind: 'cooling', ms: 4000 });
    expect(timeLeft(card(), 1000)).toEqual({ kind: 'left', ms: 99_000 });
    expect(timeLeft(card(), 100_000)).toEqual({ kind: 'expired' });
    expect(timeLeft(card({ state: 'denied' }), 1000)).toEqual({ kind: 'none' });
  });
  it('words it', () => {
    expect(timeText(card({ not_before_ms: 5000 }), 1000)).toContain('Cooling-off');
    expect(timeText(card({ expires_at_ms: 1000 + 125 * 60_000 }), 1000)).toBe('2 h 5 min left');
    expect(timeText(card({ expires_at_ms: 1000 + 30_000 }), 1000)).toBe('less than a minute left');
    expect(timeText(card({ state: 'spent' }), 1000)).toBeNull();
  });
});

describe('the rule line and the read-only state', () => {
  it('needs a passkey when the viewer may approve', () => {
    expect(ruleFor(card(), 'owner')).toBe('passkey');
  });
  it('says owner only for a member who is refused, and nothing of its own for a viewer or no sign-in', () => {
    const c = card({ can: can(false, false, 'only an owner decides this') });
    expect(ruleFor(c, 'member')).toBe('owner-only');
    expect(ruleFor(c, 'viewer')).toBeNull();
    expect(ruleFor(c, null)).toBeNull();
  });
  it('is read only when neither decision is allowed, and shows the server sentences as they are', () => {
    const c = card({ can: can(false, false, 'a viewer cannot decide', 'a viewer cannot decide') });
    expect(readOnly(c)).toBe(true);
    expect(refusals(c)).toEqual(['a viewer cannot decide']);
  });
  it('is not read only when the viewer may deny, and a finished card never shows refusals', () => {
    expect(readOnly(card({ can: can(false, true, 'owner only') }))).toBe(false);
    expect(readOnly(card({ state: 'approved', can: can(false, true) }))).toBe(false);
    expect(readOnly(card({ state: 'spent' }))).toBe(true);
    expect(refusals(card({ state: 'spent', can: can(false, false, 'x', 'y') }))).toEqual([]);
  });
});

describe('the decision line', () => {
  const fmt = () => '12:03';
  it('names who, how and when', () => {
    const d = { outcome: 'approve' as const, decider: 'Alice', role: 'owner' as const, surface: 'dashboard' as const, factor_label: 'passkey', presence: 'proved' as const, at_ms: 1 };
    expect(decisionLine(card({ decision: d }), fmt)).toBe('Approved by Alice, passkey, 12:03');
    expect(decisionLine(card({ decision: { ...d, outcome: 'deny', factor_label: 'chat-deny' } }), fmt)).toBe('Denied by Alice, chat deny, 12:03');
    expect(decisionLine(card({ decision: { ...d, outcome: 'revoke' } }), fmt)).toBe('Approval withdrawn by Alice, passkey, 12:03');
    expect(decisionLine(card(), fmt)).toBeNull();
  });
  it('says a laptop key and whether a person was there', () => {
    expect(howDecided('laptop-key:work')).toBe('laptop key work');
    expect(howDecided('laptop-key:work (no user presence)')).toBe('laptop key work, without user presence');
    expect(howDecided('something else')).toBe('something else');
  });
});

describe('the requester', () => {
  it('lists each fact the server sent and labels the requester\'s own word', () => {
    const facts = requesterFacts(card().requester);
    expect(facts.map((f) => f.key)).toEqual(['kind', 'uid', 'run_id', 'engine', 'claimed']);
    expect(facts.find((f) => f.key === 'claimed')?.claimed).toBe(true);
    expect(facts.find((f) => f.key === 'uid')?.value).toBe('1000');
    expect(facts.filter((f) => f.key !== 'claimed').every((f) => !f.claimed)).toBe(true);
  });
  it('keeps text exactly as sent, markup included', () => {
    const facts = requesterFacts({ kind: 'box-user', uid: null, key_id: null, run_id: null, engine: null, claimed: '<img src=x onerror=alert(1)>' });
    expect(facts.find((f) => f.key === 'claimed')?.value).toBe('<img src=x onerror=alert(1)>');
  });
  it('keeps the user id row of a socket requester when the system reported none, and says so', () => {
    for (const kind of ['box-user', 'supervisor', 'root-helper'] as const) {
      const facts = requesterFacts({ kind, uid: null, key_id: null, run_id: null, engine: null, claimed: null });
      expect(facts.map((f) => f.key)).toEqual(['kind', 'uid']);
      expect(facts.find((f) => f.key === 'uid')?.value).toBe('not reported');
    }
  });
  it('has no user id row for a requester identified by a key', () => {
    for (const kind of ['laptop-key', 'hub-agent'] as const) {
      const facts = requesterFacts({ kind, uid: null, key_id: 'k1', run_id: null, engine: null, claimed: null });
      expect(facts.map((f) => f.key)).toEqual(['kind', 'key_id']);
    }
  });
});

describe('small things', () => {
  it('shows the first 16 of a digest', () => expect(shortDigest('0123456789abcdef0123')).toBe('0123456789abcdef'));
  it('reads the request a link points at', () => {
    expect(requestFromSearch('?request=abc-123')).toBe('abc-123');
    expect(requestFromSearch('')).toBeNull();
    expect(requestFromSearch('?request=' + 'x'.repeat(200))).toBeNull();
  });
  it('words how a key was enrolled', () => {
    expect(enrolledViaText(null)).toBe('an older enrolment');
    expect(enrolledViaText('laptop-key:work')).toBe('laptop key work');
    expect(enrolledViaText('pinned')).toBe('pinned on the box');
  });
  it('finds the end of a key\'s cooling-off only while it is ahead', () => {
    expect(coolingUntil({ active_from_ms: 5000 }, 1000)).toBe(5000);
    expect(coolingUntil({ active_from_ms: 500 }, 1000)).toBeNull();
    expect(coolingUntil({ active_from_ms: null }, 1000)).toBeNull();
  });
});
