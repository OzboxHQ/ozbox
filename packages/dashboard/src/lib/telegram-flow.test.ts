import { describe, expect, it } from 'vitest';

import { CHAT_ACTS } from '../api/chat-acts';
import { delegationStateText, linkIsLive, linkStateText, normaliseCode, pointerToken, safeInternalPath, validDays } from './telegram-flow';

describe('the Telegram flow helpers', () => {
  it('a delegation lasts whole days from 1 to 30 and nothing else', () => {
    expect(validDays('7')).toBe(7);
    expect(validDays('30')).toBe(30);
    for (const bad of ['0', '31', '-1', '1.5', '', ' ', '1e1', 'seven', '07x']) expect(validDays(bad), bad).toBeNull();
  });

  it('a code is trimmed and upper-cased, never reshaped', () => {
    expect(normaliseCode(' ab cd2 345 ')).toBe('ABCD2345');
  });

  it('a pointer link opens only for a fragment that holds 48 hex characters', () => {
    const t = 'ab'.repeat(24);
    expect(pointerToken(`#${t}`)).toBe(t);
    for (const bad of ['', '#', `#${t}x`, `#${t.slice(1)}`, `${t}`, `#token=${t}`, `#${'g'.repeat(48)}`]) expect(pointerToken(bad), bad).toBeNull();
  });

  it('the page a pointer names is a path inside this dashboard and nothing that leaves it', () => {
    expect(safeInternalPath('/chat')).toBe('/chat');
    expect(safeInternalPath('/settings/apps')).toBe('/settings/apps');
    expect(safeInternalPath('/approvals?request=R1a-2_b')).toBe('/approvals?request=R1a-2_b');
    for (const bad of ['//evil.example', 'https://evil.example', 'javascript:alert(1)', '/a?b=c', '/a#b', 'chat', '', '/\\evil', '/approvals?request=a&next=//evil.example', '/approvals?request=', '/approvals?request=a/b']) expect(safeInternalPath(bad), bad).toBeNull();
  });

  it('every state a link or a delegation can be in has words', () => {
    for (const s of ['active', 'locked', 'revoked', 'not_genuine'] as const) expect(linkStateText(s)).not.toMatch(/^tg\./);
    for (const s of ['active', 'waiting', 'pending_owner', 'expired', 'lapsed', 'not_yet', 'not_genuine', 'revoked'] as const) expect(delegationStateText(s)).not.toMatch(/^tg\./);
    expect(linkIsLive('active') && linkIsLive('locked')).toBe(true);
    expect(linkIsLive('revoked') || linkIsLive('not_genuine')).toBe(false);
  });
});

describe('the table of acts the dashboard shows (generated from the server)', () => {
  it('has unique permanent keys and the shape of its tiers', () => {
    const ids = CHAT_ACTS.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const a of CHAT_ACTS) {
      if (a.tier === 'converse') expect(a.needs).toBe('converse');
      if (a.tier === 'power') expect(a.needs).toBe('power');
      if (a.tier === 'run') expect(a.needs).toBe('run');
      if (['read', 'handoff', 'refused'].includes(a.tier)) expect(a.needs).toBe('nothing');
      if (a.safe) expect(a.tier).toBe('read');
      if (!a.built) expect(['power', 'run']).toContain(a.tier);
    }
  });

  it('refuses every way of approving, denying, stopping, spending and reaching a secret, and never lists a free-form command', () => {
    const refused = CHAT_ACTS.filter((a) => a.tier === 'refused').map((a) => a.id);
    for (const k of ['refused.approve', 'refused.deny', 'refused.stop', 'refused.budget', 'refused.secrets', 'refused.governance', 'refused.outbound', 'refused.not_in_table']) expect(refused).toContain(k);
    // /run is the shipped catalogue only, and it is not built in this release
    const run = CHAT_ACTS.find((a) => a.id === 'run');
    expect(run?.built).toBe(false);
    expect(run?.about).toMatch(/catalogue/);
    expect(run?.about).toMatch(/Never a free-form command/);
    // creating and resizing a box are power acts (owner decision D14); clone, snapshot and destroy are only ever the dashboard's
    expect(CHAT_ACTS.find((a) => a.id === 'box.create')?.tier).toBe('power');
    expect(CHAT_ACTS.find((a) => a.id === 'box.resize')?.tier).toBe('power');
    for (const k of ['box.clone', 'box.snapshot', 'box.destroy']) expect(CHAT_ACTS.find((a) => a.id === k)?.tier).toBe('handoff');
    // only lock and unlink make Telegram less able without a delegation
    expect(CHAT_ACTS.filter((a) => a.safe).map((a) => a.id).sort()).toEqual(['lock', 'unlink']);
  });
});
