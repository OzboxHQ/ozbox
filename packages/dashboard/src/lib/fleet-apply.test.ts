import { describe, expect, it } from 'vitest';

import { ApiError } from '../api/error';
import type { Info } from '../api/types';
import { en } from '../i18n/en';
import { fleetMode, fleetNotConnected, isDemo, managedFromThisBox } from './fleet';
import type { ApplyRequest, ApplyResponse } from '../api/types';
import { applyWithGates, FLEET_PASSKEY_CODE, FLEET_REFUSAL_CODES, needsFleetPasskey, withFleetAssertion, type ApplyDeps } from './fleet-apply';

const base = { version: '0', provider: 'aws', metrics: 'live', domain: null, capabilities: { resize: 'x', online_disk_grow: false, disk_shrink: false, snapshots: false }, sizes: [] } as Info;
const managed: Info = { ...base, fleet: { mode: 'managed', connected: true, demo: false, changes_need: ['change_window', 'owner_passkey'] } };
const assertion = { id: 'cred', response: { clientDataJSON: 'cd', authenticatorData: 'ad', signature: 'sig', userHandle: 'owner' } };

describe('a fleet managed from a box (ADR 0040)', () => {
  it('is a real fleet that is neither demo data nor "not connected"', () => {
    expect(fleetMode(managed)).toBe('managed');
    expect(managedFromThisBox(managed)).toBe(true);
    expect(fleetNotConnected(managed)).toBe(false);
    expect(isDemo(managed)).toBe(false);
    expect(managedFromThisBox(null)).toBe(false);
    expect(managedFromThisBox(base)).toBe(false);
  });

  it('asks for a passkey only on the refusal that a passkey answers', () => {
    expect(needsFleetPasskey(new ApiError(403, FLEET_PASSKEY_CODE, 'confirm'))).toBe(true);
    for (const code of FLEET_REFUSAL_CODES) expect(needsFleetPasskey(new ApiError(409, code, 'no'))).toBe(false);
    expect(needsFleetPasskey(new ApiError(403, 'step_up_required', 'no'))).toBe(false);
    expect(needsFleetPasskey(new Error('x'))).toBe(false);
  });

  it('applies the same plan, once, with the assertion added', () => {
    const req = { plan_id: 'p1', confirm_name: 'dev' };
    const out = withFleetAssertion(req, assertion);
    expect(out).toEqual({ plan_id: 'p1', confirm_name: 'dev', fleet_assertion: assertion });
    expect(req).toEqual({ plan_id: 'p1', confirm_name: 'dev' });
  });

  it('says what a change needs before anyone starts one', () => {
    expect(en['fleetnote.managed_title']).toBe('Managed from this box');
    expect(en['fleetnote.managed_body']).toContain('change window');
    expect(en['fleetnote.managed_body']).toContain('passkey');
  });
});

/** A server that answers like a box's dashboard that manages the fleet: no passkey, refused; this plan's passkey, applied once. */
function fakeServer(opts: { window: boolean; passkey?: 'ok' | 'cancel' }) {
  const asked: ApplyRequest[] = [];
  const challenges: string[] = [];
  let spent = false;
  const done = { plan: {}, applied: true, result: null } as unknown as ApplyResponse;
  const deps: ApplyDeps = {
    apply: (r) => {
      asked.push(r);
      if (spent) return Promise.reject(new ApiError(409, 'unknown_plan', 'used'));
      if (!opts.window) return Promise.reject(new ApiError(409, 'change_window_required', 'open a window'));
      if (r.fleet_assertion?.response.signature !== `sig-over-${r.plan_id}`) return Promise.reject(new ApiError(403, FLEET_PASSKEY_CODE, 'confirm'));
      spent = true;
      return Promise.resolve(done);
    },
    askStepUp: () => Promise.resolve(true),
    fleetChallenge: (id) => {
      challenges.push(id);
      return opts.window
        ? Promise.resolve({ options: { rpId: 'box.example.com', challenge: `ch-${id}` }, challenge: 'ab' })
        : Promise.reject(new ApiError(409, 'change_window_required', 'open a window'));
    },
    getPasskey: (o) =>
      opts.passkey === 'cancel'
        ? Promise.reject(new DOMException('closed', 'NotAllowedError'))
        : Promise.resolve({ id: 'c', response: { clientDataJSON: 'cd', authenticatorData: 'ad', signature: `sig-over-${o.challenge.slice(3)}`, userHandle: '' } }),
  };
  return { deps, asked, challenges };
}

describe('plan, then the passkey over that plan, then apply', () => {
  it('applies with the passkey made over this plan and asks for nothing else', async () => {
    const s = fakeServer({ window: true });
    await expect(applyWithGates({ plan_id: 'p1' }, s.deps)).resolves.toMatchObject({ applied: true });
    expect(s.challenges).toEqual(['p1']);
    expect(s.asked.map((r) => r.fleet_assertion?.response.signature ?? null)).toEqual([null, 'sig-over-p1']);
  });

  it('without a change window nothing is applied and the person is told why', async () => {
    const s = fakeServer({ window: false });
    await expect(applyWithGates({ plan_id: 'p1' }, s.deps)).rejects.toMatchObject({ code: 'change_window_required' });
    expect(s.asked).toHaveLength(1);
  });

  it('a closed passkey prompt applies nothing and keeps the first refusal', async () => {
    const s = fakeServer({ window: true, passkey: 'cancel' });
    await expect(applyWithGates({ plan_id: 'p1' }, s.deps)).rejects.toMatchObject({ code: FLEET_PASSKEY_CODE });
    expect(s.asked).toHaveLength(1);
  });

  it('a dashboard that does not manage the fleet never asks for the fleet passkey', async () => {
    const s = fakeServer({ window: true });
    const plain: ApplyDeps = { ...s.deps, apply: () => Promise.resolve({ plan: {}, applied: true, result: null } as unknown as ApplyResponse) };
    await applyWithGates({ plan_id: 'p1' }, plain);
    expect(s.challenges).toEqual([]);
  });
});
