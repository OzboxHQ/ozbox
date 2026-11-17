import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ApiError, errorFrom } from '../api/error';
import { createApiClient } from '../api/client';
import type { ApplyResponse, PlanResponse, SelfTest } from '../api/types';
import { en } from '../i18n/en';
import { isMachineMissing, stateLabel } from './format';
import { t } from './i18n';
import { applyRequest, canConfirm, flowReducer, IMAGE_UNVERIFIED_CODE, idle, ops, SECRETS_KEY_HELD_CODE, SECRETS_STORE_LOST_CODE } from './plan-flow';
import { followUpgrade } from './upgrade-follow';

const here = dirname(fileURLToPath(import.meta.url));

const passing: SelfTest = { ts_ms: 1, ok: true, all_verified: true, checks: [{ name: 'work disk mounted', outcome: 'pass' }] };

function clock() {
  let t = 0;
  const waits: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      waits.push(ms);
      t += ms;
    },
    waits,
  };
}

describe('following an upgrade', () => {
  it('shows the self-test as soon as the box answers', async () => {
    const c = clock();
    const r = await followUpgrade(async () => passing, { intervalMs: 5000, timeoutMs: 60000, ...c });
    expect(r).toEqual({ kind: 'result', test: passing });
    expect(c.waits).toEqual([]);
  });

  it('keeps asking while the box is starting (unreachable, not running) and then shows the result', async () => {
    const c = clock();
    const answers = [new ApiError(502, 'agent_unreachable', 'the agent is starting'), new ApiError(409, 'box_not_running', 'the box is resuming')];
    const seen: string[] = [];
    const r = await followUpgrade(
      async () => {
        const next = answers.shift();
        if (next) throw next;
        return passing;
      },
      { intervalMs: 5000, timeoutMs: 60000, onWait: (_ms, reason) => seen.push(reason), ...c },
    );
    expect(r.kind).toBe('result');
    expect(c.waits).toEqual([5000, 5000]);
    expect(seen).toEqual(['the agent is starting', 'the box is resuming']);
  });

  it('gives up with the last reason, never a pass', async () => {
    const c = clock();
    const r = await followUpgrade(
      async () => {
        throw new ApiError(502, 'agent_unreachable', 'no route to the box');
      },
      { intervalMs: 5000, timeoutMs: 20000, ...c },
    );
    expect(r).toEqual({ kind: 'timeout', reason: 'no route to the box' });
    expect(c.waits.length).toBeGreaterThan(0);
  });

  it('says plainly when this server cannot reach box agents at all', async () => {
    const c = clock();
    const r = await followUpgrade(
      async () => {
        throw new ApiError(501, 'agent_unreachable', 'needs SSH forwarding');
      },
      { intervalMs: 5000, timeoutMs: 60000, ...c },
    );
    expect(r).toEqual({ kind: 'unsupported', reason: 'needs SSH forwarding' });
    expect(c.waits).toEqual([]);
  });

  it('does not wait on an error that waiting cannot fix, and stops when the page is left', async () => {
    const c = clock();
    const forbidden = await followUpgrade(
      async () => {
        throw new ApiError(403, 'forbidden', 'not allowed');
      },
      { intervalMs: 5000, timeoutMs: 60000, ...c },
    );
    expect(forbidden).toEqual({ kind: 'timeout', reason: 'not allowed' });
    const ctl = new AbortController();
    ctl.abort();
    const stopped = await followUpgrade(async () => passing, { intervalMs: 5000, timeoutMs: 60000, signal: ctl.signal, ...clock() });
    expect(stopped.kind).toBe('timeout');
  });
});

describe('the upgrade flow', () => {
  const plan: PlanResponse = {
    plan_id: 'p1',
    plan: {
      operation: ops.upgrade('main', 'ami-new'),
      provider: 'aws',
      changes: [{ kind: 'instance.replace_image', description: 'Replace the system disk of main; the /work disk is NOT touched', risk: 'medium' }],
      notes: [],
      based_on: 'b',
    },
    box_name: 'main',
    max_risk: 'medium',
    noop: false,
    requires_confirm_name: false,
    expires_in_s: 600,
  };

  it('is plan, review, apply like every other change, and needs no typed name (nothing is lost)', () => {
    let s = flowReducer(idle, { type: 'start', operation: ops.upgrade('main', 'latest') });
    expect(s.phase).toBe('planning');
    s = flowReducer(s, { type: 'planned', plan });
    expect(canConfirm(s)).toBe(true);
    s = flowReducer(s, { type: 'confirm' });
    expect(applyRequest(s)).toEqual({ plan_id: 'p1', plan: plan.plan });
    const response: ApplyResponse = { plan: plan.plan, applied: true, result: null, upgrade: { image: 'ami-new', checkpoint: { outcome: 'done', detail: 'Saved' } } };
    s = flowReducer(s, { type: 'applied', response });
    expect(s.phase).toBe('done');
  });

  it('asks for the newest image by the word latest and sends it as an upgrade operation', async () => {
    const calls: { url: string; body: string }[] = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({ url, body: String(init.body ?? '') });
      return new Response(JSON.stringify({ box_name: 'main', current: null, latest: null, latest_error: null, upgrade_available: null, unfinished_upgrade_to: null }), { status: 200 });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl });
    await c.boxImage('main');
    await c.plan(ops.upgrade('main', 'latest'));
    expect(calls[0]?.url).toBe('/v1/boxes/main/image');
    expect(JSON.parse(calls[1]?.body ?? '{}')).toEqual({ operation: { op: 'upgrade', name: 'main', image: 'latest' } });
  });
});

describe('upgrade text', () => {
  it('every message the sheet uses is in the catalogue, and none is typed into the component', () => {
    const src = readFileSync(join(here, '../components/upgrade-sheet.tsx'), 'utf8');
    const used = [...src.matchAll(/\bt\('([a-z_.]+)'/g)].map((m) => m[1] ?? '');
    expect(used.length).toBeGreaterThan(15);
    for (const k of used) expect(Object.keys(en), k).toContain(k);
    // the one sentence a person reads about /work is in the catalogue too
    expect(en['upgrade.intro']).toContain('/work');
    expect(en['upgrade.signature_not_verified']).toContain('NOT verified');
    expect(en['upgrade.allow_unverified']).toBe('Upgrade anyway to an unverified image');
  });

  it('every message the box pages use for a box with no machine is in the catalogue', () => {
    for (const k of ['state.instance_missing', 'box.missing_hint', 'box.missing_finish', 'box.missing_destroy', 'menu.finish_upgrade', 'card.missing', 'destroy.description_missing', 'upgrade.finish_title']) {
      expect(Object.keys(en), k).toContain(k);
    }
    expect(en['box.missing_hint']).toBe('The machine is missing and /work is kept. Finish the upgrade.');
  });
});

describe('a box whose machine is missing', () => {
  it('is named in words, never by its code, and is the one state finishing is offered for', () => {
    expect(stateLabel('instance_missing')).toBe('Machine missing');
    expect(isMachineMissing('instance_missing')).toBe(true);
    for (const s of ['running', 'paused', 'unknown'] as const) expect(isMachineMissing(s)).toBe(false);
  });
});

describe('an image the server refuses because it could not be verified', () => {
  const refused = new ApiError(409, 'image_unverified', 'Refusing to upgrade main to image ami-x: its signature was not verified');

  it('is a code the page recognises, and only the person asking by name sends the override', async () => {
    expect(IMAGE_UNVERIFIED_CODE).toBe(refused.code);
    const bodies: unknown[] = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body ?? '{}')));
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl });
    await c.plan(ops.upgrade('main', 'ami-x'), undefined, { allowUnverifiedImage: true });
    await c.plan(ops.upgrade('main', 'ami-x'), undefined, { allowUnverifiedImage: false });
    expect(bodies[0]).toEqual({ operation: { op: 'upgrade', name: 'main', image: 'ami-x' }, allow_unverified_image: true });
    expect(bodies[1]).toEqual({ operation: { op: 'upgrade', name: 'main', image: 'ami-x' } });
  });

  it('is asked again from the refusal, and the override survives only into the planning that was asked for', () => {
    let s = flowReducer(idle, { type: 'start', operation: ops.upgrade('main', 'ami-x') });
    expect(s).toEqual({ phase: 'planning', operation: ops.upgrade('main', 'ami-x') });
    s = flowReducer(s, { type: 'failed', message: refused.message, code: refused.code });
    expect(s).toMatchObject({ phase: 'error', code: 'image_unverified' });
    s = flowReducer(s, { type: 'start', operation: ops.upgrade('main', 'ami-x'), allowUnverified: true });
    expect(s).toEqual({ phase: 'planning', operation: ops.upgrade('main', 'ami-x'), allowUnverified: true });
  });

  it('carries the server\'s own reason, and the page says it in its own words, never with the command\'s flag', async () => {
    const body = { code: 'image_unverified', message: 'Refusing ... pass --allow-unverified-image to use it anyway.', image: 'ami-x', signature_detail: 'no signature was found' };
    const err = await errorFrom(new Response(JSON.stringify(body), { status: 409 }));
    expect(err.details['signature_detail']).toBe('no signature was found');
    const s = flowReducer(flowReducer(idle, { type: 'start', operation: ops.upgrade('main', 'ami-x') }), { type: 'failed', message: err.message, code: err.code, detail: 'no signature was found' });
    expect(s).toMatchObject({ phase: 'error', detail: 'no signature was found' });
    for (const key of ['upgrade.refused_reason', 'upgrade.refused_no_reason'] as const) {
      expect(t(key, { image: 'ami-x', detail: 'no signature was found' })).not.toContain('--');
    }
    expect(t('upgrade.refused_reason', { image: 'ami-x', detail: 'no signature was found' })).toContain('no signature was found');
  });
});

// A security review (2026-11-11): the second upgrade of a default box lost its secrets store without a word. The server now
// refuses such an upgrade with the loss named, and the page asks the person to accept a new store by name.
describe('an upgrade that would start a new secrets store', () => {
  const refused = new ApiError(409, 'secrets_store_lost', 'Secrets store: LOST. main keeps its store key in a file...');

  it('is a code the page recognises, and only an acceptance by name sends it', async () => {
    expect(SECRETS_STORE_LOST_CODE).toBe(refused.code);
    const bodies: unknown[] = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body ?? '{}')));
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl });
    await c.plan(ops.upgrade('main', 'ami-x'), undefined, { acceptNewSecretsStore: true });
    await c.plan(ops.upgrade('main', 'ami-x'), undefined, { acceptNewSecretsStore: true, allowUnverifiedImage: true });
    await c.plan(ops.upgrade('main', 'ami-x'));
    expect(bodies[0]).toEqual({ operation: { op: 'upgrade', name: 'main', image: 'ami-x' }, accept_new_secrets_store: true });
    expect(bodies[1]).toEqual({ operation: { op: 'upgrade', name: 'main', image: 'ami-x' }, allow_unverified_image: true, accept_new_secrets_store: true });
    expect(bodies[2]).toEqual({ operation: { op: 'upgrade', name: 'main', image: 'ami-x' } });
  });

  it('also offers the acceptance when a copy of the store key is held (the server code is secrets_key_held)', () => {
    expect(SECRETS_KEY_HELD_CODE).toBe('secrets_key_held');
  });

  it('is asked again from the refusal, and the acceptance lives only in the planning it was given for', () => {
    let s = flowReducer(idle, { type: 'start', operation: ops.upgrade('main', 'ami-x') });
    s = flowReducer(s, { type: 'failed', message: refused.message, code: refused.code });
    expect(s).toMatchObject({ phase: 'error', code: 'secrets_store_lost' });
    s = flowReducer(s, { type: 'start', operation: ops.upgrade('main', 'ami-x'), acceptNewStore: true });
    expect(s).toEqual({ phase: 'planning', operation: ops.upgrade('main', 'ami-x'), acceptNewStore: true });
    expect(t('upgrade.accept_new_store_hint')).toContain('never deleted');
  });
});
