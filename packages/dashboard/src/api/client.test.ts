import { describe, expect, it } from 'vitest';

import { ApiError, createApiClient } from './client';

function fake(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

describe('api client', () => {
  it('sends the bearer token and never caches', async () => {
    const f = fake(200, []);
    const c = createApiClient({ token: 'tok', fetchImpl: f.fetchImpl });
    await c.listBoxes();
    expect(f.calls[0]?.url).toBe('/v1/boxes');
    expect((f.calls[0]?.init.headers as Record<string, string>)['Authorization']).toBe('Bearer tok');
    expect(f.calls[0]?.init.cache).toBe('no-store');
  });

  it('posts plans and applies as JSON', async () => {
    const f = fake(200, {});
    const c = createApiClient({ token: 't', fetchImpl: f.fetchImpl });
    await c.plan({ op: 'pause', name: 'dev' });
    await c.apply({ plan_id: 'p', confirm_name: 'dev' });
    expect(f.calls.map((x) => x.url)).toEqual(['/v1/plans', '/v1/apply']);
    expect(JSON.parse(String(f.calls[0]?.init.body))).toEqual({ operation: { op: 'pause', name: 'dev' } });
    expect(JSON.parse(String(f.calls[1]?.init.body))).toEqual({ plan_id: 'p', confirm_name: 'dev' });
  });

  it('asks again while the box is getting ready and returns the change that follows', async () => {
    const answers = [
      { quiescing: true, retry_after_s: 2 },
      { quiescing: true },
      { plan: {}, applied: true, result: null },
    ];
    const calls: string[] = [];
    const waits: number[] = [];
    const fetchImpl = (async (url: string) => {
      calls.push(url);
      return new Response(JSON.stringify(answers.shift()), { status: calls.length < 3 ? 202 : 200, headers: { 'Content-Type': 'application/json' } });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl, sleepImpl: async (ms) => { waits.push(ms); } });
    const done = await c.apply({ plan_id: 'p' });
    expect(done.applied).toBe(true);
    expect(calls).toEqual(['/v1/apply', '/v1/apply', '/v1/apply']);
    expect(waits).toEqual([2000, 2000]);
  });

  it('gives up on a box that never finishes getting ready, saying nothing was changed', async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({ quiescing: true }), { status: 202, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl, sleepImpl: async () => {} });
    await expect(c.apply({ plan_id: 'p' })).rejects.toMatchObject({ code: 'quiesce_timeout' });
  });

  it('follows a change that runs in the background to its end and returns its answer', async () => {
    const answers = [
      { status: 202, body: { job_id: 'j1', job: { id: 'j1', state: 'running' } } },
      { status: 200, body: { id: 'j1', state: 'running' } },
      { status: 200, body: { id: 'j1', state: 'done', result: { applied: true, plan: {}, result: null } } },
    ];
    const urls: string[] = [];
    const fetchImpl = (async (url: string) => {
      urls.push(url);
      const a = answers.shift() ?? { status: 500, body: {} };
      return new Response(JSON.stringify(a.body), { status: a.status });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl, pollMs: 1 });
    const r = await c.apply({ plan_id: 'p' });
    expect(r.applied).toBe(true);
    expect(urls).toEqual(['/v1/apply', '/v1/jobs/j1', '/v1/jobs/j1']);
  });

  it('waits for the box to get ready, then follows the change that runs as a job', async () => {
    const answers = [
      { status: 202, body: { quiescing: true, retry_after_s: 2 } },
      { status: 202, body: { job_id: 'j3', job: { id: 'j3', state: 'running' } } },
      { status: 200, body: { id: 'j3', state: 'done', result: { applied: true, plan: {}, result: null } } },
    ];
    const urls: string[] = [];
    const waits: number[] = [];
    const fetchImpl = (async (url: string) => {
      urls.push(url);
      const a = answers.shift() ?? { status: 500, body: {} };
      return new Response(JSON.stringify(a.body), { status: a.status });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl, pollMs: 1, sleepImpl: async (ms) => { waits.push(ms); } });
    const r = await c.apply({ plan_id: 'p' });
    expect(r.applied).toBe(true);
    expect(urls).toEqual(['/v1/apply', '/v1/apply', '/v1/jobs/j3']);
    expect(waits).toEqual([2000]);
  });

  it('turns a failed background change into the same error the change gave', async () => {
    const answers = [
      { status: 202, body: { job_id: 'j2', job: { id: 'j2', state: 'running' } } },
      { status: 200, body: { id: 'j2', state: 'failed', status: 502, failure: { code: 'provider_error', message: 'the provider said no' } } },
    ];
    const fetchImpl = (async () => {
      const a = answers.shift() ?? { status: 500, body: {} };
      return new Response(JSON.stringify(a.body), { status: a.status });
    }) as unknown as typeof fetch;
    const c = createApiClient({ token: 't', fetchImpl, pollMs: 1 });
    await expect(c.apply({ plan_id: 'p' })).rejects.toMatchObject({ status: 502, code: 'provider_error', message: 'the provider said no' });
  });

  it('encodes names and the since timestamp', async () => {
    const f = fake(200, {});
    const c = createApiClient({ token: 't', fetchImpl: f.fetchImpl });
    await c.metricsSeries('dev', new Date('2026-11-09T12:00:00.000Z'), '1m');
    expect(f.calls[0]?.url).toBe('/v1/boxes/dev/metrics?since=2026-11-09T12%3A00%3A00.000Z&step=1m');
  });

  it('turns an error body into an ApiError', async () => {
    const c = createApiClient({ token: 't', fetchImpl: fake(409, { error: 'stale', code: 'stale_plan' }).fetchImpl });
    await expect(c.apply({ plan_id: 'p' })).rejects.toMatchObject({ status: 409, code: 'stale_plan', message: 'stale' });
  });

  it('reports an unreachable server plainly', async () => {
    const c = createApiClient({ token: 't', fetchImpl: (async () => { throw new TypeError('x'); }) as unknown as typeof fetch });
    await expect(c.listBoxes()).rejects.toBeInstanceOf(ApiError);
  });
});

describe('change requests', () => {
  it('lists, reads, asks for a challenge, approves with an assertion and denies', async () => {
    const f = fake(200, { request: {} });
    const c = createApiClient({ token: 't', fetchImpl: f.fetchImpl });
    await c.approvalRequests.list();
    await c.approvalRequests.get('r 1');
    await c.approvalRequests.challenge('r1');
    const assertion = { id: 'cred', response: { clientDataJSON: 'a', authenticatorData: 'b', signature: 'c', userHandle: '' } };
    await c.approvalRequests.approve('r1', assertion);
    await c.approvalRequests.deny('r1');
    expect(f.calls.map((x) => `${x.init.method} ${x.url}`)).toEqual([
      'GET /v1/approvals/requests',
      'GET /v1/approvals/requests/r%201',
      'POST /v1/approvals/requests/r1/challenge',
      'POST /v1/approvals/requests/r1/approve',
      'POST /v1/approvals/requests/r1/deny',
    ]);
    expect(JSON.parse(String(f.calls[3]?.init.body))).toEqual({ assertion });
    expect(JSON.parse(String(f.calls[2]?.init.body))).toEqual({});
  });

  it('lists the laptop keys and revokes one', async () => {
    const f = fake(200, { ok: true });
    const c = createApiClient({ token: 't', fetchImpl: f.fetchImpl });
    await c.approvalRequests.keys();
    await c.approvalRequests.revokeKey('lap/top');
    expect(f.calls.map((x) => `${x.init.method} ${x.url}`)).toEqual(['GET /v1/approvals/keys', 'POST /v1/approvals/keys/lap%2Ftop/revoke']);
  });

  it('hands a refusal to the caller with the server\'s sentence and code', async () => {
    const c = createApiClient({ token: 't', fetchImpl: fake(409, { code: 'already_decided', message: 'already approved by Alice on the dashboard (passkey), 12:03' }).fetchImpl });
    await expect(c.approvalRequests.deny('r1')).rejects.toMatchObject({ status: 409, code: 'already_decided', message: 'already approved by Alice on the dashboard (passkey), 12:03' });
  });
});

describe('error bodies', () => {
  it('reads a nested error object like the flat one', async () => {
    const c = createApiClient({ token: 't', fetchImpl: fake(403, { error: { code: 'not_allowed', message: 'only an owner decides this' } }).fetchImpl });
    await expect(c.approvalRequests.deny('r1')).rejects.toMatchObject({ status: 403, code: 'not_allowed', message: 'only an owner decides this' });
  });
});
