import { describe, expect, it } from 'vitest';

import { createApiClient } from './client';

function fake(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

describe('the people api', () => {
  it('reads who has which role', async () => {
    const f = fake(200, { mode: 'session', me: { id: 'ann', role: 'owner' }, people: [], roles: ['owner', 'member', 'viewer'], can: {} });
    const c = createApiClient({ token: 't', fetchImpl: f.fetchImpl });
    const v = await c.people.list();
    expect(f.calls[0]?.url).toBe('/v1/people');
    expect(v.me.role).toBe('owner');
  });

  it('changes a role with a PUT that names the person and carries only the role', async () => {
    const f = fake(200, { id: 'a b', role: 'viewer', was: 'member' });
    const c = createApiClient({ token: 't', fetchImpl: f.fetchImpl });
    await c.people.setRole('a b', 'viewer');
    expect(f.calls[0]?.url).toBe('/v1/people/a%20b/role');
    expect(f.calls[0]?.init.method).toBe('PUT');
    expect(JSON.parse(String(f.calls[0]?.init.body))).toEqual({ role: 'viewer' });
  });
});
