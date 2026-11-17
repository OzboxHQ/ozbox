import { describe, expect, it } from 'vitest';

import { createBackupsApi } from './backups';
import { createTransport } from './transport';

function fakeFetch(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { calls, impl };
}

describe('backups api', () => {
  it('turns a box off with a POST to its own off endpoint and sends no body', async () => {
    const { calls, impl } = fakeFetch(200, { ok: true, box: 'my box' });
    const api = createBackupsApi(createTransport({ token: 'tok', fetchImpl: impl }).request);
    await api.turnOff('my box');
    expect(calls[0]?.url).toBe('/v1/boxes/my%20box/backups/off');
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.init.body).toBeUndefined();
  });

  it('does not use the credentials endpoint for it (that one only removes credentials and leaves the schedule on)', async () => {
    const { calls, impl } = fakeFetch(200, { ok: true });
    const api = createBackupsApi(createTransport({ token: 'tok', fetchImpl: impl }).request);
    await api.turnOff('dev');
    expect(calls[0]?.url).not.toContain('credentials');
  });
});
