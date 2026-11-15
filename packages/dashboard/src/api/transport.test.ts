import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from './error';
import { createSessionApi } from './session';
import { openTerminal } from './terminal';
import { createTransport, UNREACHABLE } from './transport';

function recorder(status: number, body: unknown, ctype = 'application/json') {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'Content-Type': ctype } });
  }) as unknown as typeof fetch;
  return { calls, impl };
}
const h = (c: { init: RequestInit } | undefined) => (c?.init.headers ?? {}) as Record<string, string>;

describe('the one transport', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('carries the token on every kind of call: JSON, text, raw and blob', async () => {
    const { calls, impl } = recorder(200, {});
    const tr = createTransport({ token: 'tok', fetchImpl: impl });
    await tr.request('GET', '/a');
    await tr.requestText('PUT', '/b', 'text');
    await tr.send('POST', '/c', { body: new Uint8Array([1]), contentType: 'application/octet-stream' });
    await tr.blob('/d');
    expect(calls.map((c) => h(c)['Authorization'])).toEqual(['Bearer tok', 'Bearer tok', 'Bearer tok', 'Bearer tok']);
    expect(h(calls[1])['Content-Type']).toBe('text/plain; charset=utf-8');
    expect(h(calls[2])['Content-Type']).toBe('application/octet-stream');
  });

  it('sends the session CSRF token on a change, never on a read', async () => {
    const { calls, impl } = recorder(200, {});
    const tr = createTransport({ csrf: () => 'c1', fetchImpl: impl });
    await tr.request('GET', '/a');
    await tr.request('POST', '/b', {});
    await tr.requestText('PUT', '/c', 'x');
    expect(h(calls[0])['X-Ozbox-CSRF']).toBeUndefined();
    expect(h(calls[1])['X-Ozbox-CSRF']).toBe('c1');
    expect(h(calls[2])['X-Ozbox-CSRF']).toBe('c1');
  });

  it('turns an unreachable server into one error with one wording, for every caller', async () => {
    const down = (async () => {
      throw new TypeError('failed to fetch');
    }) as unknown as typeof fetch;
    const tr = createTransport({ token: 't', fetchImpl: down });
    for (const call of [() => tr.request('GET', '/a'), () => tr.requestText('PUT', '/b', 'x'), () => tr.send('GET', '/c'), () => tr.blob('/d')]) {
      await expect(call()).rejects.toMatchObject({ status: 0, code: 'network', message: UNREACHABLE });
    }
    // the terminal's open call and the sign-in layer say the same words
    await expect(openTerminal('b', 80, 24, { onReady() {}, onData() {}, onExit() {}, onError() {}, onLost() {} }, tr)).rejects.toMatchObject({ message: UNREACHABLE });
    await expect(createSessionApi({ fetchImpl: down }).status()).rejects.toMatchObject({ message: UNREACHABLE });
  });

  it('lets an abort through as an abort', async () => {
    const aborted = (async () => {
      throw new DOMException('x', 'AbortError');
    }) as unknown as typeof fetch;
    const tr = createTransport({ token: 't', fetchImpl: aborted });
    await expect(tr.request('GET', '/a')).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('says a session ended (401) behind a sign-in, once, for JSON, files and uploads alike; not for a token, and not for the sign-in calls', async () => {
    const seen: number[] = [];
    const on = (e: Event) => seen.push((e as CustomEvent<number>).detail);
    const w = new EventTarget() as EventTarget & { dispatchEvent: (e: Event) => boolean };
    vi.stubGlobal('window', Object.assign(w, { addEventListener: w.addEventListener.bind(w) }));
    vi.stubGlobal('CustomEvent', class extends Event {
      detail: number;
      constructor(type: string, init: { detail: number }) {
        super(type);
        this.detail = init.detail;
      }
    });
    w.addEventListener('ozbox:unauthorized', on);
    const { impl } = recorder(401, { code: 'unauthorized', message: 'no' });
    const session = createTransport({ csrf: () => 'c', fetchImpl: impl });
    await expect(session.request('GET', '/v1/x')).rejects.toBeInstanceOf(ApiError);
    await expect(session.blob('/v1/y')).rejects.toBeInstanceOf(ApiError);
    expect(seen).toEqual([401, 401]);
    const token = createTransport({ token: 't', fetchImpl: impl });
    await expect(token.request('GET', '/v1/x')).rejects.toBeInstanceOf(ApiError);
    const signIn = createTransport({ csrf: () => 'c', fetchImpl: impl, sessionEnds: false });
    await expect(signIn.request('POST', '/auth/x', {})).rejects.toBeInstanceOf(ApiError);
    expect(seen).toEqual([401, 401]);
  });

  it('opens a terminal through the transport, with the target the server names', async () => {
    const { calls, impl } = recorder(200, { session: 'abc', target: { box: 'dev', source: 'live', runs_as: 'box_user' } });
    const tr = createTransport({ token: 't', fetchImpl: impl });
    let said: unknown = null;
    // the output stream is read on its own; give it an answer that ends at once
    const both = (async (url: string, init: RequestInit) => {
      if (url.endsWith('/output')) return new Response(null, { status: 200 });
      return impl(url, init);
    }) as unknown as typeof fetch;
    const t2 = createTransport({ token: 't', fetchImpl: both });
    const c = await openTerminal('dev', 80, 24, { onReady() {}, onData() {}, onExit() {}, onError() {}, onLost() {} }, t2, undefined, (x) => (said = x));
    expect(said).toEqual({ box: 'dev', source: 'live', runs_as: 'box_user' });
    expect(calls[0]?.url).toBe('/v1/boxes/dev/terminal');
    expect(h(calls[0])['Authorization']).toBe('Bearer t');
    await c.close();
    void tr;
  });
});
