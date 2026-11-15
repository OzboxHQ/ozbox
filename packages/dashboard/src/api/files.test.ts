import { describe, expect, it } from 'vitest';

import { ApiError } from './error';
import { createFilesApi } from './files';
import { createTransport } from './transport';

function fakeFetch(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { calls, impl };
}

describe('files api', () => {
  it('lists with an encoded path and the token', async () => {
    const { calls, impl } = fakeFetch(200, { entries: [] });
    const api = createFilesApi(createTransport({ token: 'tok', fetchImpl: impl }));
    await api.list('my box', '/work/a b&c', { sort: 'size', order: 'desc', hidden: true });
    expect(calls[0]?.url).toBe('/v1/boxes/my%20box/files/list?path=%2Fwork%2Fa%20b%26c&sort=size&order=desc&hidden=1');
    expect((calls[0]?.init.headers as Record<string, string>)['Authorization']).toBe('Bearer tok');
  });

  it('saves with the hash it opened', async () => {
    const { calls, impl } = fakeFetch(200, { hash: 'h2', size: 3 });
    const api = createFilesApi(createTransport({ token: 't', fetchImpl: impl }));
    await api.write('b', '/work/a.txt', 'abc', 'h1');
    expect(calls[0]?.url).toContain('if_match=h1');
    expect(calls[0]?.init.method).toBe('PUT');
    expect(calls[0]?.init.body).toBe('abc');
  });

  it('turns a stale save into an ApiError with its code', async () => {
    const { impl } = fakeFetch(409, { code: 'stale', message: 'changed' });
    const api = createFilesApi(createTransport({ token: 't', fetchImpl: impl }));
    await expect(api.write('b', '/work/a.txt', 'x', 'old')).rejects.toMatchObject({ status: 409, code: 'stale' });
    await expect(api.write('b', '/work/a.txt', 'x', 'old')).rejects.toBeInstanceOf(ApiError);
  });

  it('builds a link a browser can follow without a header', () => {
    const api = createFilesApi(createTransport({ token: 't' }));
    expect(api.downloadUrl('dev', 'abc.123.def')).toBe('/dl/dev/abc.123.def');
  });

  it('uploads with progress and can be cancelled', async () => {
    class FakeXhr {
      method = '';
      url = '';
      headers: Record<string, string> = {};
      status = 0;
      responseText = '';
      upload: { onprogress: ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null } = { onprogress: null };
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      open(m: string, u: string) {
        this.method = m;
        this.url = u;
      }
      setRequestHeader(k: string, v: string) {
        this.headers[k] = v;
      }
      send() {}
      abort() {
        this.onabort?.();
      }
    }
    const x = new FakeXhr();
    const api = createFilesApi(createTransport({ token: 't', xhrFactory: () => x as unknown as XMLHttpRequest }));
    const seen: number[] = [];
    const h = api.upload('b', '/work/in', { name: 'a b.txt', size: 10 } as File, { overwrite: true, onProgress: (l) => seen.push(l) });
    expect(x.method).toBe('PUT');
    expect(x.url).toBe('/v1/boxes/b/files/upload?path=%2Fwork%2Fin&name=a%20b.txt&overwrite=1');
    expect(x.headers['Authorization']).toBe('Bearer t');
    x.upload.onprogress?.({ lengthComputable: true, loaded: 5, total: 10 });
    x.status = 201;
    x.responseText = '{"path":"/work/in/a b.txt","size":10,"hash":"h"}';
    x.onload?.();
    await expect(h.promise).resolves.toMatchObject({ size: 10, hash: 'h' });
    expect(seen).toEqual([5]);

    const y = new FakeXhr();
    const api2 = createFilesApi(createTransport({ token: 't', xhrFactory: () => y as unknown as XMLHttpRequest }));
    const h2 = api2.upload('b', '/work', { name: 'x', size: 1 } as File);
    h2.abort();
    await expect(h2.promise).rejects.toMatchObject({ name: 'AbortError' });

    const z = new FakeXhr();
    const api3 = createFilesApi(createTransport({ token: 't', xhrFactory: () => z as unknown as XMLHttpRequest }));
    const h3 = api3.upload('b', '/work', { name: 'x', size: 1 } as File);
    z.status = 409;
    z.responseText = '{"code":"exists","message":"there"}';
    z.onload?.();
    await expect(h3.promise).rejects.toMatchObject({ status: 409, code: 'exists' });
  });
});
