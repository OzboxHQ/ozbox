// The dashboard's one way to talk to `ozbox serve` (G7 X7). Every call, whether it is JSON, a text body, a stream, or a file
// upload, goes through here, so the sign-in headers, the "could not reach the server" words, the 401 that sends a person back to
// the sign-in page, and the error type are written once.
import { authHeaders, type Credentials } from '../lib/auth-headers';
import { ApiError, errorFrom } from './error';

export const UNREACHABLE = 'Could not reach the Oz Box server. Is `ozbox serve` still running?';

export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

export interface TransportOptions extends Credentials {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  xhrFactory?: () => XMLHttpRequest;
  /** The sign-in calls themselves have no session to lose: a 401 there is an answer, not an ended session. Default true. */
  sessionEnds?: boolean;
}

export interface SendInit {
  /** A JSON-able body (sent as JSON) or raw bytes/text with `contentType`. */
  json?: unknown;
  body?: BodyInit;
  contentType?: string;
  signal?: AbortSignal;
  /** The request still goes out while the page is being closed or left. */
  keepalive?: boolean;
  accept?: string;
}

export interface UploadHandle {
  promise: Promise<{ path: string; size: number; hash: string }>;
  abort: () => void;
}

export interface UploadInit {
  onProgress?: (loaded: number, total: number) => void;
}

export interface Transport {
  /** A call answered with JSON. A refusal is an `ApiError`. */
  request<T>(method: Method, path: string, body?: unknown, signal?: AbortSignal): Promise<T>;
  /** The same, with a text body (a file's new contents). */
  requestText<T>(method: Method, path: string, text: string, signal?: AbortSignal): Promise<T>;
  /** The call itself, for an answer that is not JSON (a stream, a file). The status is the caller's to read; a network failure is an `ApiError`. */
  send(method: string, path: string, init?: SendInit): Promise<Response>;
  /** A call whose answer is the bytes of a file or picture. */
  blob(path: string, signal?: AbortSignal): Promise<Blob>;
  /** Streams one file to the server with progress. */
  upload(path: string, file: File, init?: UploadInit): UploadHandle;
  /** What a request carries to prove who is asking (the event stream is read by the caller). */
  headers(method: string): Record<string, string>;
  url(path: string): string;
}

export function createTransport(opts: TransportOptions): Transport {
  const base = opts.baseUrl ?? '';
  const doFetch = opts.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const newXhr = opts.xhrFactory ?? (() => new XMLHttpRequest());
  const creds: Credentials = { ...(opts.token ? { token: opts.token } : {}), ...(opts.csrf ? { csrf: opts.csrf } : {}) };
  const sessionEnds = opts.sessionEnds !== false;

  async function send(method: string, path: string, init: SendInit = {}): Promise<Response> {
    const headers: Record<string, string> = { Accept: init.accept ?? 'application/json', ...authHeaders(creds, method) };
    const req: RequestInit = { method, headers, cache: 'no-store', credentials: 'same-origin' };
    if (init.signal) req.signal = init.signal;
    if (init.keepalive) req.keepalive = true;
    if (init.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      req.body = JSON.stringify(init.json);
    } else if (init.body !== undefined) {
      if (init.contentType) headers['Content-Type'] = init.contentType;
      req.body = init.body;
    }
    try {
      return await doFetch(`${base}${path}`, req);
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') throw e;
      throw new ApiError(0, 'network', UNREACHABLE);
    }
  }

  /** A refusal becomes an `ApiError`. Behind a sign-in, a 401 means the session ended (idle, revoked): the shell goes back to the sign-in page. */
  async function refuse(res: Response): Promise<ApiError> {
    if (res.status === 401 && !opts.token && sessionEnds && typeof window !== 'undefined') window.dispatchEvent(new CustomEvent('ozbox:unauthorized', { detail: 401 }));
    return errorFrom(res);
  }

  async function json<T>(method: Method, path: string, init: SendInit): Promise<T> {
    const res = await send(method, path, init);
    if (!res.ok) throw await refuse(res);
    return (await res.json()) as T;
  }

  return {
    request: (method, path, body, signal) => json(method, path, { ...(body !== undefined ? { json: body } : {}), ...(signal ? { signal } : {}) }),
    requestText: (method, path, text, signal) => json(method, path, { body: text, contentType: 'text/plain; charset=utf-8', ...(signal ? { signal } : {}) }),
    send,
    blob: async (path, signal) => {
      const res = await send('GET', path, { accept: '*/*', ...(signal ? { signal } : {}) });
      if (!res.ok) throw await refuse(res);
      return res.blob();
    },
    upload: (path, file, init = {}) => {
      const xhr = newXhr();
      const promise = new Promise<{ path: string; size: number; hash: string }>((resolve, reject) => {
        xhr.open('PUT', `${base}${path}`);
        for (const [k, v] of Object.entries(authHeaders(creds, 'PUT'))) xhr.setRequestHeader(k, v);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) init.onProgress?.(e.loaded, e.total);
        };
        xhr.onload = () => {
          let body: Record<string, unknown> = {};
          try {
            body = JSON.parse(xhr.responseText) as Record<string, unknown>;
          } catch {
            // keep the generic message
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve({ path: String(body['path'] ?? ''), size: Number(body['size'] ?? file.size), hash: String(body['hash'] ?? '') });
          } else {
            if (xhr.status === 401 && !opts.token && sessionEnds && typeof window !== 'undefined') window.dispatchEvent(new CustomEvent('ozbox:unauthorized', { detail: 401 }));
            const message = typeof body['message'] === 'string' ? body['message'] : `The upload failed (HTTP ${xhr.status}).`;
            reject(new ApiError(xhr.status, typeof body['code'] === 'string' ? body['code'] : 'error', message));
          }
        };
        xhr.onerror = () => reject(new ApiError(0, 'network', UNREACHABLE));
        xhr.onabort = () => reject(new DOMException('The upload was cancelled.', 'AbortError'));
        xhr.send(file);
      });
      return { promise, abort: () => xhr.abort() };
    },
    headers: (method) => authHeaders(creds, method),
    url: (path) => `${base}${path}`,
  };
}
