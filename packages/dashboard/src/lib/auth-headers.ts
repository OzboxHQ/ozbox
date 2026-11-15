/** How a request proves who is asking: the local access token, or (behind a sign-in) the session cookie plus its CSRF token. */
export interface Credentials {
  /** The local access token from `ozbox serve`. */
  token?: string;
  /** The signed-in session's CSRF token, read when a request is made. */
  csrf?: () => string;
}

export const CSRF_HEADER = 'X-Ozbox-CSRF';

/** Headers for one request. A session's cookie is sent by the browser itself; only a change needs the CSRF token. */
export function authHeaders(c: Credentials, method: string): Record<string, string> {
  if (c.token) return { Authorization: `Bearer ${c.token}` };
  const csrf = c.csrf?.();
  if (csrf && method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'HEAD') return { [CSRF_HEADER]: csrf };
  return {};
}
