/** The access token arrives in the URL fragment (`#token=...`), which the browser never sends to a server. */

const KEY = 'ozbox.token';

export interface TokenEnv {
  hash: string;
  pathname: string;
  search: string;
  replaceUrl: (url: string) => void;
  storage: Pick<Storage, 'getItem' | 'setItem'> | null;
}

/**
 * Take the token from the fragment, keep it for this tab only (sessionStorage), and strip it from the address bar so
 * it is not copied, bookmarked or shown. Falls back to what an earlier load of this tab kept.
 */
export function takeToken(env: TokenEnv): string | null {
  const m = /(?:^#|&)token=([A-Za-z0-9_-]+)/.exec(env.hash);
  if (m?.[1]) {
    try {
      env.storage?.setItem(KEY, m[1]);
    } catch {
      // storage can be unavailable; the token then lives in memory only
    }
    env.replaceUrl(env.pathname + env.search);
    return m[1];
  }
  try {
    return env.storage?.getItem(KEY) ?? null;
  } catch {
    return null;
  }
}
