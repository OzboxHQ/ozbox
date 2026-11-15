import { describe, expect, it } from 'vitest';

import { takeToken, type TokenEnv } from './token';

function env(hash: string, store: Record<string, string> = {}): { e: TokenEnv; urls: string[]; store: Record<string, string> } {
  const urls: string[] = [];
  return {
    urls,
    store,
    e: {
      hash,
      pathname: '/boxes/dev',
      search: '?a=1',
      replaceUrl: (u) => urls.push(u),
      storage: { getItem: (k) => store[k] ?? null, setItem: (k, v) => void (store[k] = v) },
    },
  };
}

describe('takeToken', () => {
  it('moves the fragment token into storage and strips the address bar', () => {
    const { e, urls, store } = env('#token=abc123');
    expect(takeToken(e)).toBe('abc123');
    expect(urls).toEqual(['/boxes/dev?a=1']);
    expect(Object.values(store)).toEqual(['abc123']);
  });
  it('falls back to what this tab kept', () => {
    const first = env('#token=abc123');
    takeToken(first.e);
    const { e, urls } = env('', first.store);
    expect(takeToken(e)).toBe('abc123');
    expect(urls).toEqual([]);
  });
  it('returns null with nothing and ignores odd tokens', () => {
    expect(takeToken(env('').e)).toBeNull();
    expect(takeToken(env('#token=<script>').e)).toBeNull();
  });
});
