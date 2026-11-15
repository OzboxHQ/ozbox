import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ROUTE_SAMPLES } from './route-samples';
import { SETTINGS_SECTIONS, parseRoute } from './router';

// Every page the router knows is visited by the every-route guards (e2e/35, e2e-real/b-02). A page without a sample would be a
// page nobody checks for honesty, so this fails first.
describe('route samples', () => {
  const source = readFileSync(fileURLToPath(new URL('./router.ts', import.meta.url)), 'utf8');
  const union = /export type Route =([\s\S]*?);\n/.exec(source)?.[1] ?? '';
  const pages = [...union.matchAll(/page: '([a-z]+)'/g)].map((m) => m[1] as string);

  it('finds the pages of the Route type (the guard itself is not empty)', () => {
    expect(pages.length).toBeGreaterThan(20);
  });

  it('has a sample for every page of the Route type', () => {
    const sampled = new Set(ROUTE_SAMPLES.map((s) => s.page));
    expect(pages.filter((p) => !sampled.has(p as never))).toEqual([]);
  });

  it('has a sample for every settings section', () => {
    const got = ROUTE_SAMPLES.filter((s) => s.page === 'settings').map((s) => s.section);
    expect(got).toEqual([...SETTINGS_SECTIONS]);
  });

  it('every sample parses back to the page it names', () => {
    for (const s of ROUTE_SAMPLES) expect(parseRoute(s.path('main-box')).page, s.path('main-box')).toBe(s.page);
  });
});
