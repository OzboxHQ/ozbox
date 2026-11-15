import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// G7 X7: every call to the server goes through `src/api/transport.ts`. A second HTTP client is a second copy of the sign-in
// headers, the "could not reach the server" words, the 401 that ends a session, and the error type. The needles are built by
// concatenation so this file never contains the text it forbids.
const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const NEEDLES = ['fe' + 'tch(', 'new XML' + 'HttpRequest', 'Event' + 'Source(', 'send' + 'Beacon('];

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return sources(p);
    return /\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) ? [p] : [];
  });
}

describe('one transport', () => {
  it('no file but the transport makes an HTTP call', () => {
    const offenders: string[] = [];
    for (const p of sources(root)) {
      const rel = relative(root, p);
      if (rel === join('api', 'transport.ts')) continue;
      const text = readFileSync(p, 'utf8')
        .split('\n')
        .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*'))
        .join('\n');
      for (const n of NEEDLES) if (text.includes(n)) offenders.push(`${rel}: ${n}`);
    }
    expect(offenders).toEqual([]);
  });
});
