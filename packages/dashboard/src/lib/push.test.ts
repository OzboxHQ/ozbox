import { describe, expect, it } from 'vitest';

import { urlBase64ToBytes } from './push';

describe('push key', () => {
  it('decodes base64url without padding', () => {
    expect(Array.from(urlBase64ToBytes('-__-'))).toEqual([0xfb, 0xff, 0xfe]);
    expect(Array.from(urlBase64ToBytes('Zm9v'))).toEqual([102, 111, 111]);
    expect(Array.from(urlBase64ToBytes('Zg'))).toEqual([102]);
  });
});
