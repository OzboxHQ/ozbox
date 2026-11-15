import { describe, expect, it } from 'vitest';

import { parsePrice } from './prices-card';

describe('parsePrice', () => {
  it('takes plain non-negative numbers with up to four decimals', () => {
    expect(parsePrice('2.5')).toBe(2.5);
    expect(parsePrice(' 0 ')).toBe(0);
    expect(parsePrice('0.0125')).toBe(0.0125);
  });
  it('refuses anything else', () => {
    for (const bad of ['', '-1', '1e3', '1,5', '$2', '2.12345', '1000001', 'abc']) expect(parsePrice(bad), bad).toBeNull();
  });
});
