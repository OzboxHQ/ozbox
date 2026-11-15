import { describe, expect, it } from 'vitest';

import type { PriceInfo } from '../api/types';
import { fmtEstimate, priceSourceLine } from './cost';

const price = (over: Partial<PriceInfo>): PriceInfo => ({ provider: 'aws', source: 'AWS Price List API, on-demand Linux', region: 'us-east-1', currency: 'USD', fetched_at_ms: 0, age_s: 600, stale: false, ...over });

describe('cost labels', () => {
  it('names the source and its age, and says stale when it is', () => {
    expect(priceSourceLine(price({ age_s: 600 }), false)).toBe('AWS Price List API, on-demand Linux · fetched 10 min ago');
    expect(priceSourceLine(price({ age_s: 3 * 3600 }), false)).toContain('fetched 3 h ago');
    expect(priceSourceLine(price({ age_s: 5 * 86400, stale: true }), false)).toMatch(/fetched 5 days ago · stale$/);
  });

  it('never invents a price', () => {
    expect(priceSourceLine(null, false)).toBe('No price known');
    expect(priceSourceLine(null, true)).toBe('Prices you entered in Settings');
    expect(fmtEstimate(null, 'USD')).toBe('—');
    expect(fmtEstimate(12.5, null)).toBe('—');
    expect(fmtEstimate(12.5, 'USD')).toBe('$12.50 (estimate)');
    expect(fmtEstimate(12.5, 'EUR')).toContain('(estimate)');
  });
});
