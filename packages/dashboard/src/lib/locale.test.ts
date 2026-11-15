import { describe, expect, it } from 'vitest';

import { countryName, isKnownCountryCode } from './countries';
import { filterOptions } from '../../components/ui/combobox';
import { formatWithUtc, validTimeZone, windowWithUtc } from './locale';
import { getTimezoneOptions } from './timezones';

describe('time zones and countries', () => {
  it('lists the zones and always offers UTC', () => {
    const o = getTimezoneOptions();
    expect(o.length).toBeGreaterThan(50);
    expect(o.some((z) => z.value === 'UTC')).toBe(true);
    expect(o.find((z) => z.value === 'America/New_York')?.label).toContain('EST');
  });
  it('validates a zone name without trusting the list alone', () => {
    expect(validTimeZone('Africa/Lagos')).toBe(true);
    expect(validTimeZone('Mars/Olympus')).toBe(false);
    expect(validTimeZone('')).toBe(false);
  });
  it('knows ISO country codes', () => {
    expect(countryName('ng')).toBe('Nigeria');
    expect(isKnownCountryCode('XX')).toBe(false);
    expect(isKnownCountryCode(null)).toBe(false);
  });
});

describe('showing times in the persons zone with UTC beside them', () => {
  it('follows daylight saving', () => {
    expect(formatWithUtc(Date.UTC(2026, 0, 15, 12, 0), 'America/New_York')).toMatch(/^2026-01-15 07:00 .* \(12:00 UTC\)$/);
    expect(formatWithUtc(Date.UTC(2026, 6, 15, 12, 0), 'America/New_York')).toMatch(/^2026-07-15 08:00 .* \(12:00 UTC\)$/);
  });
  it('UTC alone is not repeated, and a bad zone falls back to UTC', () => {
    expect(formatWithUtc(Date.UTC(2026, 0, 15, 12, 0), 'UTC')).toMatch(/^2026-01-15 12:00/);
    expect(formatWithUtc(Date.UTC(2026, 0, 15, 12, 0), 'Nope/Nope')).toMatch(/^2026-01-15 12:00/);
    expect(formatWithUtc(Date.UTC(2026, 0, 15, 12, 0), null)).toMatch(/^2026-01-15 12:00/);
  });
  it('writes a quiet-hours window in UTC too, with the offset of the day asked about', () => {
    expect(windowWithUtc('23:00', '07:00', 'Africa/Lagos', new Date(Date.UTC(2026, 0, 15)))).toBe('23:00 to 07:00 (22:00 to 06:00 UTC)');
    expect(windowWithUtc('23:00', '07:00', 'America/New_York', new Date(Date.UTC(2026, 0, 15)))).toBe('23:00 to 07:00 (04:00 to 12:00 UTC)');
    expect(windowWithUtc('23:00', '07:00', 'America/New_York', new Date(Date.UTC(2026, 6, 15)))).toBe('23:00 to 07:00 (03:00 to 11:00 UTC)');
    expect(windowWithUtc('23:00', '07:00', null)).toBe('23:00 to 07:00');
  });
});

describe('the searchable list', () => {
  const opts = [
    { value: 'Africa/Lagos', label: 'Africa/Lagos (WAT)' },
    { value: 'America/New_York', label: 'America/New York (EST/EDT)' },
  ];
  it('matches every word, in any order, ignoring case', () => {
    expect(filterOptions(opts, 'new york').map((o) => o.value)).toEqual(['America/New_York']);
    expect(filterOptions(opts, 'LAGOS wat').length).toBe(1);
    expect(filterOptions(opts, 'zzz')).toEqual([]);
    expect(filterOptions(opts, '').length).toBe(2);
    expect(filterOptions(opts, '', 1).length).toBe(1);
  });
});
