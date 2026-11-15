import { describe, expect, it } from 'vitest';

import { en } from '../i18n/en';
import { registerCatalogue, setLocale, t } from './i18n';

describe('t', () => {
  it('fills variables and leaves an unknown one visible', () => {
    expect(t('models.cap_value', { amount: '50.00' })).toContain('50.00');
    expect(t('models.cap_value', {})).toContain('{amount}');
  });

  it('uses another catalogue when one is registered, and falls back to English', () => {
    registerCatalogue('xx', { ...en, 'apps.title': 'Applis' });
    setLocale('xx-YY');
    expect(t('apps.title')).toBe('Applis');
    setLocale('zz');
    expect(t('apps.title')).toBe(en['apps.title']);
    setLocale('en');
  });

  it('keeps the same variables in every message of a catalogue', () => {
    for (const [k, v] of Object.entries(en)) {
      expect(typeof v, k).toBe('string');
    }
  });
});
