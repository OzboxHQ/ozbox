import { describe, expect, it } from 'vitest';

import type { ProviderCheck } from '../api/types';
import { providerState } from './provider-check';

const base: ProviderCheck = { mode: 'connected', provider: 'aws', ok: true, boxes: 2, searched: ['eu-west-1'], error: null, checked_ms: 1, took_ms: 1 };

describe('providerState', () => {
  it('is checking until the provider has answered', () => {
    expect(providerState(null, false)).toBe('checking');
  });
  it('says connected only for a real provider that answered', () => {
    expect(providerState(base, false)).toBe('connected');
  });
  it('says failed for a real provider that refused, and for a box that cannot list itself', () => {
    expect(providerState({ ...base, ok: false, error: 'refused' }, false)).toBe('failed');
    expect(providerState({ ...base, mode: 'this_box', provider: 'thisbox', ok: false }, false)).toBe('failed');
  });
  it('never says connected for the demo, whatever it answered', () => {
    expect(providerState({ ...base, mode: 'demo', provider: 'fake' }, false)).toBe('demo');
    expect(providerState({ ...base, mode: 'demo', provider: 'fake', ok: false }, false)).toBe('demo');
  });
  it('names a box\'s own dashboard as this box', () => {
    expect(providerState({ ...base, mode: 'this_box', provider: 'thisbox' }, false)).toBe('this_box');
  });
  it('says it could not check when the question itself failed', () => {
    expect(providerState(null, true)).toBe('unknown');
  });
});
