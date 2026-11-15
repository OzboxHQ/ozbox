import type { ProviderCheck } from '../api/types';
import type { MessageKey } from './i18n';

/** What the Providers page says about the connection. `unknown` is a check that could not be made at all. */
export type ProviderState = 'checking' | 'connected' | 'failed' | 'demo' | 'this_box' | 'unknown';

/**
 * The state of the connection from what the provider answered. A demo or a box's own dashboard is never "Connected": the
 * fake provider always answers, which says nothing about a cloud account, so the page names what it is instead.
 */
export function providerState(check: ProviderCheck | null, failedToAsk: boolean): ProviderState {
  if (failedToAsk) return 'unknown';
  if (!check) return 'checking';
  if (check.mode === 'demo') return 'demo';
  if (check.mode === 'this_box') return check.ok ? 'this_box' : 'failed';
  return check.ok ? 'connected' : 'failed';
}

export const STATE_LABEL: Record<ProviderState, MessageKey> = {
  checking: 'settings.checking',
  connected: 'apps.connected',
  failed: 'provider.state_failed',
  demo: 'provider.state_demo',
  this_box: 'provider.state_this_box',
  unknown: 'provider.state_unknown',
};

export const STATE_NOTE: Partial<Record<ProviderState, MessageKey>> = {
  connected: 'provider.note_connected',
  failed: 'provider.note_failed',
  demo: 'provider.note_demo',
  this_box: 'provider.note_this_box',
  unknown: 'provider.note_unknown',
};
