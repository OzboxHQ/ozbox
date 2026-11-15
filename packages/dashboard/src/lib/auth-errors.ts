import { ApiError } from '../api/error';
import { t, type MessageKey } from './i18n';
import { wasCancelled } from './webauthn';

/** Words for what went wrong while signing in. The server's messages are plain and safe to show. */
export function signInMessage(e: unknown): string {
  if (wasCancelled(e)) return t('auth.passkey_cancelled');
  if (e instanceof ApiError) return e.status === 429 ? t('auth.error_too_many') : e.message;
  return t('auth.error_generic');
}

const RETURN_CODES: Record<string, MessageKey> = {
  expired: 'auth.error_expired',
  refused: 'auth.error_refused',
  not_allowed: 'auth.error_not_allowed',
  too_many: 'auth.error_too_many',
  not_configured: 'auth.error_not_configured',
};

/** `?signin=<code>` is where the server sends someone back from Google; only these fixed codes mean anything. */
export function returnMessage(search: string): string | null {
  const code = new URLSearchParams(search).get('signin');
  const key = code ? RETURN_CODES[code] : undefined;
  return key ? t(key) : null;
}
