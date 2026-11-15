import { ApiError } from '../../api/error';
import { en } from '../../i18n/en';
import { isKnownError } from '../../lib/files';
import { t, type MessageKey } from '../../lib/i18n';

const has = (key: string): key is MessageKey => key in en;

/** What a person reads for a failed file request: translated by code, never the raw server text. */
export function fileErrorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === 'network') return e.message;
    const key = `files.err_${e.code}`;
    if (isKnownError(e.code) && has(key)) return t(key);
    // An agent or provider message that is safe to show, when it is not one this page knows.
    return e.message || t('files.err_generic');
  }
  return t('files.err_generic');
}

/** Why an entry is greyed out. */
export function blockedText(code: string): string {
  const key = `files.blocked_${code}`;
  return has(key) ? t(key) : t('files.blocked_label');
}
