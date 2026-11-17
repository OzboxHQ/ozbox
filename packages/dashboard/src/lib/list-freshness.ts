import type { BoxList } from '../api/client';

/** How old a list may be before a page says so. Younger than this, the age is not worth a line. */
export const STALE_AFTER_MS = 15_000;

export type ListNote =
  | { kind: 'none' }
  /** Older than a read takes, and a new read is running. */
  | { kind: 'refreshing'; ageMs: number }
  /** Older than a read takes, and none is running (the next one starts on the next ask). */
  | { kind: 'stale'; ageMs: number }
  /** The last read failed; this is the last list that could be read. */
  | { kind: 'failed'; ageMs: number };

/** What a page tells the person about a list that came from the server's memory instead of a read made just now. */
export function listNote(list: Pick<BoxList, 'asOf' | 'refreshing' | 'refreshFailed'> | null, now: number): ListNote {
  if (!list || list.asOf === null) return { kind: 'none' };
  const ageMs = Math.max(0, now - list.asOf);
  if (list.refreshFailed) return { kind: 'failed', ageMs };
  if (ageMs < STALE_AFTER_MS) return { kind: 'none' };
  return list.refreshing ? { kind: 'refreshing', ageMs } : { kind: 'stale', ageMs };
}

/** "12 s" or "3 min": a few words, no clock. */
export function ageWords(ms: number): { key: 'listnote.age_seconds' | 'listnote.age_minutes'; n: number } {
  const s = Math.round(ms / 1000);
  return s < 90 ? { key: 'listnote.age_seconds', n: Math.max(1, s) } : { key: 'listnote.age_minutes', n: Math.round(s / 60) };
}
