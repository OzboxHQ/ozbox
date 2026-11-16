import { useEffect, useState } from 'react';

import type { Fleet } from '../lib/use-fleet';
import { ageWords, listNote } from '../lib/list-freshness';
import { t } from '../lib/i18n';

/**
 * Says so when the boxes shown are the server's last read and not one made just now: the cloud can take half a minute to
 * answer, and the page shows what it has meanwhile instead of waiting or failing.
 */
export function ListNote({ list, now = Date.now() }: { list: Fleet['list'] | undefined; now?: number }) {
  const note = listNote(list ?? null, now);
  if (note.kind === 'none') return null;
  const w = ageWords(note.ageMs);
  const age = t(w.key, { n: w.n });
  const text = note.kind === 'refreshing' ? t('listnote.refreshing', { age }) : note.kind === 'failed' ? t('listnote.failed', { age }) : t('listnote.stale', { age });
  return (
    <p role="status" data-testid="list-note" data-kind={note.kind} className="rounded-md border px-3 py-2 text-sm text-muted-foreground">
      {text}
    </p>
  );
}

/** Shown under a loading list that is still loading after a few seconds, so a slow first read does not look like a hang. */
export function WarmingNote({ delayMs = 3000 }: { delayMs?: number }) {
  const [late, setLate] = useState(false);
  useEffect(() => {
    const id = setTimeout(() => setLate(true), delayMs);
    return () => clearTimeout(id);
  }, [delayMs]);
  if (!late) return null;
  return (
    <p role="status" data-testid="list-warming" className="text-sm text-muted-foreground">
      {t('listnote.warming')}
    </p>
  );
}
