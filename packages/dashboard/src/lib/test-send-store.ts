import type { TestRun } from '../api/alert-types';

/** What a channel card shows about its latest test send. Kept outside React so a card that remounts still shows it. */
export interface ShownTest {
  run: TestRun;
  timedOut: boolean;
  /** Order of starting, newest highest. */
  at: number;
}

let snapshot: Readonly<Record<string, ShownTest>> = {};
let sequence = 0;
const listeners = new Set<() => void>();

const emit = () => listeners.forEach((l) => l());

export const testSendStore = {
  get: (): Readonly<Record<string, ShownTest>> => snapshot,
  subscribe(l: () => void): () => void {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  set(channel: string, run: TestRun, timedOut = false): void {
    snapshot = { ...snapshot, [channel]: { run, timedOut, at: ++sequence } };
    emit();
  },
  clear(channel: string): void {
    snapshot = Object.fromEntries(Object.entries(snapshot).filter(([k]) => k !== channel));
    emit();
  },
};

/** The test to show on a card: its own channel, or the latest of a family such as `webhook:`. */
export function shownFor(all: Readonly<Record<string, ShownTest>>, match: { channel?: string; prefix?: string }): { key: string; shown: ShownTest } | null {
  if (match.channel !== undefined) {
    const shown = all[match.channel];
    return shown ? { key: match.channel, shown } : null;
  }
  if (match.prefix === undefined) return null;
  const hits = Object.entries(all).filter(([k]) => k.startsWith(match.prefix as string));
  const best = hits.sort((a, b) => b[1].at - a[1].at)[0];
  return best ? { key: best[0], shown: best[1] } : null;
}
