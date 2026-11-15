import type { Unreachable } from '../lib/use-fleet';
import { t } from '../lib/i18n';

/** Running boxes that did not answer a usage read, with the reason for each. Shown, never swallowed into an empty bar. */
export function UnreachableNote({ items }: { items: Unreachable[] }) {
  if (items.length === 0) return null;
  return (
    <div role="status" data-testid="unreachable-note" className="rounded-md border border-amber-600/50 bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:border-amber-400/50 dark:bg-amber-950/40 dark:text-amber-100">
      <p className="font-semibold">{items.length === 1 ? t('fleet.unreachable_one') : t('fleet.unreachable_n', { n: items.length })}</p>
      <ul className="mt-1 space-y-0.5">
        {items.map((u) => (
          <li key={u.name} className="break-words">
            <span className="font-mono text-xs">{u.name}</span>
            {`: ${u.reason}`}
          </li>
        ))}
      </ul>
    </div>
  );
}
