import { Badge } from '@/components/ui/badge';
import type { Change } from '../../api/types';
import { t } from '../../lib/i18n';

const RISK: Record<Change['risk'], 'flow.risk_low' | 'flow.risk_medium' | 'flow.risk_high'> = { low: 'flow.risk_low', medium: 'flow.risk_medium', high: 'flow.risk_high' };

/** Every change, in order, with its risk. Shown before anything is applied. */
export function ChangeList({ changes, label }: { changes: Change[]; label: string }) {
  return (
    <ol className="space-y-2 text-sm" aria-label={label}>
      {changes.map((c, i) => (
        <li key={`${c.kind}-${i}`} className="flex flex-col gap-1 rounded-md border p-3 sm:flex-row sm:items-start sm:gap-3">
          <Badge variant={c.risk === 'high' ? 'destructive' : c.risk === 'medium' ? 'secondary' : 'outline'} className="w-fit shrink-0">
            {t(RISK[c.risk])}
          </Badge>
          <span className="min-w-0 break-words">{c.description}</span>
        </li>
      ))}
    </ol>
  );
}
