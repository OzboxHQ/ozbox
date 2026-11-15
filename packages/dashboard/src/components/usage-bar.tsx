import { Progress } from '@/components/ui/progress';
import { cn } from '@/lib/utils';
import { ABSENT, fmtPct } from '../lib/format';

/** A labelled bar. The value is always also written as text; a missing value is "—", never an empty bar. */
export function UsageBar({ label, pct, warnAt = 85 }: { label: string; pct: number | null; warnAt?: number }) {
  const ok = pct !== null && Number.isFinite(pct);
  const v = ok ? Math.min(Math.max(pct, 0), 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium tabular-nums">{ok ? fmtPct(v) : ABSENT}</span>
      </div>
      {ok ? (
        <Progress value={v} aria-label={label} aria-valuetext={fmtPct(v)} className={cn('h-2', v >= warnAt && '[&>div]:bg-destructive')} />
      ) : (
        <div className="h-2 rounded-full border border-dashed" aria-hidden />
      )}
    </div>
  );
}
