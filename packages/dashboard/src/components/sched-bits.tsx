import type { ReactNode } from 'react';

import { Badge } from '@/components/ui/badge';
import type { WhenInstant } from '../api/sched';

export function FieldError({ msg }: { msg?: string | undefined }) {
  return msg ? (
    <p role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm">{children}</dd>
    </div>
  );
}

/** A moment in local time with UTC beside it, as the server wrote it. */
export function Instant({ at }: { at: WhenInstant | null }) {
  if (!at) return <span>-</span>;
  return <time dateTime={at.utc}>{at.local}</time>;
}

export function StatusBadge({ ok, children }: { ok: 'good' | 'bad' | 'neutral'; children: ReactNode }) {
  return <Badge variant={ok === 'bad' ? 'destructive' : ok === 'good' ? 'default' : 'secondary'}>{children}</Badge>;
}
