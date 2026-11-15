import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/client';
import { useApp } from '../App';
import { EmptyState } from './page';
import { SourceBadge } from './source-badge';
import { fmtRelative } from '../lib/format';
import { checkText, failingSteps, incidentText, newestFirst, overall, overallText } from '../lib/health';
import { t } from '../lib/i18n';
import { useAsync } from '../lib/use-async';

/** The box's self-test and incident history, as its own agent reports them. */
export function HealthTab({ name }: { name: string }) {
  const { client } = useApp();
  const test = useAsync((s) => client.selftest(name, s), [client, name], 30_000);
  const inc = useAsync((s) => client.incidents(name, s), [client, name], 30_000);

  if (test.error && !test.data) {
    const title = test.error instanceof ApiError && test.error.status === 501 ? t('health.unavailable') : t('health.unreadable');
    return <EmptyState title={title}>{test.error.message}</EmptyState>;
  }
  if (!test.data) return <Skeleton className="h-40 w-full" />;
  const result = test.data.result;
  const o = overall(result);
  const failing = failingSteps(result);
  return (
    <div className="space-y-4">
      <Card className="space-y-3 p-4" data-testid="selftest">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold">{t('health.selftest')}</h2>
          <Badge variant={o === 'failed' ? 'destructive' : o === 'unverified' ? 'secondary' : 'outline'}>{overallText(o)}</Badge>
          <SourceBadge source={test.data.source} />
        </div>
        {failing.map((f) => (
          <p key={f.step} role="alert" className="rounded-md border border-destructive/40 p-3 text-sm">
            <strong>{t('health.failed_step', { step: f.step })}</strong> {f.reason}
          </p>
        ))}
        <ul className="divide-y text-sm" aria-label={t('health.checks')}>
          {result.checks.map((c) => (
            <li key={c.name} className="flex flex-col gap-1 py-2 sm:flex-row sm:items-start sm:justify-between">
              <span>{c.name}</span>
              <span className="sm:text-right">
                <Badge variant={c.outcome === 'fail' ? 'destructive' : c.outcome === 'unknown' ? 'secondary' : 'outline'}>{checkText(c)}</Badge>
                {c.outcome !== 'pass' && <span className="mt-1 block text-xs text-muted-foreground">{c.reason}</span>}
              </span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">{t('health.last_run', { when: fmtRelative(new Date(result.ts_ms).toISOString()) })}</p>
      </Card>
      <Card className="space-y-2 p-4" data-testid="incidents">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold">{t('health.incidents')}</h2>
          {inc.data && <SourceBadge source={inc.data.source} />}
        </div>
        {inc.error && !inc.data && <p role="alert" className="text-sm text-destructive">{inc.error.message}</p>}
        {inc.data && inc.data.incidents.length === 0 && <p className="text-sm text-muted-foreground">{t('health.no_incidents')}</p>}
        {inc.data && inc.data.incidents.length > 0 && (
          <ul className="divide-y text-sm" aria-label={t('health.incidents')}>
            {newestFirst(inc.data.incidents).map((i) => (
              <li key={`${i.ts_ms}-${i.kind}`} className="py-2">
                <p className="font-medium">{incidentText(i)}</p>
                <p className="text-xs text-muted-foreground">{`${fmtRelative(new Date(i.ts_ms).toISOString())} · ${i.detail}`}</p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
