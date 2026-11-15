import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import type { UsageRow } from '../../api/types';
import { useApp } from '../../App';
import { t, type MessageKey } from '../../lib/i18n';
import { barPercent, tokens, usd } from '../../lib/models';
import { useAsync } from '../../lib/use-async';

const PERIODS: { days: number; label: MessageKey }[] = [
  { days: 7, label: 'models.usage_7' },
  { days: 30, label: 'models.usage_30' },
  { days: 90, label: 'models.usage_90' },
];

function Table({ title, rows, testId }: { title: string; rows: UsageRow[]; testId: string }) {
  if (rows.length === 0) return null;
  return (
    <div className="space-y-1" data-testid={testId}>
      <h3 className="text-xs font-medium text-muted-foreground">{title}</h3>
      {/* the table scrolls inside its own box; the page never scrolls sideways */}
      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={title}>
        <table className="w-full min-w-[28rem] text-left text-xs">
          <thead>
            <tr className="text-muted-foreground">
              <th scope="col" className="py-1 pr-2 font-medium">{t('models.usage_col_name')}</th>
              <th scope="col" className="py-1 pr-2 text-right font-medium">{t('models.usage_col_calls')}</th>
              <th scope="col" className="py-1 pr-2 text-right font-medium">{t('models.usage_col_in')}</th>
              <th scope="col" className="py-1 pr-2 text-right font-medium">{t('models.usage_col_out')}</th>
              <th scope="col" className="py-1 text-right font-medium">{t('models.usage_col_cost')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className="border-t">
                <th scope="row" className="py-1 pr-2 font-normal break-all">{r.key === '-' ? t('models.usage_unattributed') : r.key}</th>
                <td className="py-1 pr-2 text-right tabular-nums">{r.calls}</td>
                <td className="py-1 pr-2 text-right tabular-nums">{tokens(r.input_tokens)}</td>
                <td className="py-1 pr-2 text-right tabular-nums">{tokens(r.output_tokens)}</td>
                <td className="py-1 text-right tabular-nums">{usd(r.est_cost_usd)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Tokens and estimated cost recorded by runs, by day, provider, model, box and engine. */
export function UsageCard() {
  const { client } = useApp();
  const [days, setDays] = useState(30);
  const q = useAsync((s) => client.modelsUsage(days, s), [client, days]);
  if (!q.data) return q.error ? <p role="alert" className="text-sm text-destructive">{q.error.message}</p> : <Skeleton className="h-40 w-full" />;
  const u = q.data.usage;
  const empty = u.total.calls === 0;
  return (
    <Card className="space-y-3 p-4" data-testid="model-usage">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('models.usage_title')}</h2>
        <div role="group" aria-label={t('models.usage_days')} className="flex gap-2">
          {PERIODS.map((p) => (
            <Button key={p.days} size="sm" variant={p.days === days ? 'default' : 'outline'} className="max-lg:h-11" aria-pressed={p.days === days} onClick={() => setDays(p.days)}>{t(p.label)}</Button>
          ))}
        </div>
      </div>
      <p className="text-xs text-muted-foreground">{t('models.usage_help')}</p>
      {q.data.caps.map((c) => (
        <p key={c.provider_id} className={c.reached ? 'text-xs font-medium text-destructive' : 'text-xs'} data-testid={`usage-cap-${c.provider_id}`}>
          {c.reached ? t('models.usage_cap_reached', { provider: c.provider_id, cap: usd(c.cap_usd) }) : t('models.usage_cap', { provider: c.provider_id, spent: usd(c.spent_usd), cap: usd(c.cap_usd) })}
        </p>
      ))}
      {empty ? (
        <p className="text-sm" data-testid="usage-empty">{t('models.usage_none')}</p>
      ) : (
        <>
          <p className="text-sm font-medium" data-testid="usage-total">{t('models.usage_total', { calls: u.total.calls, tokens: tokens(u.total.input_tokens + u.total.output_tokens), cost: usd(u.total.est_cost_usd) })}</p>
          {u.total.unpriced_calls > 0 ? <p className="text-xs text-muted-foreground">{t('models.usage_unpriced', { count: u.total.unpriced_calls })}</p> : null}
          <div className="flex h-16 items-end gap-px" aria-hidden="true">
            {u.by_day.map((r) => (
              <div key={r.key} className="flex-1 rounded-t bg-primary/70" style={{ height: `${Math.max(barPercent(r, u.by_day), r.calls > 0 ? 4 : 0)}%` }} />
            ))}
          </div>
          <Table title={t('models.usage_by_day')} rows={u.by_day.filter((r) => r.calls > 0)} testId="usage-by-day" />
          <Table title={t('models.usage_by_provider')} rows={u.by_provider} testId="usage-by-provider" />
          <Table title={t('models.usage_by_model')} rows={u.by_model} testId="usage-by-model" />
          <Table title={t('models.usage_by_box')} rows={u.by_box} testId="usage-by-box" />
          <Table title={t('models.usage_by_engine')} rows={u.by_engine} testId="usage-by-engine" />
        </>
      )}
    </Card>
  );
}
