import { useId } from 'react';
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts';

import { Card } from '@/components/ui/card';
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart';
import type { DayTotal } from '../../api/bill';
import { chartRows, money, unfinishedDays } from '../../lib/bill';
import { t } from '../../lib/i18n';

/**
 * Billed and estimated money by finished day, on the shared chart primitives. The sentence below it and the table
 * behind "show the figures" are its text equivalents; the days the provider has not finished are named, not drawn.
 */
export function BillChart({ days, currency }: { days: DayTotal[]; currency: string }) {
  const id = useId();
  const rows = chartRows(days);
  const unfinished = unfinishedDays(days);
  const config: ChartConfig = {
    real: { label: t('bill.chart_real'), color: 'hsl(var(--chart-1))' },
    estimate: { label: t('bill.chart_estimate'), color: 'hsl(var(--chart-2))' },
  };
  const sumReal = rows.reduce((a, r) => a + r.real, 0);
  const sumEst = rows.reduce((a, r) => a + (r.estimate ?? 0), 0);
  return (
    <Card className="p-4" data-testid="bill-chart">
      <h2 id={`${id}-t`} className="text-sm font-semibold">
        {t('bill.chart_title')}
      </h2>
      {rows.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">{t('bill.chart_none')}</p>
      ) : (
        <>
          <div className="mt-3" role="img" aria-labelledby={`${id}-t ${id}-s`}>
            <ChartContainer config={config} className="aspect-auto h-52 w-full">
              <LineChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: 0 }} accessibilityLayer={false}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="date" tickFormatter={(d: string) => d.slice(5)} minTickGap={32} tickLine={false} axisLine={false} fontSize={11} />
                <YAxis width={44} tickLine={false} axisLine={false} fontSize={11} tickFormatter={(v: number) => money(v, currency)} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Line dataKey="real" type="monotone" stroke="var(--color-real)" strokeWidth={2} dot={false} isAnimationActive={false} />
                <Line dataKey="estimate" type="monotone" stroke="var(--color-estimate)" strokeWidth={2} strokeDasharray="5 4" dot={false} isAnimationActive={false} />
              </LineChart>
            </ChartContainer>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-hidden>
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-block w-6 border-t-2 border-solid" style={{ borderColor: 'hsl(var(--chart-1))' }} />
              {t('bill.chart_real')}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-block w-6 border-t-2 border-dashed" style={{ borderColor: 'hsl(var(--chart-2))' }} />
              {t('bill.chart_estimate')}
            </span>
          </div>
          <p id={`${id}-s`} className="mt-2 text-xs text-muted-foreground">
            {t('bill.chart_summary', { real: money(sumReal, currency), estimate: money(sumEst, currency), n: rows.length })}
          </p>
        </>
      )}
      {unfinished.length > 0 ? <p className="mt-1 text-xs text-muted-foreground" data-testid="bill-unfinished">{t('bill.chart_unfinished', { dates: unfinished.join(', ') })}</p> : null}
      {rows.length > 0 && (
        <details className="mt-1">
          <summary className="flex min-h-11 cursor-pointer items-center text-xs text-primary underline-offset-4 hover:underline lg:min-h-8">{t('bill.chart_show_table')}</summary>
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={t('bill.chart_title')}>
            <table className="w-full min-w-[18rem] text-xs">
              <caption className="sr-only">{t('bill.chart_title')}</caption>
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th scope="col" className="py-1 pr-2 font-medium">{t('bill.col_day')}</th>
                  <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.chart_real')}</th>
                  <th scope="col" className="py-1 text-right font-medium">{t('bill.chart_estimate')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.date} className="border-t">
                    <th scope="row" className="py-1 pr-2 text-left font-normal">{r.date}</th>
                    <td className="py-1 pr-2 text-right tabular-nums">{money(r.real, currency)}</td>
                    <td className="py-1 text-right tabular-nums">{money(r.estimate, currency)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </Card>
  );
}
