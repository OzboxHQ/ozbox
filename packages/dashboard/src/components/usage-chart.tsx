import { useId } from 'react';
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts';

import { Card } from '@/components/ui/card';
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart';
import { ABSENT } from '../lib/format';
import { t } from '../lib/i18n';
import { describeSeries, downsample, fmtClock, summarize, type Point } from '../lib/series';

interface Props {
  title: string;
  unit: string;
  points: Point[];
  rangeLabel: string;
  colorVar: string;
  withDate: boolean;
}

/** A line chart built on the shared chart primitives. The sentence below it and the data table are its text equivalents. */
export function UsageChart({ title, unit, points, rangeLabel, colorVar, withDate }: Props) {
  const id = useId();
  const summary = summarize(points);
  const config: ChartConfig = { v: { label: title, color: `hsl(var(${colorVar}))` } };
  const data = downsample(points, 120).map((p) => ({ t: p.t, v: Math.round(p.v * 10) / 10 }));
  const rows = downsample(points, 12);
  return (
    <Card className="p-4">
      <h3 id={`${id}-t`} className="text-xs font-medium text-muted-foreground">
        {title}
      </h3>
      <p className="mt-1 text-xl font-semibold tabular-nums lg:text-lg">{summary ? `${Math.round(summary.last)}${unit}` : ABSENT}</p>
      <div className="mt-3" role="img" aria-labelledby={`${id}-t ${id}-s`}>
        {data.length > 0 ? (
          <ChartContainer config={config} className="aspect-auto h-36 w-full">
            <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} accessibilityLayer={false}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickFormatter={(t: number) => fmtClock(t, withDate)} minTickGap={48} tickLine={false} axisLine={false} fontSize={11} />
              <YAxis domain={[0, 100]} width={32} tickLine={false} axisLine={false} fontSize={11} tickFormatter={(v: number) => `${v}`} />
              <ChartTooltip content={<ChartTooltipContent labelFormatter={(_l, p) => fmtClock(Number(p[0]?.payload?.t), withDate)} />} />
              <Line dataKey="v" type="monotone" stroke="var(--color-v)" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ChartContainer>
        ) : (
          <p className="py-8 text-center text-sm text-muted-foreground">{t('chart.no_data')}</p>
        )}
      </div>
      <p id={`${id}-s`} className="mt-2 text-xs text-muted-foreground">
        {describeSeries(title, unit, summary, rangeLabel)}
      </p>
      {rows.length > 0 && (
        <details className="mt-1">
          <summary className="flex min-h-11 cursor-pointer items-center text-xs text-primary underline-offset-4 hover:underline lg:min-h-8">{t('chart.show_table')}</summary>
          <table className="w-full text-xs">
            <caption className="sr-only">{`${title}, ${rangeLabel}`}</caption>
            <thead>
              <tr className="text-left text-muted-foreground">
                <th scope="col" className="py-1 pr-2 font-medium">{t('chart.time')}</th>
                <th scope="col" className="py-1 font-medium">{`${title} (${unit})`}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.t} className="border-t">
                  <th scope="row" className="py-1 pr-2 text-left font-normal">{fmtClock(p.t, withDate)}</th>
                  <td className="py-1 tabular-nums">{Math.round(p.v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </Card>
  );
}
