import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { FittedTabsList, FittedTabsTrigger } from '@/components/ui/fitted-tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent } from '@/components/ui/tabs';
import type { SuggestionItem, SuggestionsResponse, UsageRange, UsageResponse } from '../api/types';
import { useApp } from '../App';
import { PlanSheet } from '../components/box-action-sheets';
import { FleetNotConnectedSheet } from '../components/fleet-notice';
import { LoadError } from '../components/load-error';
import { CannotNote } from '../components/role-scope';
import { UnreachableNote } from '../components/unreachable-note';
import { AppLink, AppPage, EmptyState, PageHeader, StatCard } from '../components/page';
import { CostCard } from '../components/cost-card';
import { SourceNote } from '../components/source-badge';
import { UsageBar } from '../components/usage-bar';
import { UsageChart } from '../components/usage-chart';
import { ABSENT, fmtBytes, fmtCost, fmtPct, sizeLabel } from '../lib/format';
import { fleetNotConnected } from '../lib/fleet';
import { t } from '../lib/i18n';
import { mayWrite, PAGE_CANNOT } from '../lib/role-gates';
import { hrefs } from '../lib/router';
import { useAsync, type AsyncState } from '../lib/use-async';
import { useCan } from '../lib/use-can';
import { usePlanFlow } from '../lib/use-plan-flow';
import { adviceAction, adviceTitle, fleetPoints, USAGE_RANGES } from '../lib/usage';

function Suggestions({ list }: { list: AsyncState<SuggestionsResponse> }) {
  const { client, info } = useApp();
  const { can } = useCan();
  const mayApply = mayWrite('usage', can);
  const notConnected = fleetNotConnected(info);
  const [notice, setNotice] = useState(false);
  const flow = usePlanFlow(client, () => list.reload());
  if (list.error && !list.data) {
    return (
      <Card className="space-y-3 p-4" data-testid="suggestions">
        <h2 className="text-sm font-semibold">{t('usage.suggestions')}</h2>
        <LoadError title={t('usage.suggestions_failed')} error={list.error} onRetry={list.reload} />
      </Card>
    );
  }
  if (!list.data) return <Skeleton className="h-24 w-full" />;
  const items: SuggestionItem[] = list.data.items;
  const missed = (list.data.unreachable ?? []).length > 0;
  return (
    <Card className="space-y-3 p-4" data-testid="suggestions">
      <h2 className="text-sm font-semibold">{t('usage.suggestions')}</h2>
      <SourceNote source={list.data.source} what="suggestions" />
      <p className="text-xs text-muted-foreground">{t('usage.suggestions_window', { days: list.data.window_days })}</p>
      {mayApply ? null : <CannotNote cap="use_boxes" what={PAGE_CANNOT.usage} />}
      {items.length === 0 ? (
        <p className="text-sm" data-testid="suggestions-none">{missed ? t('usage.sugg_incomplete') : t('usage.suggestions_none')}</p>
      ) : (
        <ul className="space-y-3" aria-label={t('usage.suggestions')}>
          {items.map((it) => (
            <li key={it.suggestion.box_name} className="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0 space-y-1">
                <p className="text-sm font-medium">{adviceTitle(it.suggestion.box_name, it.suggestion.advice)}</p>
                <p className="text-sm text-muted-foreground">{it.suggestion.reason}</p>
                <p className="text-xs">
                  <span className="text-muted-foreground">{t('usage.saves_about')}</span>
                  <span className="font-medium tabular-nums">{it.suggestion.saving_month_usd === null ? ABSENT : t('usage.per_month', { cost: fmtCost(it.suggestion.saving_month_usd) })}</span>
                  {it.suggestion.saving_month_usd === null && <span className="text-muted-foreground">{t('usage.saving_hint')}</span>}
                </p>
              </div>
              {mayApply ? (
                <Button variant="outline" className="w-full sm:w-auto max-lg:h-11" onClick={() => (notConnected ? setNotice(true) : flow.begin(it.operation))}>
                  {adviceAction(it.suggestion.advice)}
                </Button>
              ) : null}
            </li>
          ))}
          {missed ? <li className="text-xs text-muted-foreground">{t('usage.sugg_incomplete')}</li> : null}
        </ul>
      )}
      <PlanSheet state={flow.state} dispatch={flow.dispatch} onClose={() => flow.dispatch({ type: 'cancel' })} />
      <FleetNotConnectedSheet open={notice} onClose={() => setNotice(false)} info={info} />
    </Card>
  );
}

function BoxTable({ data }: { data: UsageResponse }) {
  return (
    <Card className="overflow-hidden">
      <Table aria-label={t('usage.by_box_table')} className="min-w-[44rem]">
        <TableHeader>
          <TableRow>
            <TableHead>{t('usage.col_box')}</TableHead>
            <TableHead>{t('usage.col_size')}</TableHead>
            <TableHead className="w-44">{t('usage.col_cpu_mean')}</TableHead>
            <TableHead className="w-44">{t('usage.col_mem_mean')}</TableHead>
            <TableHead>{t('usage.col_cpu_p95')}</TableHead>
            <TableHead>{t('usage.col_cost')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.boxes.map((b) => (
            <TableRow key={b.name}>
              <TableCell className="font-medium">
                <AppLink href={hrefs.box(b.name)} className="inline-flex min-h-11 min-w-11 items-center underline-offset-4 hover:underline lg:min-h-0">
                  {b.name}
                </AppLink>
              </TableCell>
              <TableCell>{sizeLabel(b.size)}</TableCell>
              <TableCell><UsageBar label={t('usage.cpu')} pct={b.cpu?.mean ?? null} /></TableCell>
              <TableCell><UsageBar label={t('usage.memory')} pct={b.mem_pct?.mean ?? null} /></TableCell>
              <TableCell className="tabular-nums">{fmtPct(b.cpu?.p95)}</TableCell>
              <TableCell className="tabular-nums">{fmtCost(b.cost_month_est_usd)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );
}

function GroupTable({ data }: { data: UsageResponse }) {
  return (
    <Card className="overflow-hidden">
      <Table aria-label={t('usage.by_project_table')} className="min-w-[40rem]">
        <TableHeader>
          <TableRow>
            <TableHead>{t('usage.label_heading', { key: data.by_label.key })}</TableHead>
            <TableHead>{t('nav.boxes')}</TableHead>
            <TableHead>{t('usage.col_cpu_mean')}</TableHead>
            <TableHead>{t('usage.col_mem_mean')}</TableHead>
            <TableHead>{t('usage.col_cost')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.by_label.groups.map((g) => (
            <TableRow key={g.value}>
              <TableCell className="font-medium">{g.value}</TableCell>
              <TableCell>{g.boxes.join(', ')}</TableCell>
              <TableCell className="tabular-nums">{fmtPct(g.cpu_mean)}</TableCell>
              <TableCell className="tabular-nums">{fmtPct(g.mem_mean)}</TableCell>
              <TableCell className="tabular-nums">{fmtCost(g.cost_month_est_usd)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <p className="border-t p-3 text-xs text-muted-foreground">{t('usage.groups_before')}<code>{'ozbox create --label project=name'}</code>{t('usage.groups_after')}</p>
    </Card>
  );
}

function RunTable({ data }: { data: UsageResponse }) {
  if (data.by_run.length === 0) return <EmptyState title={t('usage.no_runs')}>{t('usage.no_runs_body')}</EmptyState>;
  return (
    <Card className="overflow-hidden">
      <Table aria-label={t('usage.by_run_table')} className="min-w-[36rem]">
        <TableHeader>
          <TableRow>
            <TableHead>{t('usage.col_run')}</TableHead>
            <TableHead>{t('usage.col_box')}</TableHead>
            <TableHead>{t('usage.col_cpu_mean')}</TableHead>
            <TableHead>{t('usage.col_mem_peak')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.by_run.map((r) => (
            <TableRow key={r.id}>
              <TableCell className="font-medium">{r.id}</TableCell>
              <TableCell>{r.box_name}</TableCell>
              <TableCell className="tabular-nums">{fmtPct(r.cpu_mean)}</TableCell>
              <TableCell className="tabular-nums">{fmtBytes(r.mem_peak_bytes)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );
}

/** Fleet usage over a range, broken down by box, project label and run, with the weekly suggestions on top. */
/** What sits under the cost: nothing priced, where the prices came from, and whether boxes are missing from the sum. */
function costHint(data: UsageResponse, notConnected: boolean, unreachable: number): string {
  // on a box there is no fleet to price, whatever prices were typed
  if (data.fleet.cost_month_est_usd === null) return notConnected ? t('usage.cost_hint_box') : t('usage.cost_hint_missing');
  const base = data.fleet.cost_source === 'price_list' ? t('usage.cost_hint_list') : data.fleet.cost_source === 'mixed' ? t('usage.cost_hint_mixed') : t('usage.cost_hint');
  const missing = unreachable + (data.no_samples ?? []).length;
  return data.fleet.cost_partial ? base + t('usage.cost_partial', { n: missing }) : base;
}

export function UsagePage() {
  const { client, info } = useApp();
  const [rangeId, setRangeId] = useState<UsageRange>('5s');
  const [view, setView] = useState('box');
  const range = USAGE_RANGES.find((r) => r.id === rangeId) ?? USAGE_RANGES[0];
  const cost = useAsync((s) => (!info || fleetNotConnected(info) ? Promise.resolve(null) : client.cost(s)), [client, info?.fleet?.mode, info !== null], 60_000);
  const usage = useAsync<UsageResponse>((s) => client.usage(rangeId, s), [client, rangeId], range?.refreshMs);
  const suggestions = useAsync<SuggestionsResponse>((s) => client.suggestions(s), [client], 60_000);
  if (!range) return null;
  const data = usage.data;
  const notConnected = fleetNotConnected(info);
  // Running boxes that did not answer, from either read: named once, never folded into an empty list or an empty bar.
  const unreachable = [...(data?.unreachable ?? [])];
  for (const u of suggestions.data?.unreachable ?? []) if (!unreachable.some((x) => x.name === u.name)) unreachable.push(u);
  unreachable.sort((a, b) => a.name.localeCompare(b.name));
  return (
    <AppPage>
      <PageHeader title={t('nav.usage')} description={t('usage.description')} />
      <UnreachableNote items={unreachable} />
      <Suggestions list={suggestions} />
      {cost.error && !cost.data && !notConnected ? (
        <p role="alert" className="rounded-lg border border-destructive/40 p-3 text-sm" data-testid="cost-error">
          {t('fleet.cost_error', { why: cost.error.message })}
        </p>
      ) : null}
      <CostCard cost={cost.data} onRefreshed={cost.reload} />
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold">{t('usage.fleet')}</h2>
        </div>
        <Tabs value={rangeId} onValueChange={(v) => setRangeId(v as UsageRange)}>
          <FittedTabsList aria-label={t('usage.range')}>
            {USAGE_RANGES.map((r) => (
              <FittedTabsTrigger key={r.id} value={r.id} aria-controls={undefined}>
                {r.label}
              </FittedTabsTrigger>
            ))}
          </FittedTabsList>
        </Tabs>
      </div>
      {data && <SourceNote source={data.source} what="usage" />}
      {data && (data.no_samples ?? []).length > 0 ? (
        <p className="text-sm text-muted-foreground" data-testid="usage-no-data">
          {t('usage.no_data_yet', { names: (data.no_samples ?? []).map((b) => b.name).join(', ') })}
        </p>
      ) : null}
      {data && (data.stale ?? []).length > 0 ? (
        <p className="text-sm text-muted-foreground" data-testid="usage-stale">
          {t('usage.stale', { names: (data.stale ?? []).map((b) => `${b.name} (${new Date(b.as_of_ms).toLocaleTimeString()})`).join(', ') })}
        </p>
      ) : null}
      {usage.error && !data && <LoadError title={t('usage.load_failed')} error={usage.error} onRetry={usage.reload} />}
      {usage.error && data && <LoadError title={t('usage.load_failed')} error={usage.error} onRetry={usage.reload} stale />}
      {!data && !usage.error && <Skeleton className="h-48 w-full" />}
      {data && (
        <>
          <section aria-label={t('usage.totals')} className="grid gap-3 sm:grid-cols-3">
            <StatCard label={t('usage.avg_cpu')} value={fmtPct(data.fleet.cpu_mean)} />
            <StatCard label={t('usage.avg_mem')} value={fmtPct(data.fleet.mem_mean)} />
            <StatCard label={t('usage.est_cost')} value={fmtCost(data.fleet.cost_month_est_usd)} hint={costHint(data, notConnected, unreachable.length)} />
          </section>
          {data.boxes.length === 0 ? (
            unreachable.length > 0 ? (
              <EmptyState title={t('usage.none_read')}>{t('usage.none_read_body')}</EmptyState>
            ) : (
              <EmptyState title={t('usage.no_running')}>{t('usage.no_running_body')}</EmptyState>
            )
          ) : (
            <>
              <div className="grid gap-3 md:grid-cols-2">
                <UsageChart title={t('usage.fleet_cpu')} unit="%" points={fleetPoints(data.boxes, 'cpu_pct')} rangeLabel={range.label} colorVar="--chart-2" withDate={range.withDate} />
                <UsageChart title={t('usage.fleet_mem')} unit="%" points={fleetPoints(data.boxes, 'mem_pct')} rangeLabel={range.label} colorVar="--chart-1" withDate={range.withDate} />
              </div>
              <Tabs value={view} onValueChange={setView} className="space-y-3">
                <FittedTabsList aria-label={t('usage.breakdown')}>
                  <FittedTabsTrigger value="box">{t('usage.by_box')}</FittedTabsTrigger>
                  <FittedTabsTrigger value="project">{t('usage.by_project')}</FittedTabsTrigger>
                  <FittedTabsTrigger value="run">{t('usage.by_run')}</FittedTabsTrigger>
                </FittedTabsList>
                <TabsContent value="box" className="mt-0"><BoxTable data={data} /></TabsContent>
                <TabsContent value="project" className="mt-0"><GroupTable data={data} /></TabsContent>
                <TabsContent value="run" className="mt-0"><RunTable data={data} /></TabsContent>
              </Tabs>
            </>
          )}
        </>
      )}
    </AppPage>
  );
}
