import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/client';
import type { BillResponse, BudgetFigure, Reconciliation } from '../api/bill';
import { useApp } from '../App';
import { BillChart } from '../components/bill/bill-chart';
import { OrphansCard } from '../components/bill/orphans-card';
import { LoadError } from '../components/load-error';
import { CannotNote } from '../components/role-scope';
import { AppLink, AppPage, EmptyState, PageHeader, StatCard } from '../components/page';
import { ageText, alertList, causeText, diffHint, diffText, firedList, gauge, hasBill, money, problemTitle, showsActivation } from '../lib/bill';
import { ABSENT } from '../lib/format';
import { fleetNotConnected } from '../lib/fleet';
import { t } from '../lib/i18n';
import { mayWrite, PAGE_CANNOT } from '../lib/role-gates';
import { hrefs } from '../lib/router';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

/** A scrolling table that a keyboard can reach and a screen reader can name, so the page itself never scrolls sideways. */
function Region({ label, children, min }: { label: string; children: React.ReactNode; min: string }) {
  return (
    <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={label}>
      <table className={`w-full text-left text-sm ${min}`}>
        <caption className="sr-only">{label}</caption>
        {children}
      </table>
    </div>
  );
}

function Problem({ b }: { b: BillResponse }) {
  const p = b.problem;
  if (!p) return null;
  return (
    <Card className="space-y-2 p-4" role="status" data-testid="bill-status">
      <h2 className="text-sm font-semibold">{problemTitle(p.problem)}</h2>
      <p className="text-sm">{p.message}</p>
      {showsActivation(p.problem) ? (
        <div data-testid="bill-activation">
          <h3 className="text-xs font-medium text-muted-foreground">{t('bill.activate_title')}</h3>
          <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm">
            <li>{t('bill.activate_1')}</li>
            <li>{t('bill.activate_2', { tag: b.needs.cost_allocation_tag, boxTag: b.needs.box_tag })}</li>
            <li>{t('bill.activate_3', { hours: b.needs.lag_hours })}</li>
          </ol>
        </div>
      ) : null}
      {p.problem === 'access_denied' ? <p className="text-sm">{t('bill.permissions', { a: 'ce:GetCostAndUsage', b: 'ce:GetTags' })}</p> : null}
      <p className="text-xs text-muted-foreground">{t('bill.estimate_only_note')}</p>
    </Card>
  );
}

function BudgetCard({ b }: { b: BudgetFigure }) {
  const g = gauge(b);
  const alerts = alertList(b);
  const fired = firedList(b);
  return (
    <Card className="space-y-3 p-4" data-testid="bill-budget">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">{t('bill.budget_title')}</h2>
        {b.basis ? <Badge variant="outline" data-testid="bill-budget-basis">{b.basis === 'bill' ? t('bill.badge_bill') : t('bill.badge_estimate')}</Badge> : null}
      </div>
      {b.monthly_usd === null ? (
        <div className="space-y-2">
          <p className="text-sm">{t('bill.budget_none')}</p>
          <AppLink href={hrefs.settings('budgets')} className="inline-flex min-h-11 items-center text-sm text-primary underline-offset-4 hover:underline lg:min-h-0">
            {t('bill.budget_set')}
          </AppLink>
        </div>
      ) : g === null || b.spent === null ? (
        <p className="text-sm">{t('bill.budget_unknown')}</p>
      ) : (
        <div className="space-y-2">
          <p className="text-lg font-semibold tabular-nums" data-testid="bill-budget-spent">{t('bill.budget_spent', { spent: money(b.spent, b.currency), budget: money(b.monthly_usd, 'USD') })}</p>
          <Progress value={g.fill} aria-label={t('bill.budget_gauge')} aria-valuetext={t('bill.budget_percent', { pct: Math.round(g.pct) })} className={g.tone === 'over' ? '[&>div]:bg-destructive' : g.tone === 'warn' ? '[&>div]:bg-amber-500' : ''} data-testid="bill-gauge" />
          <p className="text-sm tabular-nums">{t('bill.budget_percent', { pct: Math.round(g.pct) })}</p>
          <p className="text-xs text-muted-foreground">{b.basis === 'bill' && b.real_through ? t('bill.budget_basis_bill', { date: b.real_through }) : t('bill.budget_basis_estimate')}</p>
        </div>
      )}
      <p className="text-xs text-muted-foreground">{alerts ? t('bill.budget_alerts', { list: alerts }) : t('bill.budget_alerts_off')}</p>
      {fired ? <p className="text-xs text-muted-foreground">{t('bill.budget_fired', { list: fired })}</p> : null}
    </Card>
  );
}

function Tables({ r }: { r: Reconciliation }) {
  const cur = r.currency;
  return (
    <div className="grid gap-4 lg:grid-cols-2 [&>*]:min-w-0">
      <Card className="space-y-2 p-4" data-testid="bill-box-table">
        <h2 className="text-sm font-semibold">{t('bill.by_box')}</h2>
        {r.boxes.length === 0 ? (
          <p className="text-sm">{t('bill.no_boxes')}</p>
        ) : (
          <Region label={t('bill.boxes_table')} min="min-w-[26rem]">
            <thead>
              <tr className="text-xs text-muted-foreground">
                <th scope="col" className="py-1 pr-2 font-medium">{t('bill.col_box')}</th>
                <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.col_billed')}</th>
                <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.col_estimate')}</th>
                <th scope="col" className="py-1 text-right font-medium">{t('bill.col_diff')}</th>
              </tr>
            </thead>
            <tbody>
              {r.boxes.map((x) => (
                <tr key={x.box_name ?? '-'} className="border-t">
                  <th scope="row" className="py-2 pr-2 font-normal">{x.box_name ?? t('bill.untagged_name')}</th>
                  <td className="py-2 pr-2 text-right tabular-nums">{money(x.real, cur)}</td>
                  <td className="py-2 pr-2 text-right tabular-nums">{money(x.estimate, cur)}</td>
                  <td className="py-2 text-right tabular-nums">{diffText(x.diff, cur)}</td>
                </tr>
              ))}
            </tbody>
          </Region>
        )}
      </Card>
      <Card className="space-y-2 p-4" data-testid="bill-service-table">
        <h2 className="text-sm font-semibold">{t('bill.by_service')}</h2>
        {r.services.length === 0 ? (
          <p className="text-sm">{t('bill.no_boxes')}</p>
        ) : (
          <Region label={t('bill.services_table')} min="min-w-[20rem]">
            <thead>
              <tr className="text-xs text-muted-foreground">
                <th scope="col" className="py-1 pr-2 font-medium">{t('bill.col_service')}</th>
                <th scope="col" className="py-1 text-right font-medium">{t('bill.col_billed')}</th>
              </tr>
            </thead>
            <tbody>
              {r.services.map((x) => (
                <tr key={x.service} className="border-t">
                  <th scope="row" className="py-2 pr-2 font-normal">{x.service}</th>
                  <td className="py-2 text-right tabular-nums">{money(x.real, cur)}</td>
                </tr>
              ))}
            </tbody>
          </Region>
        )}
      </Card>
    </div>
  );
}

function Drift({ r, b }: { r: Reconciliation; b: BillResponse }) {
  const cur = r.currency;
  return (
    <Card className="space-y-2 p-4" data-testid="bill-drift">
      <h2 className="text-sm font-semibold">{t('bill.drift_title')}</h2>
      <p className="text-xs text-muted-foreground">{t('bill.drift_desc', { pct: b.drift_threshold.percent, min: money(b.drift_threshold.min, cur) })}</p>
      {r.drift.length === 0 ? (
        <p className="text-sm" data-testid="bill-drift-none">{t('bill.drift_none')}</p>
      ) : (
        <Region label={t('bill.drift_table')} min="min-w-[44rem]">
          <thead>
            <tr className="text-xs text-muted-foreground">
              <th scope="col" className="py-1 pr-2 font-medium">{t('bill.col_day')}</th>
              <th scope="col" className="py-1 pr-2 font-medium">{t('bill.col_box')}</th>
              <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.col_billed')}</th>
              <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.col_estimate')}</th>
              <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.col_diff')}</th>
              <th scope="col" className="py-1 font-medium">{t('bill.col_cause')}</th>
            </tr>
          </thead>
          <tbody>
            {r.drift.map((d) => (
              <tr key={`${d.date}:${d.box_name ?? '-'}`} className="border-t align-top" data-testid="bill-drift-row">
                <th scope="row" className="py-2 pr-2 font-normal tabular-nums">{d.date}</th>
                <td className="py-2 pr-2">{d.box_name ?? t('bill.untagged_name')}</td>
                <td className="py-2 pr-2 text-right tabular-nums">{money(d.real, cur)}</td>
                <td className="py-2 pr-2 text-right tabular-nums">{money(d.estimate, cur)}</td>
                <td className="py-2 pr-2 text-right tabular-nums">{diffText(d.diff, cur)}</td>
                <td className="py-2">{causeText(d.causes)}</td>
              </tr>
            ))}
          </tbody>
        </Region>
      )}
    </Card>
  );
}

function ModelSpend({ b }: { b: BillResponse }) {
  const m = b.model_spend;
  return (
    <Card className="space-y-2 p-4" data-testid="bill-models">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold">{t('bill.models_title')}</h2>
        <Badge variant="outline">{t('bill.badge_estimate')}</Badge>
      </div>
      <p className="text-xs text-muted-foreground">{t('bill.models_note')}</p>
      {m.calls === 0 ? (
        <p className="text-sm">{t('bill.models_none')}</p>
      ) : (
        <>
          <Region label={t('bill.models_table')} min="min-w-[24rem]">
            <thead>
              <tr className="text-xs text-muted-foreground">
                <th scope="col" className="py-1 pr-2 font-medium">{t('bill.col_model')}</th>
                <th scope="col" className="py-1 pr-2 text-right font-medium">{t('bill.col_calls')}</th>
                <th scope="col" className="py-1 text-right font-medium">{t('bill.col_cost')}</th>
              </tr>
            </thead>
            <tbody>
              {m.by_model.map((x) => (
                <tr key={x.model} className="border-t">
                  <th scope="row" className="break-all py-2 pr-2 font-normal">{x.model}</th>
                  <td className="py-2 pr-2 text-right tabular-nums">{x.calls}</td>
                  <td className="py-2 text-right tabular-nums">{money(x.est_cost_usd, m.currency)}</td>
                </tr>
              ))}
            </tbody>
          </Region>
          {m.unpriced_calls > 0 ? <p className="text-xs text-muted-foreground">{t('bill.models_unpriced', { n: m.unpriced_calls })}</p> : null}
        </>
      )}
    </Card>
  );
}

/** Costs, Bill: what the provider really billed beside the estimate, the difference and why, the budget on the real figure, and forgotten resources. */
export function BillPage() {
  const { client, info } = useApp();
  const { can } = useCan();
  const mayRead = mayWrite('bill', can);
  // A box's own dashboard sees one box, and a bill is for a cloud account: it says so and asks for nothing.
  const notConnected = fleetNotConnected(info);
  // Until the server has said what it is, nothing is asked of it: a box must never be sent a request for a fleet's bill.
  const known = info !== null;
  const q = useAsync<BillResponse | null>((s) => (!known || notConnected ? Promise.resolve(null) : client.bill.bill(s)), [client, known, notConnected], 15_000);
  const [asking, setAsking] = useState(false);
  const b = q.data;
  const refresh = async () => {
    setAsking(true);
    try {
      await client.bill.refreshBill();
      toast.success(t('bill.refresh_started'));
      q.reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('bill.refresh_failed'));
    } finally {
      setAsking(false);
    }
  };
  const busy = asking || b?.refreshing === true;
  const r = b?.reconciliation ?? null;
  const cur = b?.currency ?? r?.currency ?? 'USD';
  return (
    <AppPage>
      <PageHeader
        title={t('bill.title')}
        description={t('bill.desc')}
        actions={
          !known || notConnected || !mayRead ? null : (
            <Button variant="outline" className="w-full sm:w-auto max-lg:h-11" disabled={busy || b?.problem?.problem === 'unsupported'} onClick={refresh}>
              {busy ? t('bill.refreshing') : t('bill.refresh')}
            </Button>
          )
        }
      />
      {notConnected ? (
        <div data-testid="bill-not-connected">
          <EmptyState title={t('bill.nc_title')}>{t('bill.nc_body')}</EmptyState>
        </div>
      ) : null}
      {!notConnected && !mayRead ? <CannotNote cap="start_runs" what={PAGE_CANNOT.bill} /> : null}
      {!notConnected && q.error && !b ? <LoadError title={t('bill.load_failed')} error={q.error} onRetry={q.reload} /> : null}
      {!notConnected && q.error && b ? <LoadError title={t('bill.load_failed')} error={q.error} onRetry={q.reload} stale /> : null}
      {!notConnected && !b && !q.error ? <Skeleton className="h-48 w-full" /> : null}
      {b ? (
        <>
          <div className="flex flex-wrap items-center gap-2" data-testid="bill-source">
            <Badge variant="outline">{hasBill(b) ? t('bill.badge_bill') : t('bill.badge_estimate')}</Badge>
            {b.demo ? <Badge variant="secondary">{t('bill.badge_demo')}</Badge> : null}
            {b.source && b.age_s !== null ? <span className="text-xs text-muted-foreground">{t('bill.source_line', { source: b.source, age: ageText(b.age_s) })}</span> : <span className="text-xs text-muted-foreground">{t('bill.never_read')}</span>}
            {b.stale ? <Badge variant="destructive">{t('bill.stale')}</Badge> : null}
          </div>
          <Problem b={b} />
          {hasBill(b) ? <p className="text-xs text-muted-foreground" data-testid="bill-lag-note">{t('bill.lag', { hours: b.needs.lag_hours })}</p> : null}
          <section aria-label={t('bill.title')} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" data-testid="bill-stats">
            <StatCard label={t('bill.stat_billed')} value={r ? money(r.month_real, cur) : ABSENT} hint={r?.through ? t('bill.stat_billed_hint', { date: r.through }) : undefined} />
            <StatCard label={t('bill.stat_estimate')} value={r ? money(r.month_estimate, cur) : ABSENT} hint={t('bill.stat_estimate_hint')} />
            <StatCard label={t('bill.stat_diff')} value={r ? diffText(r.month_real - r.month_estimate, cur) : ABSENT} hint={r ? diffHint(r.month_real - r.month_estimate) : undefined} />
            <StatCard label={t('bill.stat_models')} value={money(b.model_spend.est_cost_usd, b.model_spend.currency)} hint={t('bill.stat_models_hint')} />
          </section>
          <div className="grid gap-4 lg:grid-cols-2 [&>*]:min-w-0">
            <BudgetCard b={b.budget} />
            {r ? <BillChart days={r.days} currency={cur} /> : null}
          </div>
          {r ? <Tables r={r} /> : null}
          {r ? <Drift r={r} b={b} /> : null}
          <ModelSpend b={b} />
        </>
      ) : null}
      {known && !notConnected ? <OrphansCard /> : null}
    </AppPage>
  );
}
