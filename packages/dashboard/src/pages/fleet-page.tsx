import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { useApp } from '../App';
import { BoxCard } from '../components/box-card';
import { AppLink, AppPage, EmptyState, PageHeader, StatCard } from '../components/page';
import { deriveAlerts } from '../lib/alerts';
import { ABSENT, fmtPct } from '../lib/format';
import { openFlow } from '../lib/flows';
import { fleetNotConnected } from '../lib/fleet';
import { t } from '../lib/i18n';
import { hrefs } from '../lib/router';
import { costFor, fmtEstimate } from '../lib/cost';
import type { SelfTest } from '../api/types';
import { ListNote, WarmingNote } from '../components/list-note';
import { UnreachableNote } from '../components/unreachable-note';
import { useFleet } from '../lib/use-fleet';
import { useAsync } from '../lib/use-async';

export function FleetPage() {
  const { client, info } = useApp();
  const fleet = useFleet(client, info);
  const cost = useAsync((s) => (fleetNotConnected(info) ? Promise.resolve(null) : client.cost(s)), [client, info?.fleet?.mode], 60_000);
  const approvals = useAsync((s) => client.approvals(s), [client], 5000);
  const boxes = fleet.data?.boxes ?? [];
  const metrics = fleet.data?.metrics ?? {};
  // The newest self-test of every running box, slowly (a self-test runs real checks on the box).
  const runningNames = boxes.filter((b) => b.state === 'running').map((b) => b.spec.name);
  const runningKey = runningNames.join(',');
  const selftests = useAsync(
    async (s) => {
      const tests: Record<string, SelfTest | undefined> = {};
      const unreachable: { name: string; reason: string }[] = [];
      await Promise.all(
        runningNames.map(async (n) => {
          try {
            tests[n] = (await client.selftest(n, s)).result;
          } catch (e) {
            if (s.aborted) throw e;
            unreachable.push({ name: n, reason: e instanceof Error ? e.message : String(e) });
          }
        }),
      );
      return { tests, unreachable };
    },
    [client, runningKey],
    120_000,
  );
  const unreachable = [...(fleet.data?.unreachable ?? [])];
  const pending = approvals.data?.items ?? [];
  const alerts = fleet.data ? deriveAlerts(boxes, metrics, selftests.data?.tests) : [];
  const running = boxes.filter((b) => b.state === 'running').length;
  const paused = boxes.filter((b) => b.state === 'paused').length;
  const cpus = Object.values(metrics).flatMap((m) => (m ? [m.sample.cpu_pct] : []));
  const avgCpu = cpus.length ? cpus.reduce((a, b) => a + b, 0) / cpus.length : null;
  const notConnected = fleetNotConnected(info);
  const costValue = notConnected ? t('fleet.stat_cost_nc') : cost.error && !cost.data ? t('fleet.stat_cost_error') : fmtEstimate(cost.data?.fleet.month_to_date ?? null, cost.data?.fleet.month_to_date_currency ?? null);
  const costHint = cost.error && !cost.data && !notConnected ? cost.error.message : notConnected ? undefined : t('fleet.stat_cost_hint');

  return (
    <AppPage>
      <PageHeader
        title={t('fleet.title')}
        description={t('fleet.desc')}
        actions={
          <>
            <Button className="max-lg:h-11 w-full sm:w-auto" onClick={() => openFlow('create')} data-testid="create-box-button">
              {t('flow.create_box')}
            </Button>
            <Button asChild variant="outline" className="max-lg:h-11 w-full sm:w-auto">
              <AppLink href={hrefs.boxes}>{t('fleet.all_boxes')}</AppLink>
            </Button>
          </>
        }
      />

      <section aria-labelledby="needs-you" className="space-y-2">
        <Card className="p-4">
          <h2 id="needs-you" className="text-sm font-semibold">
            {t('fleet.needs_you')}
          </h2>
          {!fleet.data ? (
            <Skeleton className="mt-3 h-5 w-2/3" />
          ) : alerts.length > 0 || pending.length > 0 ? (
            <ul className="mt-3 space-y-2" aria-label={t('fleet.alerts')}>
              {pending.length > 0 && (
                <li className="flex flex-col gap-1 rounded-md border p-2 sm:flex-row sm:items-center sm:gap-3">
                  <span className="w-fit rounded border px-1.5 py-0.5 text-[11px] font-semibold">{t('fleet.approval')}</span>
                  <AppLink href={hrefs.approvals} className="flex min-h-11 min-w-0 items-center text-sm underline-offset-4 hover:underline lg:min-h-0">
                    {`${pending.length === 1 ? t('fleet.plans_waiting_one') : t('fleet.plans_waiting', { n: pending.length })}${pending.some((p) => p.needs_passkey) ? t('fleet.plans_passkey') : ''}.`}
                  </AppLink>
                </li>
              )}
              {alerts.map((a) => (
                <li key={a.id} className="flex flex-col gap-1 rounded-md border p-2 sm:flex-row sm:items-center sm:gap-3">
                  <span className={a.severity === 'critical' ? 'w-fit rounded border border-destructive px-1.5 py-0.5 text-[11px] font-semibold text-destructive' : 'w-fit rounded border px-1.5 py-0.5 text-[11px] font-semibold'}>
                    {a.severity === 'critical' ? t('fleet.urgent') : t('fleet.warning')}
                  </span>
                  <AppLink href={hrefs.box(a.box)} className="flex min-h-11 min-w-0 items-center text-sm underline-offset-4 hover:underline lg:min-h-0">
                    {a.text}
                  </AppLink>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-muted-foreground">{t('fleet.nothing')}</p>
          )}
        </Card>
      </section>

      <section aria-label={t('fleet.totals')} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label={t('fleet.stat_boxes')} value={fleet.data ? boxes.length : ABSENT} />
        <StatCard label={t('fleet.stat_running')} value={fleet.data ? `${running} / ${paused}` : ABSENT} />
        <StatCard label={t('fleet.stat_cpu')} value={fmtPct(avgCpu)} hint={cpus.length ? (info?.metrics === 'simulated' ? t('fleet.stat_cpu_hint') : t('fleet.stat_cpu_hint_live')) : undefined} />
        <StatCard label={t('fleet.stat_cost')} value={costValue} hint={costHint} />
      </section>

      {approvals.error && !approvals.data && (
        <p role="alert" className="rounded-lg border border-destructive/40 p-3 text-sm" data-testid="approvals-error">
          {t('fleet.approvals_error', { why: approvals.error.message })}
        </p>
      )}
      {cost.error && !cost.data && !notConnected && (
        <p role="alert" className="rounded-lg border border-destructive/40 p-3 text-sm" data-testid="cost-error">
          {t('fleet.cost_error', { why: cost.error.message })}
        </p>
      )}
      <ListNote list={fleet.data?.list} />
      <UnreachableNote items={[...unreachable, ...(selftests.data?.unreachable ?? []).filter((u) => !unreachable.some((x) => x.name === u.name))]} />

      {fleet.error && !fleet.data && (
        <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm">
          <p>{fleet.error.message}</p>
          <Button variant="outline" className="mt-2 max-lg:h-11" onClick={fleet.reload}>
            {t('fleet.try_again')}
          </Button>
        </div>
      )}
      {!fleet.data && !fleet.error && <WarmingNote />}
      {!fleet.data && !fleet.error && (
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label={t('fleet.loading')}>
          {[0, 1, 2].map((i) => (
            <li key={i}>
              <Skeleton className="h-52 w-full" />
            </li>
          ))}
        </ul>
      )}
      {fleet.data && boxes.length === 0 && (
        info?.setup?.needed ? (
          <EmptyState title={t('fleet.first_title')}>
            <p>{t('fleet.first_body')}</p>
            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
              <Button className="max-lg:h-11" onClick={() => openFlow('setup')} data-testid="setup-fleet-button">
                {t('flow.setup_fleet')}
              </Button>
              <Button variant="outline" className="max-lg:h-11" onClick={() => openFlow('sandbox')} data-testid="try-free-button">
                {t('setup.try_free')}
              </Button>
            </div>
          </EmptyState>
        ) : (
          <EmptyState title={t('fleet.empty_title')}>
            <p>{t('fleet.empty_body')}</p>
            <Button className="mt-3 max-lg:h-11" onClick={() => openFlow('create')}>
              {t('flow.create_box')}
            </Button>
          </EmptyState>
        )
      )}
      {boxes.length > 0 && (
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label={t('fleet.boxes')}>
          {boxes.map((b) => (
            <li key={b.spec.name}>
              <BoxCard box={b} now={metrics[b.spec.name]} domain={info?.domain ?? null} cost={costFor(cost.data, b.spec.name)} />
            </li>
          ))}
        </ul>
      )}
    </AppPage>
  );
}
