import { useEffect, useState } from 'react';
import { MoreHorizontalIcon } from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { FittedTabsList, FittedTabsTrigger } from '@/components/ui/fitted-tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent } from '@/components/ui/tabs';
import { ApiError } from '../api/client';
import type { BoxRecord, MetricsNow, MetricsSeries } from '../api/types';
import { useApp } from '../App';
import { AgentMcpCard } from '../components/agent-mcp-card';
import { BoxActionSheets, type ActionKind } from '../components/box-action-sheets';
import { AppLink, AppPage, EmptyState, PageHeader, StatCard, StatusDot } from '../components/page';
import { ConnectButtons } from '../components/connect-buttons';
import { FilesView } from '../components/files/files-view';
import { ToolsView } from '../components/tools/tools-view';
import { TerminalView } from '../components/terminal/terminal-view';
import { t } from '../lib/i18n';
import { BackupsTab } from '../components/backups-tab';
import { CodeTab } from '../components/code-tab';
import { HealthTab } from '../components/health-tab';
import { OpenInMenu } from '../components/open-in';
import { SourceBadge } from '../components/source-badge';
import { UsageBar } from '../components/usage-bar';
import { UsageChart } from '../components/usage-chart';
import { ABSENT, diskUsedPct, fmtBytes, fmtPct, fmtRelative, isMachineMissing, memUsedPct, sizeLabel } from '../lib/format';
import { hrefs, navigate } from '../lib/router';
import { RANGES, type Range } from '../lib/series';
import { useAsync } from '../lib/use-async';
import { CannotNote } from '../components/role-scope';
import { useCan } from '../lib/use-can';
import { costFor, fmtEstimate } from '../lib/cost';
import { fleetNotConnected } from '../lib/fleet';

function Usage({ name }: { name: string }) {
  const { client } = useApp();
  const [rangeId, setRangeId] = useState<Range['id']>('live');
  const range = RANGES.find((r) => r.id === rangeId) ?? RANGES[0];
  const now = useAsync<MetricsNow>((s) => client.metricsNow(name, s), [client, name], 5000);
  const series = useAsync<MetricsSeries>((s) => client.metricsSeries(name, new Date(Date.now() - (range?.spanMs ?? 0)), range?.step ?? '5s', s), [client, name, rangeId], range?.refreshMs);
  if (!range) return null;

  if (now.error && !now.data) {
    const unavailable = now.error instanceof ApiError && now.error.status === 501;
    return <EmptyState title={unavailable ? t('usage.none') : t('boxpage.usage_error')}>{unavailable ? t('boxpage.usage_unavailable') : now.error.message}</EmptyState>;
  }
  const sample = now.data?.sample;
  const all = series.data?.samples ?? [];
  const cpu = all.map((s) => ({ t: s.ts_ms, v: s.cpu_pct }));
  const mem = all.flatMap((s) => {
    const v = memUsedPct(s);
    return v === null ? [] : [{ t: s.ts_ms, v }];
  });
  const withDate = range.spanMs > 86_400_000;
  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold">{t('nav.usage')}</h2>
          {now.data && <SourceBadge source={now.data.source} />}
        </div>
        <Tabs value={rangeId} onValueChange={(v) => setRangeId(v as Range['id'])}>
          <FittedTabsList aria-label={t('boxpage.chart_range')}>
            {RANGES.map((r) => (
              <FittedTabsTrigger key={r.id} value={r.id} aria-controls={undefined}>
                {r.label}
              </FittedTabsTrigger>
            ))}
          </FittedTabsList>
        </Tabs>
      </div>
      <Card className="grid gap-3 p-4 sm:grid-cols-3">
        <UsageBar label={t('usage.cpu')} pct={sample?.cpu_pct ?? null} />
        <UsageBar label={t('usage.memory')} pct={memUsedPct(sample)} />
        <UsageBar label={t('boxpage.work_disk')} pct={diskUsedPct(sample)} />
      </Card>
      {series.error && !series.data && <p role="alert" className="text-sm text-destructive">{series.error.message}</p>}
      {!series.data && !series.error ? (
        <div className="grid gap-3 md:grid-cols-2" aria-label={t('fleet.loading')}>
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : (
      <div className="grid gap-3 md:grid-cols-2">
        <UsageChart title={t('usage.cpu')} unit="%" points={cpu} rangeLabel={range.label} colorVar="--chart-2" withDate={withDate} />
        <UsageChart title={t('usage.memory')} unit="%" points={mem} rangeLabel={range.label} colorVar="--chart-1" withDate={withDate} />
      </div>
      )}
      <Card className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold">{t('boxpage.runs')}</h3>
          <AppLink href={`${hrefs.tasks}?box=${encodeURIComponent(name)}`} className="inline-flex min-h-11 items-center text-sm underline-offset-4 hover:underline lg:min-h-0" data-testid="box-tasks-link">
            {t('boxpage.runs_link')}
          </AppLink>
        </div>
        {sample && sample.runs.length > 0 ? (
          <table className="mt-2 w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th scope="col" className="py-1 font-medium">{t('boxpage.col_run')}</th>
                <th scope="col" className="py-1 font-medium">{t('boxpage.col_cpu')}</th>
                <th scope="col" className="py-1 font-medium">{t('boxpage.col_memory')}</th>
              </tr>
            </thead>
            <tbody>
              {sample.runs.map((r) => (
                <tr key={r.id} className="border-t">
                  <th scope="row" className="py-2 text-left font-normal">{r.id}</th>
                  <td className="py-2 tabular-nums">{fmtPct(r.cpu_pct)}</td>
                  <td className="py-2 tabular-nums">{fmtBytes(r.mem_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="mt-2 text-sm text-muted-foreground">{t('boxpage.no_runs')}</p>
        )}
      </Card>
    </div>
  );
}

export function BoxPage({ name }: { name: string }) {
  const { client, info } = useApp();
  const { can } = useCan();
  const box = useAsync<BoxRecord>((s) => client.getBox(name, s), [client, name], 5000);
  const notConnected = fleetNotConnected(info);
  const cost = useAsync((s) => (notConnected ? Promise.resolve(null) : client.cost(s)), [client, notConnected], 60_000);
  const [action, setAction] = useState<ActionKind | null>(null);
  const [tab, setTab] = useState('usage');
  // A tmux session the Code panel's Open asked for; the Terminal tab opened by hand uses the shared terminal.
  const [attach, setAttach] = useState<string | undefined>(undefined);

  useEffect(() => {
    const gone = (e: Event) => {
      if ((e as CustomEvent<string>).detail === name) navigate(hrefs.boxes);
    };
    window.addEventListener('ozbox:box-destroyed', gone);
    return () => window.removeEventListener('ozbox:box-destroyed', gone);
  }, [name]);

  if (box.error && !box.data) {
    return (
      <AppPage>
        <PageHeader title={name} />
        <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm">
          {box.error.message}
          <div className="mt-2">
            <AppLink href={hrefs.boxes} className="inline-flex min-h-11 items-center text-primary underline-offset-4 hover:underline">
              {t('boxpage.back')}
            </AppLink>
          </div>
        </div>
      </AppPage>
    );
  }
  if (!box.data) {
    return (
      <AppPage>
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-24 w-full" />
      </AppPage>
    );
  }
  const b = box.data;
  const boxCost = costFor(cost.data, name);
  const missing = isMachineMissing(b.state);
  return (
    <AppPage>
      <PageHeader
        title={b.spec.name}
        description={<StatusDot state={b.state} />}
        actions={
          <>
            {b.state === 'running' && (
              <Button variant="outline" className="max-lg:h-11 w-full sm:w-auto" onClick={() => setAction('pause')}>
                {t('menu.pause')}
              </Button>
            )}
            {b.state === 'paused' && (
              <Button className="max-lg:h-11 w-full sm:w-auto" onClick={() => setAction('resume')}>
                {t('menu.resume')}
              </Button>
            )}
            {missing && (
              <>
                <Button className="max-lg:h-11 w-full sm:w-auto" onClick={() => setAction('upgrade')}>
                  {t('box.missing_finish')}
                </Button>
                <Button variant="outline" className="max-lg:h-11 w-full text-destructive sm:w-auto" onClick={() => setAction('destroy')}>
                  {t('box.missing_destroy')}
                </Button>
              </>
            )}
            {!missing && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="max-lg:h-11 w-full sm:w-auto" aria-label={t('boxpage.more_actions')}>
                  <HugeiconsIcon icon={MoreHorizontalIcon} className="h-4 w-4" /> {t('boxpage.more')}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuItem onSelect={() => setAction('snapshot')}>{t('menu.snapshot')}</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setAction('resize')}>{t('menu.resize')}</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setAction('upgrade')}>{t('menu.upgrade')}</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => setAction('destroy')} className="text-destructive">
                  {t('menu.destroy')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            )}
          </>
        }
      />
      {missing ? (
        <p role="status" className="rounded-lg border p-3 text-sm" data-testid="missing-hint">
          {t('box.missing_hint')}
        </p>
      ) : (
        <>
          <ConnectButtons box={b} domain={info?.domain ?? null} />
          <OpenInMenu box={b} domain={info?.domain ?? null} />
          {info?.fleet?.mode === 'this_box' && <AgentMcpCard />}
        </>
      )}
      <section aria-label={t('boxpage.summary')} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label={t('boxpage.size')} value={sizeLabel(b.spec.size)} hint={b.machine_type ?? ABSENT} />
        <StatCard label={t('boxpage.work_disk')} value={t('settings.gb', { n: b.spec.work_disk_gb })} />
        <StatCard
          label={t('boxpage.cost_month')}
          value={notConnected ? t('boxpage.cost_nc') : cost.error && !cost.data ? t('boxpage.cost_error') : fmtEstimate(boxCost?.month_to_date ?? null, boxCost?.currency ?? null)}
          hint={notConnected ? undefined : cost.error && !cost.data ? cost.error.message : boxCost?.run_rate_month != null ? t('boxpage.cost_rate', { amount: fmtEstimate(boxCost.run_rate_month, boxCost.currency) }) : t('boxpage.cost_hint')}
        />
        <StatCard label={t('boxpage.last_activity')} value={fmtRelative(b.last_activity_at)} />
      </section>

      <Tabs
        value={tab}
        onValueChange={(v) => {
          setTab(v);
          setAttach(undefined);
        }} className="space-y-4">
        <FittedTabsList aria-label={t('boxpage.sections')}>
          <FittedTabsTrigger value="usage">{t('nav.usage')}</FittedTabsTrigger>
          <FittedTabsTrigger value="backups">{t('boxpage.tab_snapshots')}</FittedTabsTrigger>
          <FittedTabsTrigger value="health">{t('boxpage.tab_health')}</FittedTabsTrigger>
          <FittedTabsTrigger value="files">{t('files.tab')}</FittedTabsTrigger>
          <FittedTabsTrigger value="tools">{t('tools.tab')}</FittedTabsTrigger>
          <FittedTabsTrigger value="terminal">{t('terminal.tab')}</FittedTabsTrigger>
          <FittedTabsTrigger value="code">{t('code.tab')}</FittedTabsTrigger>
        </FittedTabsList>
        <TabsContent value="usage" className="mt-0">
          {b.state !== 'running' ? (
            <EmptyState title={t('boxpage.not_running')}>{t('boxpage.not_running_usage')}</EmptyState>
          ) : (
            <Usage name={name} />
          )}
        </TabsContent>
        <TabsContent value="backups" className="mt-0">
          <BackupsTab box={b} />
        </TabsContent>
        <TabsContent value="health" className="mt-0">
          {b.state === 'running' ? <HealthTab name={name} /> : <EmptyState title={t('boxpage.not_running')}>{t('boxpage.not_running_health')}</EmptyState>}
        </TabsContent>
        <TabsContent value="files" className="mt-0">
          {tab === 'files' && (can('use_boxes') ? <FilesView box={b} /> : <CannotNote cap="use_boxes" />)}
        </TabsContent>
        <TabsContent value="tools" className="mt-0">
          {tab === 'tools' && <ToolsView box={b} />}
        </TabsContent>
        <TabsContent value="terminal" className="mt-0">
          {tab === 'terminal' && !can('use_boxes') && <CannotNote cap="use_boxes" />}
          {tab === 'terminal' && can('use_boxes') &&
            (b.state === 'running' ? <TerminalView box={name} session={attach} className="h-[70dvh]" /> : <EmptyState title={t('terminal.title')}>{t('terminal.not_running')}</EmptyState>)}
        </TabsContent>
        <TabsContent value="code" className="mt-0">
          {tab === 'code' && !can('use_boxes') && <CannotNote cap="use_boxes" />}
          {tab === 'code' && can('use_boxes') && <CodeTab
              box={b}
              onOpenTerminal={(session) => {
                setAttach(session);
                setTab('terminal');
              }}
            />}
        </TabsContent>
      </Tabs>

      {action && <BoxActionSheets key={action} box={b} kind={action} client={client} info={info} onClose={() => setAction(null)} onApplied={box.reload} />}
    </AppPage>
  );
}
