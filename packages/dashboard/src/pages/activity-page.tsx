import { useMemo, useState } from 'react';
import { FilterIcon, Search01Icon } from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { ActivityEntry } from '../api/types';
import { useApp } from '../App';
import { LoadError } from '../components/load-error';
import { AppPage, EmptyState, PageHeader, TablePager } from '../components/page';
import { toCsv } from '../lib/csv';
import { t } from '../lib/i18n';
import { formatWithUtc } from '../lib/locale';
import { useAsync } from '../lib/use-async';

const PAGE_SIZE = 10;
/** What the server keeps (its ring buffer): said beside the list so nobody reads it as the whole history. */
const SERVER_KEEPS = 500;
const ALL = '__all__';

function exportCsv(rows: ActivityEntry[]): void {
  const csv = toCsv(['time', 'who', 'action', 'box', 'risk', 'outcome'], rows.map((r) => [new Date(r.ts_ms).toISOString(), r.actor, r.action, r.box_name, r.risk, r.outcome]));
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'ozbox-activity.csv';
  a.click();
  URL.revokeObjectURL(url);
}

export function ActivityPage() {
  const { client, info } = useApp();
  const zone = info?.clock?.time_zone;
  const when = (ms: number) => formatWithUtc(ms, zone);
  const feed = useAsync((s) => client.activity(s), [client], 5000);
  const [q, setQ] = useState('');
  const [box, setBox] = useState(ALL);
  const [draft, setDraft] = useState(ALL);
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(1);

  const all = useMemo(() => [...(feed.data?.entries ?? [])].reverse(), [feed.data]);
  const boxes = useMemo(() => [...new Set(all.map((e) => e.box_name))].sort(), [all]);
  const needle = q.trim().toLowerCase();
  const shown = all.filter((e) => (box === ALL || e.box_name === box) && (!needle || `${e.action} ${e.box_name} ${e.outcome}`.toLowerCase().includes(needle)));
  const pages = Math.max(1, Math.ceil(shown.length / PAGE_SIZE));
  const cur = Math.min(page, pages);
  const rows = shown.slice((cur - 1) * PAGE_SIZE, cur * PAGE_SIZE);

  return (
    <AppPage>
      <PageHeader
        title={t('activity.title')}
        description={t('activity.desc')}
        actions={
          <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" disabled={shown.length === 0} onClick={() => exportCsv(shown)}>
            {t('activity.export')}
          </Button>
        }
      />
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative w-full sm:max-w-xs">
          <HugeiconsIcon icon={Search01Icon} className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} placeholder={t('activity.search')} aria-label={t('activity.search')} className="h-11 pl-8 lg:h-9" />
        </div>
        <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" onClick={() => { setDraft(box); setOpen(true); }}>
          <HugeiconsIcon icon={FilterIcon} className="h-4 w-4" /> {box !== ALL ? t('activity.filters_count') : t('activity.filters')}
        </Button>
      </div>
      {feed.data?.since_start ? (
        <p role="note" data-testid="activity-since-start" className="text-xs text-muted-foreground">
          {t('activity.since_start', { max: SERVER_KEEPS })}
        </p>
      ) : null}
      {feed.error && !feed.data ? <LoadError title={t('activity.load_failed')} error={feed.error} onRetry={feed.reload} /> : null}
      {feed.error && feed.data ? <LoadError title={t('activity.load_failed')} error={feed.error} onRetry={feed.reload} stale /> : null}
      {!feed.data && !feed.error && <Skeleton className="h-48 w-full" />}
      {feed.data && all.length === 0 && <EmptyState title={t('activity.none')}>{t('activity.none_body')}</EmptyState>}
      {feed.data && all.length > 0 && shown.length === 0 && <EmptyState title={t('activity.no_match')}>{t('activity.no_match_body')}</EmptyState>}
      {rows.length > 0 && (
        <>
          <ul className="space-y-3 md:hidden" aria-label={t('activity.list')}>
            {rows.map((e, i) => (
              <li key={`${e.ts_ms}-${i}`}>
                <Card className="p-4 text-sm">
                  <p className="font-medium">{`${e.action} · ${e.box_name}`}</p>
                  <p className="text-xs text-muted-foreground">{`${when(e.ts_ms)} · ${e.actor}`}</p>
                  <p className="mt-1 text-xs">{e.outcome}</p>
                </Card>
              </li>
            ))}
          </ul>
          <Card className="hidden overflow-hidden md:block">
            <Table aria-label={t('activity.list')}>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('activity.col_when')}</TableHead>
                  <TableHead>{t('activity.col_who')}</TableHead>
                  <TableHead>{t('activity.col_action')}</TableHead>
                  <TableHead>{t('activity.col_box')}</TableHead>
                  <TableHead>{t('activity.col_risk')}</TableHead>
                  <TableHead>{t('activity.col_outcome')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((e, i) => (
                  <TableRow key={`${e.ts_ms}-${i}`}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{when(e.ts_ms)}</TableCell>
                    <TableCell>{e.actor}</TableCell>
                    <TableCell className="font-medium">{e.action}</TableCell>
                    <TableCell>{e.box_name}</TableCell>
                    <TableCell>{e.risk ? <Badge variant={e.risk === 'high' ? 'destructive' : 'outline'}>{e.risk}</Badge> : '—'}</TableCell>
                    <TableCell>{e.outcome}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <TablePager page={cur} pageSize={PAGE_SIZE} total={shown.length} noun={[t('activity.entry'), t('activity.entries')]} onPageChange={setPage} />
          </Card>
          <div className="md:hidden">
            <TablePager page={cur} pageSize={PAGE_SIZE} total={shown.length} noun={[t('activity.entry'), t('activity.entries')]} onPageChange={setPage} />
          </div>
        </>
      )}
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="activity-filters">
          <form className="flex min-h-0 flex-1 flex-col" onSubmit={(e) => { e.preventDefault(); setBox(draft); setPage(1); setOpen(false); }}>
            <PanelSheetHeader>
              <PanelSheetTitle>{t('activity.filters')}</PanelSheetTitle>
              <PanelSheetDescription>{t('activity.filters_desc')}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody>
              <div className="space-y-1">
                <Label htmlFor="activity-box">{t('activity.box')}</Label>
                <Select value={draft} onValueChange={setDraft}>
                  <SelectTrigger id="activity-box">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL}>{t('activity.all_boxes')}</SelectItem>
                    {boxes.map((b) => (
                      <SelectItem key={b} value={b}>
                        {b}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => { setBox(ALL); setPage(1); setOpen(false); }}>
                {t('activity.clear')}
              </Button>
              <Button type="submit">{t('activity.apply')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </AppPage>
  );
}
