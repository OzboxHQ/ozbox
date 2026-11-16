import { useMemo, useState } from 'react';
import { FilterIcon, Search01Icon } from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useApp } from '../App';
import { BoxActionSheets, type ActionKind } from '../components/box-action-sheets';
import { BoxMenu } from '../components/box-menu';
import { AppLink, AppPage, EmptyState, PageHeader, StatusDot, TablePager } from '../components/page';
import { SourceBadge } from '../components/source-badge';
import { UsageBar } from '../components/usage-bar';
import type { BoxRecord } from '../api/types';
import { ABSENT, fmtRelative, isMachineMissing, memUsedPct, sizeLabel } from '../lib/format';
import { t } from '../lib/i18n';
import { hrefs, navigate } from '../lib/router';
import { useFleet } from '../lib/use-fleet';
import { openFlow } from '../lib/flows';
import { ListNote, WarmingNote } from '../components/list-note';
import { UnreachableNote } from '../components/unreachable-note';

const PAGE_SIZE = 8;
type StateFilter = 'all' | 'running' | 'paused' | 'other';

/** What a box with no machine shows in a list: why, and the one thing to do about it. */
function MissingNote({ onFinish }: { onFinish: () => void }) {
  return (
    <div className="mt-1 space-y-2" data-testid="missing-note">
      <p className="max-w-xs text-xs text-muted-foreground">{t('box.missing_hint')}</p>
      <Button size="sm" className="max-lg:h-11" onClick={onFinish}>
        {t('box.missing_finish')}
      </Button>
    </div>
  );
}

function matches(b: BoxRecord, q: string, state: StateFilter): boolean {
  if (q && !b.spec.name.toLowerCase().includes(q)) return false;
  if (state === 'running') return b.state === 'running';
  if (state === 'paused') return b.state === 'paused';
  if (state === 'other') return b.state !== 'running' && b.state !== 'paused';
  return true;
}

function FiltersSheet({ open, state, onApply, onClose }: { open: boolean; state: StateFilter; onApply: (s: StateFilter) => void; onClose: () => void }) {
  const [draft, setDraft] = useState<StateFilter>(state);
  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="filters-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            onApply(draft);
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('boxes.filters')}</PanelSheetTitle>
            <PanelSheetDescription>{t('boxes.filters_description')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody>
            <div className="space-y-1">
              <Label htmlFor="filter-state">{t('boxes.state')}</Label>
              <Select value={draft} onValueChange={(v) => setDraft(v as StateFilter)}>
                <SelectTrigger id="filter-state">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('boxes.state_all')}</SelectItem>
                  <SelectItem value="running">{t('boxes.state_running')}</SelectItem>
                  <SelectItem value="paused">{t('boxes.state_paused')}</SelectItem>
                  <SelectItem value="other">{t('boxes.state_other')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={() => onApply('all')}>
              {t('boxes.clear')}
            </Button>
            <Button type="submit">{t('boxes.apply')}</Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

export function BoxesPage() {
  const { client, info } = useApp();
  const fleet = useFleet(client, info);
  const [q, setQ] = useState('');
  const [state, setState] = useState<StateFilter>('all');
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [action, setAction] = useState<{ box: BoxRecord; kind: ActionKind } | null>(null);

  const boxes = useMemo(() => fleet.data?.boxes ?? [], [fleet.data]);
  const metrics = fleet.data?.metrics ?? {};
  const needle = q.trim().toLowerCase();
  const shown = useMemo(() => boxes.filter((b) => matches(b, needle, state)), [boxes, needle, state]);
  const pageCount = Math.max(1, Math.ceil(shown.length / PAGE_SIZE));
  const current = Math.min(page, pageCount);
  const rows = shown.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);

  return (
    <AppPage>
      <PageHeader
        title={t('nav.boxes')}
        description={t('boxes.description')}
        actions={
          <Button className="max-lg:h-11 w-full sm:w-auto" onClick={() => openFlow('create')} data-testid="create-box-button">
            {t('flow.create_box')}
          </Button>
        }
      />
      <ListNote list={fleet.data?.list} />
      <UnreachableNote items={fleet.data?.unreachable ?? []} />

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative w-full sm:max-w-xs">
          <HugeiconsIcon icon={Search01Icon} className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} placeholder={t('boxes.search')} aria-label={t('boxes.search')} className="h-11 pl-8 lg:h-9" />
        </div>
        <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" onClick={() => setFiltersOpen(true)}>
          <HugeiconsIcon icon={FilterIcon} className="h-4 w-4" /> {state !== 'all' ? t('boxes.filters_active') : t('boxes.filters')}
        </Button>
      </div>

      {!fleet.data && !fleet.error && (
        <>
          <Skeleton className="h-64 w-full" />
          <WarmingNote />
        </>
      )}
      {fleet.error && !fleet.data && (
        <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm">
          {fleet.error.message}
        </div>
      )}
      {fleet.data && boxes.length === 0 && <EmptyState title={t('boxes.none')}>{t('boxes.none_before')}<code className="font-mono text-xs">{'ozbox create my-box --size M'}</code>{t('boxes.none_after')}</EmptyState>}
      {fleet.data && boxes.length > 0 && shown.length === 0 && <EmptyState title={t('boxes.no_match')}>{t('boxes.no_match_body')}</EmptyState>}

      {rows.length > 0 && (
        <>
          {/* Phones and small tablets: each box is a stacked card. */}
          <ul className="space-y-3 md:hidden" aria-label={t('nav.boxes')}>
            {rows.map((b) => {
              const s = metrics[b.spec.name]?.sample;
              return (
                <li key={b.spec.name}>
                  <Card className="p-4">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h2 className="truncate text-sm font-semibold">
                          <AppLink href={hrefs.box(b.spec.name)} className="flex min-h-11 items-center underline-offset-4 hover:underline">
                            {b.spec.name}
                          </AppLink>
                        </h2>
                        <p className="font-mono text-xs text-muted-foreground">{`${sizeLabel(b.spec.size)} · ${b.machine_type ?? ABSENT}`}</p>
                      </div>
                      <BoxMenu box={b} onAction={(kind) => setAction({ box: b, kind })} onOpen={() => navigate(hrefs.box(b.spec.name))} />
                    </div>
                    <div className="mt-2 space-y-2">
                      <StatusDot state={b.state} />
                      {isMachineMissing(b.state) && <MissingNote onFinish={() => setAction({ box: b, kind: 'upgrade' })} />}
                      {s && (
                        <>
                          <UsageBar label={t('usage.cpu')} pct={s.cpu_pct} />
                          <UsageBar label={t('usage.memory')} pct={memUsedPct(s)} />
                        </>
                      )}
                    </div>
                    <p className="mt-2 text-xs text-muted-foreground">{t('boxes.last_activity', { when: fmtRelative(b.last_activity_at) })}</p>
                  </Card>
                </li>
              );
            })}
          </ul>

          <Card className="hidden overflow-hidden md:block">
            <Table aria-label={t('nav.boxes')}>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('boxes.col_name')}</TableHead>
                  <TableHead>{t('boxes.col_state')}</TableHead>
                  <TableHead>{t('boxes.col_size')}</TableHead>
                  <TableHead className="w-40">{t('usage.cpu')}</TableHead>
                  <TableHead className="w-40">{t('usage.memory')}</TableHead>
                  <TableHead>{t('boxes.col_last_activity')}</TableHead>
                  <TableHead>
                    <span className="sr-only">{t('boxes.col_actions')}</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((b) => {
                  const s = metrics[b.spec.name]?.sample;
                  return (
                    <TableRow key={b.spec.name}>
                      <TableCell className="font-medium">
                        <AppLink href={hrefs.box(b.spec.name)} className="inline-flex min-h-11 min-w-11 items-center underline-offset-4 hover:underline lg:min-h-0">
                          {b.spec.name}
                        </AppLink>
                      </TableCell>
                      <TableCell>
                        <StatusDot state={b.state} />
                        {isMachineMissing(b.state) && <MissingNote onFinish={() => setAction({ box: b, kind: 'upgrade' })} />}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">{`${sizeLabel(b.spec.size)} · ${b.machine_type ?? ABSENT}`}</TableCell>
                      <TableCell>{s ? <UsageBar label={t('usage.cpu')} pct={s.cpu_pct} /> : <span className="text-muted-foreground">{ABSENT}</span>}</TableCell>
                      <TableCell>{s ? <UsageBar label={t('usage.memory')} pct={memUsedPct(s)} /> : <span className="text-muted-foreground">{ABSENT}</span>}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{fmtRelative(b.last_activity_at)}</TableCell>
                      <TableCell className="text-right">
                        <BoxMenu box={b} onAction={(kind) => setAction({ box: b, kind })} onOpen={() => navigate(hrefs.box(b.spec.name))} />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <TablePager page={current} pageSize={PAGE_SIZE} total={shown.length} onPageChange={setPage} />
          </Card>
          <div className="md:hidden">
            <TablePager page={current} pageSize={PAGE_SIZE} total={shown.length} onPageChange={setPage} />
          </div>
          {Object.values(metrics).some((m) => m?.source === 'simulated') && <SourceBadge source="simulated" />}
        </>
      )}

      <FiltersSheet key={String(filtersOpen)} open={filtersOpen} state={state} onClose={() => setFiltersOpen(false)} onApply={(s) => { setState(s); setPage(1); setFiltersOpen(false); }} />
      {action && <BoxActionSheets key={`${action.box.spec.name}:${action.kind}`} box={action.box} kind={action.kind} client={client} info={info} onClose={() => setAction(null)} onApplied={fleet.reload} />}
    </AppPage>
  );
}
