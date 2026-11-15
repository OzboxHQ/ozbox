import { useMemo, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { FittedTabsList, FittedTabsTrigger } from '@/components/ui/fitted-tabs';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs } from '@/components/ui/tabs';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../api/client';
import { TASK_STATES, type BulkAction, type Task, type TaskFilter, type TaskState } from '../api/tasks';
import { useApp } from '../App';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { CannotNote } from '../components/role-scope';
import { NewTaskSheet } from '../components/tasks/new-task-sheet';
import { TaskDetailSheet } from '../components/tasks/task-detail-sheet';
import { costSourceText, costText, modelText, originText, pullRequest, stateLabel, StateBadge, timeText, whyLine } from '../components/tasks/task-bits';
import { SourceBadge } from '../components/source-badge';
import { t, type MessageKey } from '../lib/i18n';
import { anyFilter, bulkCount, COLUMNS, filtersFromSearch, groupByColumn, NO_FILTERS, sinceFor, type Column, type Filters } from '../lib/tasks';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const COLUMN_LABEL: Record<Column, MessageKey> = {
  queued: 'tasks.col_queued',
  running: 'tasks.col_running',
  needs_you: 'tasks.col_needs_you',
  review: 'tasks.col_review',
  done: 'tasks.col_done',
};

const DATE_LABEL: Record<Filters['date'], MessageKey> = { any: 'tasks.f_any', today: 'tasks.f_today', '7d': 'tasks.f_7d', '30d': 'tasks.f_30d' };

const ALL = '__all__';

function toFilter(f: Filters, now: number): TaskFilter {
  const out: TaskFilter = {};
  if (f.box) out.box = f.box;
  if (f.engine) out.engine = f.engine;
  if (f.person) out.person = f.person;
  if (f.state) out.states = [f.state];
  const since = sinceFor(f.date, now);
  if (since !== undefined) out.since_ms = since;
  return out;
}

function TaskCard({ task, selected, onSelect, onOpen }: { task: Task; selected: boolean; onSelect: (on: boolean) => void; onOpen: () => void }) {
  const pr = pullRequest(task);
  const why = whyLine(task);
  const origin = originText(task);
  return (
    <Card className="space-y-2 p-3 text-sm" data-testid="task-card" data-state={task.state}>
      <div className="flex items-start gap-1">
        <TouchCheckbox aria-label={t('tasks.select', { id: task.id })} checked={selected} onCheckedChange={(c) => onSelect(c === true)} />
        <div className="min-w-0 flex-1 pt-1.5 lg:pt-0">
          <p className="break-words font-medium">{task.prompt || task.skill || task.id}</p>
          <p className="break-words text-xs text-muted-foreground">
            {t('tasks.on_box', { box: task.box })} · {task.engine} · {t('tasks.by', { person: task.person })}
          </p>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {task.state === 'failed' || task.state === 'cancelled' ? <StateBadge state={task.state} /> : null}
        {why ? <Badge variant={task.state === 'needs_you' ? 'default' : 'outline'}>{why}</Badge> : null}
        {origin ? <Badge variant="outline">{origin}</Badge> : null}
      </div>
      <dl className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <dt className="text-muted-foreground">{t('tasks.cost')}</dt>
          <dd>
            {costText(task)}
            {costSourceText(task) ? <span className="text-muted-foreground"> · {costSourceText(task)}</span> : null}
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{t('tasks.elapsed')}</dt>
          <dd>{timeText(task)}</dd>
        </div>
        {modelText(task) ? (
          <div className="col-span-2">
            <dt className="text-muted-foreground">{t('tasks.model')}</dt>
            <dd className="break-words" data-testid="task-model">
              {modelText(task)}
            </dd>
          </div>
        ) : null}
      </dl>
      <div className="flex flex-wrap items-center justify-between gap-2">
        {pr ? (
          <a href={pr} target="_blank" rel="noreferrer noopener" className="inline-flex min-h-11 items-center text-xs underline underline-offset-4 lg:min-h-0">
            {t('tasks.pr')}
          </a>
        ) : (
          <span />
        )}
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={onOpen}>
          {t('tasks.open')}
        </Button>
      </div>
    </Card>
  );
}

function Board({ tasks, chosen, toggle, open }: { tasks: Task[]; chosen: Set<string>; toggle: (id: string, on: boolean) => void; open: (id: string) => void }) {
  const groups = groupByColumn(tasks);
  return (
    <div className="grid gap-4 lg:grid-cols-5" role="group" aria-label={t('tasks.board_label')} data-testid="task-board">
      {COLUMNS.map((c) => (
        <section key={c} aria-label={t(COLUMN_LABEL[c])} className="min-w-0 space-y-2" data-testid={`col-${c}`}>
          <h2 className="flex items-center justify-between text-sm font-semibold">
            <span>{t(COLUMN_LABEL[c])}</span>
            <Badge variant="secondary">{groups[c].length}</Badge>
          </h2>
          {groups[c].length === 0 ? <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">{t('tasks.col_empty')}</p> : null}
          <ul className="space-y-2">
            {groups[c].map((k) => (
              <li key={k.id}>
                <TaskCard task={k} selected={chosen.has(k.id)} onSelect={(on) => toggle(k.id, on)} onOpen={() => open(k.id)} />
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

function ListView({ tasks, chosen, toggle, toggleAll, open }: { tasks: Task[]; chosen: Set<string>; toggle: (id: string, on: boolean) => void; toggleAll: (on: boolean) => void; open: (id: string) => void }) {
  const all = tasks.length > 0 && tasks.every((k) => chosen.has(k.id));
  return (
    <>
      <ul className="space-y-3 md:hidden" aria-label={t('tasks.list_label')}>
        {tasks.map((k) => (
          <li key={k.id}>
            <TaskCard task={k} selected={chosen.has(k.id)} onSelect={(on) => toggle(k.id, on)} onOpen={() => open(k.id)} />
          </li>
        ))}
      </ul>
      <div className="hidden md:block" data-testid="task-table">
        <Table aria-label={t('tasks.list_label')}>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">
                <TouchCheckbox aria-label={t('tasks.select_all')} checked={all} onCheckedChange={(c) => toggleAll(c === true)} />
              </TableHead>
              <TableHead>{t('tasks.col_task')}</TableHead>
              <TableHead>{t('tasks.col_box')}</TableHead>
              <TableHead>{t('tasks.col_engine')}</TableHead>
              <TableHead>{t('tasks.col_person')}</TableHead>
              <TableHead>{t('tasks.col_state')}</TableHead>
              <TableHead>{t('tasks.col_cost')}</TableHead>
              <TableHead>{t('tasks.col_time')}</TableHead>
              <TableHead>{t('tasks.col_pr')}</TableHead>
              <TableHead>
                <span className="sr-only">{t('tasks.open')}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tasks.map((k) => {
              const pr = pullRequest(k);
              return (
                <TableRow key={k.id} data-testid="task-row">
                  <TableCell>
                    <TouchCheckbox aria-label={t('tasks.select', { id: k.id })} checked={chosen.has(k.id)} onCheckedChange={(c) => toggle(k.id, c === true)} />
                  </TableCell>
                  <TableCell className="max-w-[16rem] break-words">{k.prompt || k.skill || k.id}</TableCell>
                  <TableCell>{k.box}</TableCell>
                  <TableCell>{k.engine}</TableCell>
                  <TableCell>{k.person}</TableCell>
                  <TableCell>
                    <StateBadge state={k.state} />
                  </TableCell>
                  <TableCell>{costText(k)}</TableCell>
                  <TableCell>{timeText(k)}</TableCell>
                  <TableCell>
                    {pr ? (
                      <a href={pr} target="_blank" rel="noreferrer noopener" className="underline underline-offset-4">
                        {t('tasks.pr')}
                      </a>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" onClick={() => open(k.id)}>
                      {t('tasks.open')}
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </>
  );
}

/** The task board and list: every agent run, what it costs, and what needs you. */
export function TasksPage() {
  const { client } = useApp();
  const { can } = useCan();
  const [view, setView] = useState<'board' | 'list'>('board');
  const [filters, setFilters] = useState<Filters>(() => filtersFromSearch(window.location.search));
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [opened, setOpened] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const key = JSON.stringify(filters);
  const list = useAsync((s) => client.tasks.list(toFilter(filters, Date.now()), s), [client, key], 3000);
  const boxes = useAsync((s) => client.listBoxes(s), [client], 20000);
  // Only to offer the person and engine choices: read once and again after a change, never polled (the board polls itself).
  const unfiltered = useAsync((s) => client.tasks.list({}, s), [client]);
  const tasks = list.data?.items ?? [];
  const unavailable = list.error instanceof ApiError && list.error.status === 501;
  const running = (boxes.data ?? []).filter((b) => b.state === 'running').map((b) => b.spec.name);

  const people = useMemo(() => [...new Set((unfiltered.data?.items ?? []).map((k) => k.person))].sort(), [unfiltered.data]);
  const engines = useMemo(() => [...new Set((unfiltered.data?.items ?? []).map((k) => k.engine))].sort(), [unfiltered.data]);
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => setFilters((f) => ({ ...f, [k]: v }));

  const toggle = (id: string, on: boolean) =>
    setChosen((c) => {
      const n = new Set(c);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });
  const toggleAll = (on: boolean) => setChosen(on ? new Set(tasks.map((k) => k.id)) : new Set());

  async function bulk(action: BulkAction) {
    const ids = tasks.filter((k) => chosen.has(k.id)).map((k) => k.id);
    try {
      const r = await client.tasks.bulk(action, ids);
      const ok = r.results.filter((x) => x.ok).length;
      toast.success(t('tasks.bulk_done', { ok, failed: r.results.length - ok }));
      setChosen(new Set());
      list.reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('tasks.action_failed'));
    }
  }

  const nCancel = bulkCount('cancel', tasks, chosen);
  const nRetry = bulkCount('retry', tasks, chosen);
  const nReview = bulkCount('review', tasks, chosen);

  const filterBar = (
    <section aria-label={t('tasks.filters')} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6" data-testid="task-filters">
      <div className="space-y-1">
        <Label htmlFor="tf-box">{t('tasks.f_box')}</Label>
        <Select value={filters.box || ALL} onValueChange={(v) => set('box', v === ALL ? '' : v)}>
          <SelectTrigger id="tf-box">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('tasks.f_any')}</SelectItem>
            {(boxes.data ?? []).map((b) => (
              <SelectItem key={b.spec.name} value={b.spec.name}>
                {b.spec.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="tf-engine">{t('tasks.f_engine')}</Label>
        <Select value={filters.engine || ALL} onValueChange={(v) => set('engine', v === ALL ? '' : v)}>
          <SelectTrigger id="tf-engine">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('tasks.f_any')}</SelectItem>
            {engines.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="tf-state">{t('tasks.f_state')}</Label>
        <Select value={filters.state || ALL} onValueChange={(v) => set('state', v === ALL ? '' : (v as TaskState))}>
          <SelectTrigger id="tf-state">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('tasks.f_any')}</SelectItem>
            {TASK_STATES.map((s) => (
              <SelectItem key={s} value={s}>
                {stateLabel(s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="tf-person">{t('tasks.f_person')}</Label>
        <Select value={filters.person || ALL} onValueChange={(v) => set('person', v === ALL ? '' : v)}>
          <SelectTrigger id="tf-person">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('tasks.f_any')}</SelectItem>
            {people.map((p) => (
              <SelectItem key={p} value={p}>
                {p}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="tf-date">{t('tasks.f_date')}</Label>
        <Select value={filters.date} onValueChange={(v) => set('date', v as Filters['date'])}>
          <SelectTrigger id="tf-date">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(Object.keys(DATE_LABEL) as Filters['date'][]).map((d) => (
              <SelectItem key={d} value={d}>
                {t(DATE_LABEL[d])}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {anyFilter(filters) ? (
        <div className="flex items-end">
          <Button variant="outline" className="w-full max-lg:h-11" onClick={() => setFilters(NO_FILTERS)}>
            {t('tasks.f_clear')}
          </Button>
        </div>
      ) : null}
    </section>
  );

  return (
    <AppPage>
      <PageHeader
        title={t('tasks.title')}
        description={t('tasks.desc')}
        actions={
          <Button className="w-full max-lg:h-11 sm:w-auto" onClick={() => setCreating(true)} disabled={unavailable || !can('start_runs')}>
            {t('tasks.new')}
          </Button>
        }
      />
      {list.data ? <SourceBadge source={list.data.source} /> : null}
      {list.data?.source === 'simulated' ? <p className="text-xs text-muted-foreground">{t('tasks.simulated')}</p> : null}
      {list.error && list.data && !unavailable ? (
        <p role="status" className="text-xs text-destructive" data-testid="tasks-stale">
          {t('tasks.refresh_failed', { reason: list.error.message })}
        </p>
      ) : null}
      {!can('start_runs') && list.data ? <CannotNote cap="start_runs" /> : null}
      {!list.data && !list.error ? <Skeleton className="h-48 w-full" /> : null}
      {unavailable ? (
        <EmptyState title={t('tasks.unavailable')}>
          <span data-testid="tasks-unavailable">{list.error instanceof ApiError ? list.error.message : t('tasks.unavailable_body')}</span>
        </EmptyState>
      ) : null}
      {list.error && !unavailable && !list.data ? (
        <p role="alert" className="text-sm text-destructive">
          {list.error.message}
        </p>
      ) : null}
      {list.data ? (
        <>
          <Tabs value={view} onValueChange={(v) => setView(v as 'board' | 'list')}>
            <FittedTabsList aria-label={t('tasks.view')}>
              <FittedTabsTrigger value="board">{t('tasks.view_board')}</FittedTabsTrigger>
              <FittedTabsTrigger value="list">{t('tasks.view_list')}</FittedTabsTrigger>
            </FittedTabsList>
          </Tabs>
          {filterBar}
          {chosen.size > 0 ? (
            <section aria-label={t('tasks.bulk_label')} className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 p-2" data-testid="bulk-bar">
              <span className="px-1 text-sm font-medium">{t('tasks.selected', { n: chosen.size })}</span>
              <Button variant="outline" className="max-lg:h-11" disabled={nCancel === 0 || !can('start_runs')} onClick={() => setConfirmCancel(true)}>
                {t('tasks.bulk_cancel')}
              </Button>
              <Button variant="outline" className="max-lg:h-11" disabled={nRetry === 0 || !can('start_runs')} onClick={() => bulk('retry')}>
                {t('tasks.bulk_retry')}
              </Button>
              <Button variant="outline" className="max-lg:h-11" disabled={nReview === 0 || !can('start_runs')} onClick={() => bulk('review')}>
                {t('tasks.bulk_review')}
              </Button>
              <Button variant="ghost" className="max-lg:h-11" onClick={() => setChosen(new Set())}>
                {t('tasks.bulk_clear')}
              </Button>
            </section>
          ) : null}
          {tasks.length === 0 ? (
            <EmptyState title={anyFilter(filters) ? t('tasks.none_filtered') : t('tasks.none')}>{anyFilter(filters) ? '' : t('tasks.none_body')}</EmptyState>
          ) : view === 'board' ? (
            <Board tasks={tasks} chosen={chosen} toggle={toggle} open={setOpened} />
          ) : (
            <ListView tasks={tasks} chosen={chosen} toggle={toggle} toggleAll={toggleAll} open={setOpened} />
          )}
        </>
      ) : null}
      {creating ? <NewTaskSheet client={client} boxes={running} simulated={list.data?.source === 'simulated'} onClose={() => setCreating(false)} onQueued={() => { list.reload(); unfiltered.reload(); }} /> : null}
      {opened ? <TaskDetailSheet client={client} id={opened} onClose={() => setOpened(null)} onChanged={() => { list.reload(); unfiltered.reload(); }} /> : null}
      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title={t('tasks.bulk_confirm_title', { n: nCancel })}
        description={t('tasks.bulk_confirm_body')}
        confirmLabel={t('tasks.bulk_confirm_verb')}
        destructive
        onConfirm={() => bulk('cancel')}
      />
    </AppPage>
  );
}
