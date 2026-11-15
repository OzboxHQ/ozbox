import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect, useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { TAP_ACTION } from '@/components/ui/tap-target';
import { Textarea } from '@/components/ui/textarea';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../api/client';
import type { SchedulePreview, ScheduleItem, SchedRun } from '../api/sched';
import { useApp } from '../App';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { Fact, FieldError, Instant, StatusBadge } from '../components/sched-bits';
import { CannotNote } from '../components/role-scope';
import { SourceNote } from '../components/source-badge';
import { fmtCost } from '../lib/format';
import { t, type MessageKey } from '../lib/i18n';
import { boxChoiceLabel, boxChoices, defaultEngine, emptyScheduleForm, engineChoices, formToInput, previewKey, runNote, scheduleSchema, scheduleToForm, sourceLabel, statusLabel, whenText, type ScheduleForm } from '../lib/sched';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const fieldMsg = (m?: string): string | undefined => (m ? t(`schedules.${m}` as MessageKey) : undefined);
const errorText = (e: unknown): string => (e instanceof ApiError ? e.message : t('common.save_failed'));

function ScheduleSheet({ item, zone, boxes, source, onClose, onSaved }: { item: ScheduleItem | null; zone: string; boxes: string[]; source: 'simulated' | 'live'; onClose: () => void; onSaved: () => void }) {
  const { client } = useApp();
  const [err, setErr] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ key: string; data: SchedulePreview } | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const form = useForm<ScheduleForm>({ resolver: zodResolver(scheduleSchema), defaultValues: item ? scheduleToForm(item) : emptyScheduleForm(zone, defaultEngine(source)) });
  const e = form.formState.errors;
  const kind = form.watch('kind');
  const v = form.watch();
  const key = previewKey(v as ScheduleForm);
  const fresh = preview?.key === key;
  const needsPreview = kind === 'task';

  const runPreview = async () => {
    setErr(null);
    setPreviewing(true);
    try {
      const data = await client.sched.preview({ ...(v.whenText ? { when_text: v.whenText } : { cron: v.cron }), time_zone: v.timeZone });
      setPreview({ key, data });
    } catch (x) {
      setPreview(null);
      setErr(errorText(x));
    } finally {
      setPreviewing(false);
    }
  };

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="wide" data-testid="schedule-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          noValidate
          onSubmit={form.handleSubmit(async (f) => {
            setErr(null);
            if (needsPreview && !fresh) return setErr(preview ? t('schedules.preview_stale') : t('schedules.preview_needed'));
            try {
              const input = formToInput(f);
              if (item) await client.sched.update(item.id, input);
              else await client.sched.create(input);
            } catch (x) {
              return setErr(errorText(x));
            }
            toast.success(t('schedules.saved'));
            onSaved();
            onClose();
          })}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{item ? t('schedules.form_edit') : t('schedules.form_new')}</PanelSheetTitle>
            <PanelSheetDescription>{t('schedules.form_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {err ? (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{err}</AlertDescription>
              </Alert>
            ) : null}
            <div className="space-y-1">
              <Label htmlFor="sc-name">{t('schedules.f_name')}</Label>
              <Input id="sc-name" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.name} {...form.register('name')} />
              <FieldError msg={fieldMsg(e.name?.message)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="sc-kind">{t('schedules.f_kind')}</Label>
              <Select value={kind} onValueChange={(x) => form.setValue('kind', x as ScheduleForm['kind'], { shouldValidate: true })}>
                <SelectTrigger id="sc-kind" className="max-lg:h-11">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="task">{t('schedules.kind_task')}</SelectItem>
                  <SelectItem value="heartbeat">{t('schedules.kind_heartbeat')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {kind === 'task' ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor="sc-when">{t('schedules.f_when_text')}</Label>
                  <Input id="sc-when" autoComplete="off" className="max-lg:h-11" aria-describedby="sc-when-hint" aria-invalid={!!e.whenText} {...form.register('whenText')} />
                  <p id="sc-when-hint" className="text-xs text-muted-foreground">
                    {t('schedules.f_when_hint')}
                  </p>
                  <FieldError msg={fieldMsg(e.whenText?.message)} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="sc-cron">{t('schedules.f_cron')}</Label>
                  <Input id="sc-cron" autoComplete="off" spellCheck={false} className="max-lg:h-11 font-mono" {...form.register('cron')} />
                </div>
              </>
            ) : (
              <div className="space-y-1">
                <Label htmlFor="sc-every">{t('schedules.f_every')}</Label>
                <Input id="sc-every" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-describedby="sc-every-hint" aria-invalid={!!e.everyMinutes} {...form.register('everyMinutes')} />
                <p id="sc-every-hint" className="text-xs text-muted-foreground">
                  {t('schedules.f_every_hint')}
                </p>
                <FieldError msg={fieldMsg(e.everyMinutes?.message)} />
              </div>
            )}
            <div className="space-y-1">
              <Label htmlFor="sc-zone">{t('schedules.f_zone')}</Label>
              <Input id="sc-zone" autoComplete="off" spellCheck={false} className="max-lg:h-11" {...form.register('timeZone')} />
            </div>
            {needsPreview ? (
              <div className="space-y-2" data-testid="schedule-preview">
                <Button type="button" variant="outline" className={TAP_ACTION} onClick={() => void runPreview()} disabled={previewing || (!v.whenText && !v.cron)}>
                  {t('schedules.preview')}
                </Button>
                {preview && fresh ? (
                  <div className="rounded-md border p-3 text-sm">
                    <p className="font-mono text-xs">{t('schedules.preview_cron', { cron: preview.data.cron })}</p>
                    <p className="text-xs text-muted-foreground">{t('schedules.preview_zone', { zone: preview.data.time_zone })}</p>
                    <p className="mt-2 text-xs font-medium">{t('schedules.preview_next')}</p>
                    <ol className="list-decimal space-y-0.5 pl-5">
                      {preview.data.next.map((n) => (
                        <li key={n.ms}>
                          <Instant at={n} />
                        </li>
                      ))}
                    </ol>
                  </div>
                ) : null}
              </div>
            ) : null}
            <div className="space-y-1">
              <Label htmlFor="sc-box">{t('schedules.f_box')}</Label>
              <Select value={v.box} onValueChange={(x) => form.setValue('box', x, { shouldValidate: true })}>
                <SelectTrigger id="sc-box" className="max-lg:h-11" aria-invalid={!!e.box}>
                  <SelectValue placeholder={t('schedules.f_box_pick')} />
                </SelectTrigger>
                <SelectContent>
                  {boxes.map((b) => (
                    <SelectItem key={b} value={b}>
                      {boxChoiceLabel(b)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldError msg={fieldMsg(e.box?.message)} />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="sc-engine">{t('schedules.f_engine')}</Label>
                <Select value={v.engine} onValueChange={(x) => form.setValue('engine', x, { shouldValidate: true })}>
                  <SelectTrigger id="sc-engine" className="max-lg:h-11" aria-invalid={!!e.engine}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {engineChoices(source, v.engine).map((x) => (
                      <SelectItem key={x} value={x}>
                        {x}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldError msg={fieldMsg(e.engine?.message)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="sc-skill">{t('schedules.f_skill')}</Label>
                <Input id="sc-skill" autoComplete="off" className="max-lg:h-11" {...form.register('skill')} />
              </div>
            </div>
            <div className="space-y-1">
              <Label htmlFor="sc-prompt">{t('schedules.f_prompt')}</Label>
              <Textarea id="sc-prompt" aria-invalid={!!e.prompt} {...form.register('prompt')} />
              <FieldError msg={fieldMsg(e.prompt?.message)} />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <Label htmlFor="sc-spend">{t('schedules.f_max_spend')}</Label>
                <Input id="sc-spend" inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.maxSpend} {...form.register('maxSpend')} />
                <FieldError msg={fieldMsg(e.maxSpend?.message)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="sc-minutes">{t('schedules.f_max_minutes')}</Label>
                <Input id="sc-minutes" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.maxMinutes} {...form.register('maxMinutes')} />
                <FieldError msg={fieldMsg(e.maxMinutes?.message)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="sc-catch">{t('schedules.f_catch_up')}</Label>
                <Input id="sc-catch" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.catchUp} {...form.register('catchUp')} />
                <FieldError msg={fieldMsg(e.catchUp?.message)} />
              </div>
            </div>
            <label className="flex min-h-11 items-center gap-3 text-sm">
              <TouchCheckbox checked={v.alertOnFinish} onCheckedChange={(c) => form.setValue('alertOnFinish', c === true)} />
              {t('schedules.f_results_alert')}
            </label>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" className={TAP_ACTION} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" className={TAP_ACTION} disabled={form.formState.isSubmitting}>
              {t('common.save')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function HistorySheet({ item, onClose }: { item: ScheduleItem; onClose: () => void }) {
  const { client } = useApp();
  const runs = useAsync<SchedRun[]>((s) => client.sched.runs(item.id, s), [client, item.id], 5000);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="wide" data-testid="history-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('schedules.runs_title', { name: item.name })}</PanelSheetTitle>
          <PanelSheetDescription>{whenText(item)}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-2">
          {!runs.data && !runs.error && <Skeleton className="h-24 w-full" />}
          {runs.error && <p role="alert" className="text-sm text-destructive">{runs.error.message}</p>}
          {runs.data && runs.data.length === 0 && <p className="text-sm text-muted-foreground">{t('schedules.runs_none')}</p>}
          {runs.data?.map((r) => (
            <Card key={r.id} className="space-y-1 p-3" data-testid="run-row">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge ok={r.status === 'succeeded' ? 'good' : r.status === 'failed' ? 'bad' : 'neutral'}>{statusLabel(r.status)}</StatusBadge>
                <span className="text-xs text-muted-foreground">{sourceLabel(r.source)}</span>
                <time className="text-xs" dateTime={new Date(r.started_ms).toISOString()}>
                  {new Date(r.started_ms).toLocaleString()}
                </time>
              </div>
              <p className="break-words text-sm">{runNote(r, item.catch_up_minutes)}</p>
              <p className="text-xs text-muted-foreground">
                {r.box_name ? `${r.box_name} ` : ''}
                {r.woke_box ? `· ${t('schedules.run_woke')} ` : ''}
                {r.cost !== null ? `· ${t('schedules.run_cost')} ${fmtCost(r.cost)}` : ''}
              </p>
              {r.result_url ? (
                <a className="text-sm underline" href={r.result_url} target="_blank" rel="noreferrer noopener">
                  {t('schedules.run_link')}
                </a>
              ) : null}
            </Card>
          ))}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION} onClick={onClose}>
            {t('common.close')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function ScheduleCard({ s, mayStart, onEdit, onHistory, onRemove, reload }: { s: ScheduleItem; mayStart: boolean; onEdit: () => void; onHistory: () => void; onRemove: () => void; reload: () => void }) {
  const { client } = useApp();
  const act = async (fn: () => Promise<unknown>, ok: MessageKey) => {
    try {
      await fn();
      toast.success(t(ok));
      reload();
    } catch (x) {
      toast.error(errorText(x));
    }
  };
  const last = s.last_run;
  return (
    <Card className="space-y-3 p-4" data-testid="schedule-card" data-schedule={s.name}>
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-base font-semibold">{s.name}</h2>
        <Badge variant={s.enabled ? 'default' : 'secondary'}>{s.enabled ? t('schedules.on') : t('schedules.off')}</Badge>
        {s.heartbeat ? <Badge variant="outline">{t('schedules.heartbeat')}</Badge> : null}
        {s.running ? <Badge variant="outline">{t('schedules.running')}</Badge> : null}
      </div>
      <dl className="grid gap-3 sm:grid-cols-3">
        <Fact label={t('schedules.col_when')}>{whenText(s)}</Fact>
        <Fact label={t('schedules.col_next')}>{s.enabled && s.next ? <Instant at={s.next} /> : t('schedules.no_next')}</Fact>
        <Fact label={t('schedules.col_last')}>
          {last ? (
            <span>
              {statusLabel(last.status)} · {new Date(last.started_ms).toLocaleString()}
            </span>
          ) : (
            t('schedules.never_ran')
          )}
        </Fact>
      </dl>
      {s.cost ? (
        <p className="text-xs text-muted-foreground" data-testid="schedule-cost">
          {t('schedules.cost_wake', { perRun: fmtCost(s.cost.per_run, s.cost.currency ?? 'USD'), perMonth: fmtCost(s.cost.per_month, s.cost.currency ?? 'USD'), runs: s.cost.runs_per_month })}
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">{t('schedules.cost_unknown')}</p>
      )}
      <div className="flex flex-wrap gap-2" role="group" aria-label={t('schedules.actions_for', { name: s.name })}>
        <Button variant="outline" className={TAP_ACTION} disabled={!mayStart} onClick={() => void act(() => client.sched.runNow(s.id), 'schedules.run_now_queued')}>
          {t('schedules.run_now')}
        </Button>
        <Button variant="outline" className={TAP_ACTION} disabled={!mayStart} onClick={() => void act(() => client.sched.setEnabled(s.id, !s.enabled), s.enabled ? 'schedules.paused_toast' : 'schedules.resumed_toast')}>
          {s.enabled ? t('schedules.pause') : t('schedules.resume')}
        </Button>
        <Button variant="outline" className={TAP_ACTION} disabled={!mayStart} onClick={onEdit}>
          {t('schedules.edit')}
        </Button>
        <Button variant="outline" className={TAP_ACTION} onClick={onHistory}>
          {t('schedules.history')}
        </Button>
        <Button variant="outline" className={TAP_ACTION} disabled={!mayStart} onClick={onRemove}>
          {t('schedules.remove')}
        </Button>
      </div>
    </Card>
  );
}

export function SchedulesPage() {
  const { client } = useApp();
  const { can } = useCan();
  const list = useAsync((s) => client.sched.list(s), [client], 5000);
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const [editing, setEditing] = useState<ScheduleItem | 'new' | null>(null);
  const [history, setHistory] = useState<ScheduleItem | null>(null);
  const [removing, setRemoving] = useState<ScheduleItem | null>(null);
  const names = useMemo(() => boxChoices(boxes.data ?? []), [boxes.data]);
  const data = list.data;
  useEffect(() => {
    // Keep an open history sheet pointing at the latest copy of its schedule.
    if (history && data) {
      const fresh = data.schedules.find((x) => x.id === history.id);
      if (fresh && fresh !== history) setHistory(fresh);
    }
  }, [data, history]);

  return (
    <AppPage>
      <PageHeader
        title={t('schedules.title')}
        description={t('schedules.desc')}
        actions={
          <Button className={TAP_ACTION} onClick={() => setEditing('new')} disabled={!data || !can('start_runs')}>
            {t('schedules.add')}
          </Button>
        }
      />
      <SourceNote source={data?.source} what="schedules" />
      {!can('start_runs') ? <CannotNote cap="start_runs" /> : null}
      {!data && !list.error && <Skeleton className="h-40 w-full" />}
      {list.error && !data && <p role="alert" data-testid="schedules-error" className="text-sm text-destructive">{list.error.message}</p>}
      {list.error && data && <p role="alert" data-testid="schedules-stale" className="text-sm text-destructive">{t('schedules.refresh_failed')}</p>}
      {boxes.error && <p role="alert" data-testid="schedules-boxes-error" className="text-sm text-destructive">{t('schedules.boxes_failed')}</p>}
      {data && !data.run_system_connected && (
        <Alert>
          <AlertDescription>{t('schedules.no_run_system')}</AlertDescription>
        </Alert>
      )}
      {data && data.lease && !data.lease.holder_is_me && (
        <Alert>
          <AlertDescription>{t('schedules.lease_other')}</AlertDescription>
        </Alert>
      )}
      {data && data.schedules.length === 0 && (
        <EmptyState
          title={t('schedules.none')}
          action={
            <Button className={TAP_ACTION} disabled={!can('start_runs')} onClick={() => setEditing('new')}>
              {t('schedules.add')}
            </Button>
          }
        >
          {t('schedules.none_body')}
        </EmptyState>
      )}
      <div className="space-y-3">
        {data?.schedules.map((s) => (
          <ScheduleCard key={s.id} s={s} mayStart={can('start_runs')} onEdit={() => setEditing(s)} onHistory={() => setHistory(s)} onRemove={() => setRemoving(s)} reload={list.reload} />
        ))}
      </div>
      {editing && data ? <ScheduleSheet item={editing === 'new' ? null : editing} zone={data.time_zone} boxes={names} source={data.source} onClose={() => setEditing(null)} onSaved={list.reload} /> : null}
      {history ? <HistorySheet item={history} onClose={() => setHistory(null)} /> : null}
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('schedules.remove_title')}
        description={t('schedules.remove_body', { name: removing?.name ?? '' })}
        confirmLabel={t('schedules.remove')}
        destructive
        onConfirm={async () => {
          if (!removing) return;
          try {
            await client.sched.remove(removing.id);
          } catch (x) {
            toast.error(errorText(x));
            throw x;
          }
          toast.success(t('schedules.removed'));
          setRemoving(null);
          list.reload();
        }}
      />
    </AppPage>
  );
}
