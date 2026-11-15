import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { ApiError } from '../api/client';
import type { BackupItem, BoxBackups } from '../api/backups';
import type { BoxRecord } from '../api/types';
import { useApp } from '../App';
import { SourceNote } from './source-badge';
import { AppLink, EmptyState } from './page';
import { PlanSheet } from './box-action-sheets';
import { canRestore, fmtIso, fmtWhen, itemKindText, itemLabels, itemSize, itemStatusText, restoreTargets, scheduleText, type RestoreTarget } from '../lib/backups';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { ops } from '../lib/plan-flow';
import { hrefs } from '../lib/router';
import { useAsync } from '../lib/use-async';
import { usePlanFlow } from '../lib/use-plan-flow';

const NAME = /^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$/;

/** Choose where a backup goes, then hand the choice to the plan review: nothing changes before the plan is applied. */
function RestoreSheet({ box, item, onClose, onPlan }: { box: string; item: BackupItem; onClose: () => void; onPlan: (op: ReturnType<typeof ops.restoreWork>) => void }) {
  const targets = restoreTargets(item);
  const [target, setTarget] = useState<RestoreTarget | null>(targets[0] ?? null);
  const [name, setName] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const short = item.id.length > 12 ? `${item.id.slice(0, 12)}…` : item.id;
  const choose = (v: RestoreTarget, label: string, hint: string) => (
    <label key={v} className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md border p-3 has-[:checked]:border-primary has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring" data-testid={`restore-${v}`}>
      {/* The whole row is the target; the radio itself is visually replaced by the dot beside it. */}
      <input type="radio" name="restore-target" className="peer sr-only" checked={target === v} onChange={() => setTarget(v)} />
      <span aria-hidden="true" className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-primary">
        <span className="hidden h-2.5 w-2.5 rounded-full bg-primary peer-checked:block" />
      </span>
      <span>
        <span className="block text-sm font-medium">{label}</span>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </label>
  );
  const submit = () => {
    if (target === 'new_box') {
      if (!NAME.test(name)) return setProblem(t('backups.err_name'));
      return onPlan(item.kind === 'snapshot' ? ops.cloneFrom(box, name, item.id) : ops.restoreToNewBox(box, name, item.id));
    }
    if (target === 'in_place') return onPlan(item.kind === 'snapshot' ? ops.restoreWork(box, item.id) : ops.resticRestore(box, item.id, true));
    if (target === 'folder') return onPlan(ops.resticRestore(box, item.id, false));
  };
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="restore-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('backups.restore_title', { id: short })}</PanelSheetTitle>
            <PanelSheetDescription>{t('backups.restore_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-3">
            <fieldset className="space-y-2">
              <legend className="sr-only">{t('backups.restore_title', { id: short })}</legend>
              {targets.includes('new_box') &&
                (item.kind === 'snapshot'
                  ? choose('new_box', t('backups.restore_new_box'), t('backups.restore_new_box_hint'))
                  : choose('new_box', t('backups.restore_new_box_repo'), t('backups.restore_new_box_repo_hint')))}
              {targets.includes('folder') && choose('folder', t('backups.restore_folder'), t('backups.restore_folder_hint'))}
              {targets.includes('in_place') && choose('in_place', t('backups.restore_in_place'), t('backups.restore_in_place_hint'))}
            </fieldset>
            {target === 'new_box' ? (
              <div className="space-y-1">
                <Label htmlFor="restore-name">{t('backups.restore_new_name')}</Label>
                <Input id="restore-name" autoComplete="off" className="max-lg:h-11" value={name} onChange={(e) => { setName(e.target.value); setProblem(null); }} aria-invalid={!!problem} />
                {problem ? (
                  <p role="alert" className="text-sm text-destructive">
                    {problem}
                  </p>
                ) : null}
              </div>
            ) : null}
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" className="max-lg:h-11" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" className="max-lg:h-11" disabled={target === null}>
              {t('backups.restore_review')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

/** A box's backups: what exists, when the next one runs, how the last one ended, and what can be done with each. */
export function BackupsTab({ box }: { box: BoxRecord }) {
  const { client } = useApp();
  const name = box.spec.name;
  const q = useAsync<BoxBackups>((s) => client.backups.box(name, s), [client, name], 8_000);
  const flow = usePlanFlow(client, () => q.reload());
  const [restoring, setRestoring] = useState<BackupItem | null>(null);
  const [sending, setSending] = useState(false);

  const data = q.data;
  const sendCredentials = async () => {
    setSending(true);
    try {
      await client.backups.pushCredentials(name);
      toast.success(t('backups.credentials_sent'));
      q.reload();
    } catch (e) {
      toast.error(t('backups.credentials_failed', { why: e instanceof ApiError ? e.message : '' }));
    } finally {
      setSending(false);
    }
  };

  if (q.error && !data) return <EmptyState title={t('health.unreadable')}>{q.error.message}</EmptyState>;
  if (!data) return <Skeleton className="h-40 w-full" />;
  const repoSet = data.restic.target_set;
  return (
    <div className="space-y-4" data-testid="backups-tab">
      <SourceNote source={data.source} what="backups" />
      <Card className="space-y-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <h2 className="text-sm font-semibold">{t('backups.tab_title', { name })}</h2>
          <div className="flex w-full flex-wrap gap-2 sm:w-auto">
            {repoSet ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button className="max-lg:h-11" data-testid="backup-now" disabled={data.running}>
                    {t('backups.now')}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem className="min-h-11 lg:min-h-0" onSelect={() => flow.begin(ops.snapshot(name))}>
                    {t('backups.now_snapshot')}
                  </DropdownMenuItem>
                  <DropdownMenuItem className="min-h-11 lg:min-h-0" onSelect={() => flow.begin(ops.resticBackup(name))}>
                    {t('backups.now_restic')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <Button className="max-lg:h-11" data-testid="backup-now" disabled={data.running} onClick={() => flow.begin(ops.snapshot(name))}>
                {t('backups.now')}
              </Button>
            )}
            <Button variant="outline" className="max-lg:h-11" onClick={() => q.reload()}>
              {t('backups.refresh')}
            </Button>
          </div>
        </div>
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <dt className="text-xs text-muted-foreground">{t('backups.next_run')}</dt>
            <dd className="text-sm font-medium" data-testid="backups-next">
              {data.schedule.kind === 'off' ? t('backups.next_none') : `${fmtWhen(data.next_run_ms, data.zone)} · ${scheduleText(data.schedule)}`}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">{t('backups.last_run')}</dt>
            <dd className="text-sm font-medium" data-testid="backups-last">
              {data.running ? (
                <Badge variant="secondary">{t('backups.running')}</Badge>
              ) : data.last ? (
                <span className={data.last.ok ? '' : 'text-destructive'}>
                  {data.last.ok ? t('backups.last_ok', { when: fmtRelative(new Date(data.last.ts_ms).toISOString()) }) : t('backups.last_failed', { when: fmtRelative(new Date(data.last.ts_ms).toISOString()), detail: data.last.detail })}
                </span>
              ) : (
                t('backups.none_yet')
              )}
            </dd>
          </div>
        </dl>
        {!data.provider.supported && data.provider.error ? <p className="text-xs text-muted-foreground">{t('backups.snapshot_unsupported', { why: data.provider.error })}</p> : null}
        {!repoSet ? (
          <p className="text-xs text-muted-foreground">
            {t('backups.repo_none')}{' '}
            <AppLink href={hrefs.settings('backups')} className="underline underline-offset-4">
              {t('backups.title')}
            </AppLink>
          </p>
        ) : null}
        {repoSet && data.state !== 'running' ? <p className="text-xs text-muted-foreground">{t('backups.not_running', { state: data.state })}</p> : null}
        {repoSet && data.restic.error && data.state === 'running' ? (
          <Alert variant="destructive" role="alert">
            <AlertDescription>{t('backups.repo_error', { why: data.restic.error })}</AlertDescription>
          </Alert>
        ) : null}
        {repoSet && data.state === 'running' && data.restic.configured_on_box === false ? (
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span>{t('backups.repo_not_here')}</span>
            <Button variant="outline" size="sm" className="max-lg:h-11" disabled={sending} onClick={() => void sendCredentials()} data-testid="send-credentials">
              {t('backups.send_credentials')}
            </Button>
          </div>
        ) : null}
      </Card>

      {data.new_box_restore ? (
        <Alert data-testid="new-box-restore">
          <AlertDescription>{t('backups.new_box_restore', { from: data.new_box_restore.from, detail: data.new_box_restore.detail })}</AlertDescription>
        </Alert>
      ) : null}

      {data.items.length === 0 ? (
        <EmptyState title={t('backups.empty')}>{t('backups.empty_body')}</EmptyState>
      ) : (
        <Card className="p-4" data-testid="backups-list">
          <h2 className="text-sm font-semibold">{t('backups.list')}</h2>
          <ul className="mt-2 divide-y text-sm" aria-label={t('backups.list')}>
            {data.items.map((i) => (
              <li key={`${i.kind}-${i.id}`} className="grid gap-2 py-3 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_6rem_minmax(0,1.4fr)_8rem_auto] lg:items-center" data-testid={`backup-${i.id}`}>
                <div className="min-w-0">
                  <p className="font-medium">{fmtIso(i.created_at, data.zone)}</p>
                  <p className="break-all font-mono text-xs text-muted-foreground">{i.id}</p>
                </div>
                <p>{itemKindText(i)}</p>
                <p className="tabular-nums">{itemSize(i)}</p>
                <p className="flex flex-wrap gap-1">
                  {itemLabels(i).map((l) => (
                    <Badge key={l} variant="outline">
                      {l}
                    </Badge>
                  ))}
                </p>
                <p>
                  <Badge variant={i.status === 'completed' ? 'outline' : i.status === 'pending' ? 'secondary' : 'destructive'}>{itemStatusText(i.status)}</Badge>
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!canRestore(i) || restoreTargets(i).length === 0} onClick={() => setRestoring(i)} aria-label={`${t('backups.restore')} ${i.id}`}>
                    {t('backups.restore')}
                  </Button>
                  <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => flow.begin(i.kind === 'snapshot' ? ops.deleteSnapshot(name, i.id) : ops.resticForget(name, i.id))} aria-label={`${t('backups.delete')} ${i.id}`}>
                    {t('backups.delete')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {data.old_disks && data.old_disks.length > 0 ? (
        <Card className="p-4" data-testid="old-disks">
          <h2 className="text-sm font-semibold">{t('backups.old_disks')}</h2>
          <p className="mt-1 text-xs text-muted-foreground">{t('backups.old_disks_body')}</p>
          <ul className="mt-2 divide-y text-sm" aria-label={t('backups.old_disks')}>
            {data.old_disks.map((d) => (
              <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 py-3" data-testid={`old-disk-${d.id}`}>
                <div className="min-w-0">
                  <p className="break-all font-mono text-xs">{d.id}</p>
                  <p className="text-xs text-muted-foreground">{d.state === 'pending' ? t('backups.old_disk_pending') : t('backups.old_disk_from', { from: d.restored_from ?? '-', size: d.size_gb === null ? '-' : `${d.size_gb} GB` })}</p>
                </div>
                <Button variant="outline" size="sm" className="max-lg:h-11" disabled={d.state === 'pending'} onClick={() => flow.begin(ops.deleteOldWork(name, d.id))} aria-label={`${t('backups.old_disk_delete')} ${d.id}`}>
                  {t('backups.old_disk_delete')}
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      {restoring ? (
        <RestoreSheet
          box={name}
          item={restoring}
          onClose={() => setRestoring(null)}
          onPlan={(op) => {
            setRestoring(null);
            flow.begin(op);
          }}
        />
      ) : null}
      <PlanSheet
        state={flow.state}
        dispatch={flow.dispatch}
        onClose={() => {
          flow.dispatch({ type: 'cancel' });
          q.reload();
        }}
      />
    </div>
  );
}
