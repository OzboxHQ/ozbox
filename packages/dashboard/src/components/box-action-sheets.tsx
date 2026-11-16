import { useEffect, useRef, type ReactNode } from 'react';
import { fleetNotConnected } from '../lib/fleet';
import { FleetNotConnectedSheet } from './fleet-notice';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { z } from 'zod';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useState } from 'react';
import type { ApiClient } from '../api/client';
import type { BoxRecord, Info, Operation } from '../api/types';
import { sizeLabel } from '../lib/format';
import { isMachineMissing } from '../lib/format';
import { canConfirm, IMAGE_UNVERIFIED_CODE, ops, riskLabel, SECRETS_KEY_HELD_CODE, SECRETS_STORE_LOST_CODE, type FlowState } from '../lib/plan-flow';
import { usePlanFlow } from '../lib/use-plan-flow';
import { t, type MessageKey } from '../lib/i18n';
import { UpgradeFollowUp, UpgradeForm, UpgradeProgress } from './upgrade-sheet';

export type ActionKind = 'pause' | 'resume' | 'snapshot' | 'resize' | 'upgrade' | 'destroy';

const BACKUP_VERBS: Partial<Record<Operation['op'], MessageKey>> = {
  delete_snapshot: 'plan.verb_delete_snapshot',
  restore_work: 'plan.verb_restore_work',
  restic_backup: 'plan.verb_restic_backup',
  restic_forget: 'plan.verb_restic_forget',
  restic_restore: 'plan.verb_restic_restore',
  restore_to_new_box: 'plan.verb_restore_to_new_box',
  delete_old_work: 'plan.verb_delete_old_work',
};

function opTitle(op: Operation | null): string {
  if (!op) return t('plan.change');
  const name = op.op === 'clone' || op.op === 'restore_to_new_box' ? op.to : op.op === 'create' ? op.spec.name : op.name;
  const verb = BACKUP_VERBS[op.op];
  return t('plan.op_title', { verb: verb ? t(verb) : `${op.op.charAt(0).toUpperCase()}${op.op.slice(1)}`, name });
}

/** The plan review: every change with its risk, Apply in the footer. A change that cannot be undone needs the name typed. */
export function PlanSheet({ state, dispatch, onClose, busyExtra, doneExtra }: { state: FlowState; dispatch: (a: import('../lib/plan-flow').FlowAction) => void; onClose: () => void; busyExtra?: ReactNode; doneExtra?: ReactNode }) {
  const open = state.phase !== 'idle';
  const op = 'operation' in state ? state.operation : state.phase === 'done' ? state.plan.plan.operation : null;
  const reviewing = state.phase === 'review' || state.phase === 'applying';
  const busy = state.phase === 'applying';
  const high = reviewing && state.plan.requires_confirm_name && !state.plan.noop;
  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <PanelSheetContent size="compact" onEscapeKeyDown={(e) => busy && e.preventDefault()} onInteractOutside={(e) => busy && e.preventDefault()} data-testid="plan-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (canConfirm(state)) dispatch({ type: 'confirm' });
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{state.phase === 'done' ? t('plan.done') : state.phase === 'error' ? t('plan.error') : opTitle(op)}</PanelSheetTitle>
            <PanelSheetDescription>{reviewing ? t('plan.review_desc') : state.phase === 'planning' ? t('plan.planning_desc') : ' '}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-3">
            {state.phase === 'planning' && (
              <div role="status" aria-label={t('plan.preparing')} className="space-y-2">
                <Skeleton className="h-5 w-3/4" />
                <Skeleton className="h-5 w-1/2" />
              </div>
            )}
            {reviewing && (
              <>
                {state.plan.noop ? (
                  <p className="text-sm">{t('plan.noop', { name: state.plan.box_name })}</p>
                ) : (
                  <>
                    <p className="text-sm">
                      {t('plan.on_before')}<strong>{state.plan.plan.provider}</strong>{t('plan.on_after')}
                    </p>
                    <ol className="space-y-2 text-sm" aria-label={t('plan.changes')}>
                      {state.plan.plan.changes.map((c, i) => (
                        <li key={`${c.kind}-${i}`} className="flex flex-col gap-1 rounded-md border p-3 sm:flex-row sm:items-start sm:gap-3">
                          <Badge variant={c.risk === 'high' ? 'destructive' : c.risk === 'medium' ? 'secondary' : 'outline'} className="w-fit shrink-0">
                            {riskLabel(c.risk)}
                          </Badge>
                          <span className="min-w-0">{c.description}</span>
                        </li>
                      ))}
                    </ol>
                  </>
                )}
                {state.plan.plan.notes.map((n) => (
                  <p key={n} className="text-sm text-muted-foreground">
                    {t('plan.note', { note: n })}
                  </p>
                ))}
                {busy && <p role="status" className="text-sm">{t('plan.applying_keep_open')}</p>}
                {busy && busyExtra}
              </>
            )}
            {state.phase === 'done' && (
              <p role="status" className="text-sm">
                {state.response.applied
                  ? state.response.result
                    ? t('plan.now', { name: state.plan.box_name, state: state.response.result.state })
                    : t('plan.destroyed', { name: state.plan.box_name })
                  : t('plan.unchanged', { name: state.plan.box_name })}
              </p>
            )}
            {state.phase === 'done' && doneExtra}
            {state.phase === 'error' && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{state.message}</AlertDescription>
              </Alert>
            )}
          </PanelSheetBody>
          <PanelSheetFooter>
            {high && reviewing && (
              <div className="w-full space-y-1 sm:order-first sm:flex-1">
                <Label htmlFor="confirm-name">{t('plan.confirm_name', { name: state.plan.box_name })}</Label>
                <Input id="confirm-name" autoComplete="off" autoCapitalize="none" spellCheck={false} className="max-lg:h-11" value={state.typed} disabled={busy} onChange={(e) => dispatch({ type: 'typed', text: e.target.value })} />
              </div>
            )}
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {state.phase === 'done' || state.phase === 'error' ? t('common.close') : t('common.cancel')}
            </Button>
            {reviewing && !state.plan.noop && (
              <Button type="submit" variant={state.plan.max_risk === 'high' ? 'destructive' : 'default'} disabled={busy || !canConfirm(state)}>
                {busy ? t('plan.applying') : state.plan.max_risk === 'high' ? t('plan.apply_irreversible') : t('plan.apply')}
              </Button>
            )}
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

const resizeSchema = () =>
  z.object({
    size: z.string().min(1, t('resize.choose_size')),
    disk: z.string().refine((v) => v === '' || (/^\d+$/.test(v) && Number(v) >= 20), t('resize.disk_invalid')),
  });
type ResizeValues = z.infer<ReturnType<typeof resizeSchema>>;

function ResizeForm({ box, info, onSubmit, onClose }: { box: BoxRecord; info: Info | null; onSubmit: (op: Operation) => void; onClose: () => void }) {
  const current = sizeLabel(box.spec.size);
  const form = useForm<ResizeValues>({ resolver: zodResolver(resizeSchema()), defaultValues: { size: current, disk: '' } });
  const submit = form.handleSubmit((v) => {
    const chosen = info?.sizes.find((s) => s.id === v.size);
    const size = chosen && chosen.id !== current ? chosen.size : null;
    const disk = v.disk === '' ? null : Number(v.disk);
    if (size === null && disk === null) {
      form.setError('size', { message: t('resize.choose_different') });
      return;
    }
    if (disk !== null && disk < box.spec.work_disk_gb) {
      form.setError('disk', { message: t('resize.no_shrink', { gb: box.spec.work_disk_gb }) });
      return;
    }
    onSubmit({ op: 'resize', name: box.spec.name, size, work_disk_gb: disk });
  });
  const errors = form.formState.errors;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="resize-sheet">
        <form onSubmit={submit} className="flex min-h-0 flex-1 flex-col" noValidate>
          <PanelSheetHeader>
            <PanelSheetTitle>{t('resize.title', { name: box.spec.name })}</PanelSheetTitle>
            <PanelSheetDescription>{t('resize.description', { size: current, gb: box.spec.work_disk_gb })}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="resize-size">{t('resize.new_size')}</Label>
              <Select value={form.watch('size')} onValueChange={(v) => form.setValue('size', v, { shouldValidate: true })}>
                <SelectTrigger id="resize-size" aria-invalid={!!errors.size}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(info?.sizes ?? []).map((s) => (
                    <SelectItem key={s.id} value={s.id}>{t('settings.size_option', { id: s.id, vcpus: s.vcpus, memory: s.memory_gb })}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {errors.size && <p role="alert" className="text-sm text-destructive">{errors.size.message}</p>}
            </div>
            <div className="space-y-1">
              <Label htmlFor="resize-disk">{t('resize.grow_disk')}</Label>
              <Input id="resize-disk" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.disk} {...form.register('disk')} />
              {errors.disk && <p role="alert" className="text-sm text-destructive">{errors.disk.message}</p>}
            </div>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit">{t('resize.review')}</Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function DestroyForm({ box, onSubmit, onClose }: { box: BoxRecord; onSubmit: (op: Operation) => void; onClose: () => void }) {
  const [keep, setKeep] = useState(true);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="destroy-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit(ops.destroy(box.spec.name, keep));
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('destroy.title', { name: box.spec.name })}</PanelSheetTitle>
            <PanelSheetDescription>{isMachineMissing(box.state) ? t('destroy.description_missing') : t('destroy.description')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody>
            <div className="flex min-h-11 items-center gap-3">
              <Checkbox id="keep-snapshot" checked={keep} onCheckedChange={(c) => setKeep(c === true)} className="h-5 w-5" />
              <Label htmlFor="keep-snapshot">{t('destroy.keep_snapshot')}</Label>
            </div>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" variant="destructive">{t('resize.review')}</Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

/**
 * Everything one action needs: an options sheet where there is something to choose (resize, destroy), then the plan
 * review. Mounted when a person picks an action; `onClose` unmounts it.
 */
type SheetsProps = { box: BoxRecord; kind: ActionKind; client: ApiClient; info: Info | null; onClose: () => void; onApplied: () => void };

/** On a box's own dashboard no action reaches a plan: the person is told the fleet is not connected instead. */
export function BoxActionSheets(props: SheetsProps) {
  if (fleetNotConnected(props.info)) return <FleetNotConnectedSheet open onClose={props.onClose} info={props.info} />;
  return <BoxActionSheetsInner {...props} />;
}

function BoxActionSheetsInner({ box, kind, client, info, onClose, onApplied }: SheetsProps) {
  const flow = usePlanFlow(client, () => {
    onApplied();
  });
  const started = useRef(false);
  const name = box.spec.name;
  useEffect(() => {
    if (started.current) return;
    if (kind === 'pause' || kind === 'resume' || kind === 'snapshot') {
      started.current = true;
      flow.begin(ops[kind](name));
    }
  }, [kind, name, flow]);

  // A finished change is announced once, then the sheet stays for the person to read and close.
  const doneAnnounced = useRef(false);
  useEffect(() => {
    if (flow.state.phase === 'done' && !doneAnnounced.current) {
      doneAnnounced.current = true;
      if (flow.state.response.applied) toast.success(kind === 'upgrade' ? t('upgrade.toast', { name }) : t('plan.applied_toast', { name, kind }));
    }
  }, [flow.state, name, kind]);

  const close = () => {
    const destroyed = flow.state.phase === 'done' && flow.state.response.applied && flow.state.response.result === null;
    flow.dispatch({ type: 'cancel' });
    onClose();
    if (destroyed) window.dispatchEvent(new CustomEvent('ozbox:box-destroyed', { detail: name }));
  };

  // An image whose release signature could not be verified is refused while planning: the options sheet comes back
  // with the reason and the override, which is off until the person turns it on.
  const refused = flow.state.phase === 'error' && kind === 'upgrade' && flow.state.code === IMAGE_UNVERIFIED_CODE ? flow.state : null;
  if (refused) {
    const asked = refused.operation?.op === 'upgrade' && refused.operation.image !== 'latest' ? refused.operation.image : '';
    return <UpgradeForm key="refused" box={box} client={client} onClose={() => { flow.dispatch({ type: 'cancel' }); onClose(); }} refusal={refused.detail === undefined ? t('upgrade.refused_no_reason', { image: asked || 'latest' }) : t('upgrade.refused_reason', { image: asked || 'latest', detail: refused.detail })} initialImage={asked} onSubmit={(op, allow, accept) => flow.begin(op, allow, accept)} />;
  }
  // The box's secrets store would not survive the upgrade (or the box could not be asked): the sheet comes back with what is
  // lost and the acceptance, which is off until the person turns it on.
  const storeLost = flow.state.phase === 'error' && kind === 'upgrade' && (flow.state.code === SECRETS_STORE_LOST_CODE || flow.state.code === SECRETS_KEY_HELD_CODE) ? flow.state : null;
  if (storeLost) {
    const asked = storeLost.operation?.op === 'upgrade' && storeLost.operation.image !== 'latest' ? storeLost.operation.image : '';
    return <UpgradeForm key="store-lost" box={box} client={client} onClose={() => { flow.dispatch({ type: 'cancel' }); onClose(); }} storeRefusal={storeLost.message} initialImage={asked} onSubmit={(op, allow, accept) => flow.begin(op, allow, accept)} />;
  }
  if (flow.state.phase === 'idle' && (kind === 'resize' || kind === 'destroy' || kind === 'upgrade')) {
    if (kind === 'upgrade') return <UpgradeForm box={box} client={client} onClose={onClose} onSubmit={(op, allow, accept) => flow.begin(op, allow, accept)} />;
    return kind === 'resize' ? (
      <ResizeForm box={box} info={info} onClose={onClose} onSubmit={(op) => flow.begin(op)} />
    ) : (
      <DestroyForm box={box} onClose={onClose} onSubmit={(op) => flow.begin(op)} />
    );
  }
  const response = flow.state.phase === 'done' ? flow.state.response : null;
  return (
    <PlanSheet
      state={flow.state}
      dispatch={flow.dispatch}
      onClose={close}
      busyExtra={kind === 'upgrade' ? <UpgradeProgress /> : undefined}
      doneExtra={kind === 'upgrade' && response?.applied ? <UpgradeFollowUp client={client} name={name} response={response} /> : undefined}
    />
  );
}
