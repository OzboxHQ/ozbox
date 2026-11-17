import { zodResolver } from '@hookform/resolvers/zod';
import { useMemo, useState } from 'react';
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
import { ApiError } from '../api/client';
import type { Delivery, Scheme, TriggerItem } from '../api/sched';
import { useApp } from '../App';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { Fact, FieldError, StatusBadge } from '../components/sched-bits';
import { CannotNote } from '../components/role-scope';
import { SourceNote } from '../components/source-badge';
import { fmtBytes } from '../lib/format';
import { t, type MessageKey } from '../lib/i18n';
import { copyAndSay } from '../lib/copy-and-say';
import { boxChoiceLabel, boxChoices, defaultEngine, deliveryOutcome, deliveryWhy, emptyTriggerForm, engineChoices, triggerFormToInput, triggerSchema, type TriggerForm } from '../lib/sched';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const fieldMsg = (m?: string): string | undefined => (m ? t(`triggers.${m}` as MessageKey) : undefined);
const errorText = (e: unknown): string => (e instanceof ApiError ? e.message : t('common.save_failed'));
const SCHEME: Record<Scheme, MessageKey> = { github: 'triggers.scheme_github', generic: 'triggers.scheme_generic', stripe: 'triggers.scheme_stripe' };

function TriggerSheet({ boxes, source, onClose, onCreated }: { boxes: string[]; source: 'simulated' | 'live'; onClose: () => void; onCreated: (tr: TriggerItem) => void }) {
  const { client } = useApp();
  const [err, setErr] = useState<string | null>(null);
  const form = useForm<TriggerForm>({ resolver: zodResolver(triggerSchema), defaultValues: emptyTriggerForm(defaultEngine(source)) });
  const e = form.formState.errors;
  const v = form.watch();
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="wide" data-testid="trigger-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          noValidate
          onSubmit={form.handleSubmit(async (f) => {
            setErr(null);
            try {
              onCreated(await client.sched.createTrigger(triggerFormToInput(f)));
            } catch (x) {
              setErr(errorText(x));
            }
          })}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('triggers.form_new')}</PanelSheetTitle>
            <PanelSheetDescription>{t('triggers.form_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {err ? (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{err}</AlertDescription>
              </Alert>
            ) : null}
            <div className="space-y-1">
              <Label htmlFor="tr-name">{t('triggers.f_name')}</Label>
              <Input id="tr-name" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.name} {...form.register('name')} />
              <FieldError msg={fieldMsg(e.name?.message)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="tr-scheme">{t('triggers.f_scheme')}</Label>
              <Select value={v.scheme} onValueChange={(x) => form.setValue('scheme', x as Scheme)}>
                <SelectTrigger id="tr-scheme" className="max-lg:h-11">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(SCHEME) as Scheme[]).map((s) => (
                    <SelectItem key={s} value={s}>
                      {t(SCHEME[s])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="tr-box">{t('triggers.f_box')}</Label>
              <Select value={v.box} onValueChange={(x) => form.setValue('box', x, { shouldValidate: true })}>
                <SelectTrigger id="tr-box" className="max-lg:h-11" aria-invalid={!!e.box}>
                  <SelectValue placeholder={t('triggers.f_box_pick')} />
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
            <div className="space-y-1">
              <Label htmlFor="tr-engine">{t('triggers.f_engine')}</Label>
              <Select value={v.engine} onValueChange={(x) => form.setValue('engine', x, { shouldValidate: true })}>
                <SelectTrigger id="tr-engine" className="max-lg:h-11">
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
            </div>
            <div className="space-y-1">
              <Label htmlFor="tr-template">{t('triggers.f_template')}</Label>
              <Textarea id="tr-template" aria-describedby="tr-template-hint" aria-invalid={!!e.template} {...form.register('template')} />
              <p id="tr-template-hint" className="text-xs text-muted-foreground">
                {t('triggers.f_template_hint')}
              </p>
              <FieldError msg={fieldMsg(e.template?.message)} />
            </div>
            {v.scheme === 'github' ? (
              <div className="space-y-1">
                <Label htmlFor="tr-events">{t('triggers.f_events')}</Label>
                <Input id="tr-events" autoComplete="off" spellCheck={false} className="max-lg:h-11" {...form.register('events')} />
              </div>
            ) : null}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="tr-spend">{t('triggers.f_max_spend')}</Label>
                <Input id="tr-spend" inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.maxSpend} {...form.register('maxSpend')} />
                <FieldError msg={fieldMsg(e.maxSpend?.message)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="tr-minutes">{t('triggers.f_max_minutes')}</Label>
                <Input id="tr-minutes" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.maxMinutes} {...form.register('maxMinutes')} />
                <FieldError msg={fieldMsg(e.maxMinutes?.message)} />
              </div>
            </div>
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

/** The one time the secret is on screen. Closing it removes it from the page's memory. */
function SecretSheet({ trigger, onClose }: { trigger: TriggerItem; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="secret-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{trigger.previous_secret_until_ms ? t('triggers.rotated_title') : t('triggers.created_title')}</PanelSheetTitle>
          <PanelSheetDescription>
            {trigger.previous_secret_until_ms ? t('triggers.rotated_body', { until: new Date(trigger.previous_secret_until_ms).toLocaleString() }) : t('triggers.created_body')}
          </PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="tr-secret">{t('triggers.secret')}</Label>
            <Input id="tr-secret" readOnly value={trigger.secret ?? ''} spellCheck={false} className="max-lg:h-11 font-mono" onFocus={(ev) => ev.currentTarget.select()} />
          </div>
          <Button
            variant="outline"
            className={TAP_ACTION}
            onClick={() => {
              void copyAndSay(trigger.secret ?? '', { kind: 'secret', done: t('triggers.copied'), failed: t('triggers.copy_failed') }).then(setCopied);
            }}
          >
            {copied ? t('triggers.copied') : t('triggers.copy')}
          </Button>
          <dl>
            <Fact label={t('triggers.address')}>{trigger.url ?? t('triggers.address_path', { path: trigger.path })}</Fact>
          </dl>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button className={TAP_ACTION} onClick={onClose}>
            {t('triggers.done')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function DeliveriesSheet({ trigger, onClose }: { trigger: TriggerItem; onClose: () => void }) {
  const { client } = useApp();
  const rows = useAsync<Delivery[]>((s) => client.sched.deliveries(trigger.id, s), [client, trigger.id], 5000);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="wide" data-testid="deliveries-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('triggers.deliveries')}</PanelSheetTitle>
          <PanelSheetDescription>{trigger.name}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-2">
          {!rows.data && !rows.error && <Skeleton className="h-24 w-full" />}
          {rows.error && <p role="alert" className="text-sm text-destructive">{rows.error.message}</p>}
          {rows.data && rows.data.length === 0 && <p className="text-sm text-muted-foreground">{t('triggers.deliveries_none')}</p>}
          {rows.data?.map((d) => (
            <Card key={d.id} className="space-y-1 p-3" data-testid="delivery-row">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge ok={d.outcome === 'refused' ? 'bad' : d.outcome === 'accepted' ? 'good' : 'neutral'}>{deliveryOutcome(d)}</StatusBadge>
                <time className="text-xs" dateTime={new Date(d.ts_ms).toISOString()}>
                  {new Date(d.ts_ms).toLocaleString()}
                </time>
                <span className="text-xs text-muted-foreground">{fmtBytes(d.size)}</span>
                {d.event ? <span className="text-xs text-muted-foreground">{d.event}</span> : null}
              </div>
              <p className="text-sm">{deliveryWhy(d)}</p>
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

export function TriggersPage() {
  const { client } = useApp();
  const { can } = useCan();
  const list = useAsync((s) => client.sched.triggers(s), [client], 5000);
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const names = useMemo(() => boxChoices(boxes.data ?? []), [boxes.data]);
  const [adding, setAdding] = useState(false);
  const [created, setCreated] = useState<TriggerItem | null>(null);
  const [viewing, setViewing] = useState<TriggerItem | null>(null);
  const [removing, setRemoving] = useState<TriggerItem | null>(null);
  const [rotating, setRotating] = useState<TriggerItem | null>(null);
  const data = list.data;

  const act = async (fn: () => Promise<unknown>, ok?: MessageKey) => {
    try {
      await fn();
      if (ok) toast.success(t(ok));
      list.reload();
    } catch (x) {
      toast.error(errorText(x));
    }
  };

  return (
    <AppPage>
      <PageHeader
        title={t('triggers.title')}
        description={t('triggers.desc')}
        actions={
          <Button className={TAP_ACTION} onClick={() => setAdding(true)} disabled={!data || !can('start_runs')}>
            {t('triggers.add')}
          </Button>
        }
      />
      <SourceNote source={data?.source} what="triggers" />
      {!can('start_runs') ? <CannotNote cap="start_runs" /> : null}
      {!data && !list.error && <Skeleton className="h-40 w-full" />}
      {list.error && !data && <p role="alert" data-testid="triggers-error" className="text-sm text-destructive">{list.error.message}</p>}
      {list.error && data && <p role="alert" data-testid="triggers-stale" className="text-sm text-destructive">{t('triggers.refresh_failed')}</p>}
      {boxes.error && <p role="alert" data-testid="triggers-boxes-error" className="text-sm text-destructive">{t('triggers.boxes_failed')}</p>}
      {data && !data.public_url_set && (
        <Alert>
          <AlertDescription>{t('triggers.no_public')}</AlertDescription>
        </Alert>
      )}
      {data && data.triggers.length === 0 && (
        <EmptyState
          title={t('triggers.none')}
          action={
            <Button className={TAP_ACTION} disabled={!can('start_runs')} onClick={() => setAdding(true)}>
              {t('triggers.add')}
            </Button>
          }
        >
          {t('triggers.none_body')}
        </EmptyState>
      )}
      <div className="space-y-3">
        {data?.triggers.map((tr) => (
          <Card key={tr.id} className="space-y-3 p-4" data-testid="trigger-card" data-trigger={tr.name}>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold">{tr.name}</h2>
              <Badge variant={tr.enabled ? 'default' : 'secondary'}>{tr.enabled ? t('triggers.on') : t('triggers.off')}</Badge>
            </div>
            <dl className="grid gap-3 sm:grid-cols-3">
              <Fact label={t('triggers.address')}>
                <code className="break-all text-xs">{tr.url ?? tr.path}</code>
              </Fact>
              <Fact label={t('triggers.col_scheme')}>{t(SCHEME[tr.scheme])}</Fact>
              <Fact label={t('triggers.col_last')}>
                {tr.last_delivery ? `${deliveryOutcome(tr.last_delivery)} · ${new Date(tr.last_delivery.ts_ms).toLocaleString()}` : t('triggers.never')}
              </Fact>
            </dl>
            <div className="flex flex-wrap gap-2" role="group" aria-label={t('triggers.actions_for', { name: tr.name })}>
              <Button
                variant="outline"
                className={TAP_ACTION}
                disabled={!can('start_runs')}
                onClick={() =>
                  void act(async () => {
                    const r = await client.sched.testTrigger(tr.id);
                    toast.success(r.verified ? t('triggers.test_ok') : t('triggers.test_failed'));
                  })
                }
              >
                {t('triggers.test')}
              </Button>
              <Button variant="outline" className={TAP_ACTION} onClick={() => setViewing(tr)}>
                {t('triggers.deliveries')}
              </Button>
              <Button variant="outline" className={TAP_ACTION} disabled={!can('start_runs')} onClick={() => void act(() => client.sched.setTriggerEnabled(tr.id, !tr.enabled))}>
                {tr.enabled ? t('triggers.disable') : t('triggers.enable')}
              </Button>
              <Button variant="outline" className={TAP_ACTION} disabled={!can('start_runs')} onClick={() => setRotating(tr)}>
                {t('triggers.rotate')}
              </Button>
              <Button variant="outline" className={TAP_ACTION} disabled={!can('start_runs')} onClick={() => setRemoving(tr)}>
                {t('triggers.remove')}
              </Button>
            </div>
          </Card>
        ))}
      </div>
      {adding && data ? (
        <TriggerSheet
          boxes={names}
          source={data.source}
          onClose={() => setAdding(false)}
          onCreated={(tr) => {
            setAdding(false);
            setCreated(tr);
            list.reload();
          }}
        />
      ) : null}
      {created ? <SecretSheet trigger={created} onClose={() => setCreated(null)} /> : null}
      <ConfirmDialog
        open={!!rotating}
        onOpenChange={(o) => !o && setRotating(null)}
        title={t('triggers.rotate_title')}
        description={t('triggers.rotate_body', { name: rotating?.name ?? '' })}
        confirmLabel={t('triggers.rotate_confirm')}
        onConfirm={async () => {
          if (!rotating) return;
          try {
            const fresh = await client.sched.rotateTriggerSecret(rotating.id);
            setRotating(null);
            setCreated(fresh);
            list.reload();
          } catch (x) {
            toast.error(errorText(x));
            throw x;
          }
        }}
      />
      {viewing ? <DeliveriesSheet trigger={viewing} onClose={() => setViewing(null)} /> : null}
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('triggers.remove_title')}
        description={t('triggers.remove_body', { name: removing?.name ?? '' })}
        confirmLabel={t('triggers.remove')}
        destructive
        onConfirm={async () => {
          if (!removing) return;
          try {
            await client.sched.removeTrigger(removing.id);
          } catch (x) {
            toast.error(errorText(x));
            throw x;
          }
          toast.success(t('triggers.removed'));
          setRemoving(null);
          list.reload();
        }}
      />
    </AppPage>
  );
}
