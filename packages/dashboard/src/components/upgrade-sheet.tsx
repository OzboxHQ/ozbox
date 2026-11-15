import { useEffect, useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { Spinner } from '@/components/ui/spinner';
import type { ApiClient } from '../api/client';
import type { ApplyResponse, BoxImage, BoxRecord, Operation, SelfTest } from '../api/types';
import { checkText, failingSteps, overall } from '../lib/health';
import { isMachineMissing } from '../lib/format';
import { t } from '../lib/i18n';
import { ops } from '../lib/plan-flow';
import { followUpgrade, type FollowResult } from '../lib/upgrade-follow';

const schema = z.object({
  image: z.string().refine((v) => !/\s/.test(v.trim()), t('upgrade.image_invalid')),
});
type Values = z.infer<typeof schema>;

function imageText(id: string | null, release: string | null): string {
  if (!id) return t('upgrade.unknown');
  return release ? `${id} (${t('upgrade.release', { release })})` : id;
}

/** The options step: which image the box runs and which is newest, then a plan to review. Nothing changes here. */
export function UpgradeForm({
  box,
  client,
  onSubmit,
  onClose,
  refusal = null,
  storeRefusal = null,
  initialImage = '',
}: {
  box: BoxRecord;
  client: ApiClient;
  onSubmit: (op: Operation, allowUnverified: boolean, acceptNewStore: boolean) => void;
  onClose: () => void;
  /** The server's reason for refusing an image whose signature could not be verified; shows the override. */
  refusal?: string | null;
  /** The server's words for an upgrade that would start a new secrets store (or a box it could not ask); shows the acceptance. */
  storeRefusal?: string | null;
  initialImage?: string;
}) {
  const name = box.spec.name;
  const finishing = isMachineMissing(box.state);
  const [allow, setAllow] = useState(false);
  const [accept, setAccept] = useState(false);
  const [info, setInfo] = useState<BoxImage | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  useEffect(() => {
    const ctl = new AbortController();
    client
      .boxImage(name, ctl.signal)
      .then(setInfo)
      .catch((e: unknown) => {
        if (!ctl.signal.aborted) setFailed(e instanceof Error ? e.message : t('common.request_failed'));
      });
    return () => ctl.abort();
  }, [client, name]);

  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { image: initialImage } });
  // A box with no machine is finished on the image its upgrade was marked with, unless another is typed.
  const marked = finishing ? (info?.unfinished_upgrade_to ?? null) : null;
  const submit = form.handleSubmit((v) =>
    onSubmit(ops.upgrade(name, v.image.trim() === '' ? (marked ?? 'latest') : v.image.trim()), refusal !== null && allow, storeRefusal !== null && accept),
  );
  const errors = form.formState.errors;
  const latest = info?.latest ?? null;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="upgrade-sheet">
        <form onSubmit={submit} className="flex min-h-0 flex-1 flex-col" noValidate>
          <PanelSheetHeader>
            <PanelSheetTitle>{finishing ? t('upgrade.finish_title', { name }) : t('upgrade.title', { name })}</PanelSheetTitle>
            <PanelSheetDescription>{finishing ? t('upgrade.finish_intro') : t('upgrade.intro')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {!info && !failed && (
              <div role="status" aria-label={t('upgrade.loading')} className="space-y-2">
                <Skeleton className="h-5 w-3/4" />
                <Skeleton className="h-5 w-1/2" />
              </div>
            )}
            {failed && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{failed}</AlertDescription>
              </Alert>
            )}
            {info && (
              <dl className="space-y-3 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('upgrade.now')}</dt>
                  <dd className="break-all font-mono text-xs" data-testid="image-current">
                    {info.current ?? t('upgrade.unknown')}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('upgrade.newest')}</dt>
                  <dd className="break-all font-mono text-xs" data-testid="image-latest">
                    {latest ? imageText(latest.id, latest.release) : t('upgrade.unknown')}
                  </dd>
                </div>
              </dl>
            )}
            {info && info.upgrade_available === false && <p className="text-sm">{t('upgrade.same')}</p>}
            {info && info.upgrade_available === true && <p className="text-sm">{t('upgrade.available')}</p>}
            {info?.latest_error && <p className="text-sm text-muted-foreground">{t('upgrade.no_latest', { reason: info.latest_error })}</p>}
            {latest && latest.signature_applicable !== false && (
              <p className="text-sm" data-testid="image-signature">
                {t(latest.signature_verified ? 'upgrade.signature_verified' : 'upgrade.signature_not_verified', { detail: latest.signature_detail || t('upgrade.signature_no_detail') })}
              </p>
            )}
            {info?.unfinished_upgrade_to && <p className="text-sm">{t('upgrade.unfinished', { image: info.unfinished_upgrade_to })}</p>}
            <div className="space-y-1">
              <Label htmlFor="upgrade-image">{t('upgrade.image_label')}</Label>
              <Input id="upgrade-image" autoComplete="off" autoCapitalize="none" spellCheck={false} className="max-lg:h-11" aria-invalid={!!errors.image} aria-describedby="upgrade-image-hint" {...form.register('image')} />
              <p id="upgrade-image-hint" className="text-xs text-muted-foreground">
                {marked ? t('upgrade.finish_image_hint', { image: marked }) : t('upgrade.image_hint')}
              </p>
              {errors.image && (
                <p role="alert" className="text-sm text-destructive">
                  {errors.image.message}
                </p>
              )}
            </div>
            {refusal !== null && (
              <div className="space-y-3" data-testid="image-refused">
                <Alert variant="destructive" role="alert">
                  <AlertDescription>
                    <strong>{t('upgrade.refused_title')}.</strong> {refusal}
                  </AlertDescription>
                </Alert>
                <div className="flex min-h-11 items-center gap-3">
                  <Checkbox id="allow-unverified" checked={allow} onCheckedChange={(c) => setAllow(c === true)} className="h-5 w-5 max-lg:h-11 max-lg:w-11 max-lg:rounded-md" aria-describedby="allow-unverified-hint" />
                  <Label htmlFor="allow-unverified">{t('upgrade.allow_unverified')}</Label>
                </div>
                <p id="allow-unverified-hint" className="text-xs text-muted-foreground">
                  {t('upgrade.allow_unverified_hint')}
                </p>
              </div>
            )}
            {storeRefusal !== null && (
              <div className="space-y-3" data-testid="store-refused">
                <Alert variant="destructive" role="alert">
                  <AlertDescription>
                    <strong>{t('upgrade.store_refused_title')}.</strong> {storeRefusal}
                  </AlertDescription>
                </Alert>
                <div className="flex min-h-11 items-center gap-3">
                  <Checkbox id="accept-new-store" checked={accept} onCheckedChange={(c) => setAccept(c === true)} className="h-5 w-5 max-lg:h-11 max-lg:w-11 max-lg:rounded-md" aria-describedby="accept-new-store-hint" />
                  <Label htmlFor="accept-new-store">{t('upgrade.accept_new_store')}</Label>
                </div>
                <p id="accept-new-store-hint" className="text-xs text-muted-foreground">
                  {t('upgrade.accept_new_store_hint')}
                </p>
              </div>
            )}
            <p className="text-sm text-muted-foreground">{t('upgrade.offline_note')}</p>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit">{t('upgrade.review')}</Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function useSeconds(): number {
  const [s, setS] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setS((v) => v + 1), 1000);
    return () => clearInterval(id);
  }, []);
  return s;
}

/** Shown while the provider's change runs: the server answers once, when it is finished, so this says how long it has been. */
export function UpgradeProgress() {
  const seconds = useSeconds();
  return (
    <div role="status" className="flex items-start gap-2 text-sm" data-testid="upgrade-progress">
      <Spinner className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{t('upgrade.progress_wait', { seconds })}</span>
    </div>
  );
}

const POLL_MS = 5_000;
const GIVE_UP_MS = 10 * 60_000;

function SelfTestChecks({ test }: { test: SelfTest }) {
  const o = overall(test);
  return (
    <div className="space-y-2">
      <p role="status" className="text-sm font-medium">
        {o === 'failed' ? t('upgrade.selftest_failed') : o === 'unverified' ? t('upgrade.selftest_partial') : t('upgrade.selftest_passed')}
      </p>
      {failingSteps(test).map((f) => (
        <p key={f.step} role="alert" className="rounded-md border border-destructive/40 p-3 text-sm">
          <strong>{t('health.failed_step', { step: f.step })}</strong> {f.reason}
        </p>
      ))}
      <ul className="divide-y text-sm" aria-label={t('health.checks')}>
        {test.checks.map((c) => (
          <li key={c.name} className="flex flex-col gap-1 py-2 sm:flex-row sm:items-start sm:justify-between">
            <span>{c.name}</span>
            <span className="sm:text-right">
              <Badge variant={c.outcome === 'fail' ? 'destructive' : c.outcome === 'unknown' ? 'secondary' : 'outline'}>{checkText(c)}</Badge>
              {c.outcome !== 'pass' && <span className="mt-1 block text-xs text-muted-foreground">{c.reason}</span>}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** After the change: what the checkpoint did, then wait for the box to answer and show its own self-test. */
export function UpgradeFollowUp({ client, name, response, intervalMs = POLL_MS, timeoutMs = GIVE_UP_MS }: { client: ApiClient; name: string; response: ApplyResponse; intervalMs?: number; timeoutMs?: number }) {
  const [waited, setWaited] = useState(0);
  const [result, setResult] = useState<FollowResult | null>(null);
  useEffect(() => {
    const ctl = new AbortController();
    void followUpgrade(() => client.selftest(name, ctl.signal).then((r) => r.result), {
      intervalMs,
      timeoutMs,
      signal: ctl.signal,
      onWait: (ms) => setWaited(Math.round(ms / 1000)),
    }).then((r) => {
      if (!ctl.signal.aborted) setResult(r);
    });
    return () => ctl.abort();
  }, [client, name, intervalMs, timeoutMs]);

  const checkpoint = response.upgrade?.checkpoint;
  return (
    <section aria-label={t('upgrade.after_title')} className="space-y-3 border-t pt-3" data-testid="upgrade-followup">
      <h3 className="text-sm font-semibold">{t('upgrade.after_title')}</h3>
      {checkpoint && (
        <p className="text-sm">
          <strong>{t('upgrade.step_checkpoint')}:</strong> {checkpoint.detail}
        </p>
      )}
      {!result && (
        <div role="status" className="flex items-start gap-2 text-sm">
          <Spinner className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{t('upgrade.waiting', { seconds: waited })}</span>
        </div>
      )}
      {result?.kind === 'result' && (
        <>
          <p className="text-sm">
            <strong>{t('upgrade.step_ready')}:</strong> {t('upgrade.answered')}
          </p>
          <SelfTestChecks test={result.test} />
        </>
      )}
      {result?.kind === 'timeout' && (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{t('upgrade.gave_up', { minutes: Math.round(timeoutMs / 60_000), reason: result.reason })}</AlertDescription>
        </Alert>
      )}
      {result?.kind === 'unsupported' && <p className="text-sm text-muted-foreground">{t('upgrade.cannot_wait', { reason: result.reason })}</p>}
    </section>
  );
}
