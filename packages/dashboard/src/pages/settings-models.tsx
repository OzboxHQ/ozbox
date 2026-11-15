import { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { z } from 'zod';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/client';
import type { ModelJob, ModelKind, ModelListResult, ModelProvider, ModelTestResult, ModelsStatus, Settings } from '../api/types';
import { useApp } from '../App';
import { SecretField } from '../components/secret-field';
import { EnginesCard } from '../components/models/engines-card';
import { LocalAiCard } from '../components/models/local-ai-card';
import { PricesCard } from '../components/models/prices-card';
import { ModelList } from '../components/models/model-list';
import { UsageCard } from '../components/models/usage-card';
import { t } from '../lib/i18n';
import { fieldsFor, GUIDE_STEPS, KIND_LABEL, KINDS, MODEL_RE, REGION_RE, RESOURCE_RE } from '../lib/models';
import { useAsync } from '../lib/use-async';
import { useSettings } from '../lib/use-settings';

const JOBS: ModelJob[] = ['coding', 'chat', 'review'];
const JOB_LABEL: Record<ModelJob, 'models.job_coding' | 'models.job_chat' | 'models.job_review'> = { coding: 'models.job_coding', chat: 'models.job_chat', review: 'models.job_review' };
const NONE = '__none__';

const errorText = (e: unknown) => (e instanceof ApiError ? e.message : t('common.request_failed'));
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24);

function FieldError({ msg }: { msg?: string }) {
  return msg ? (
    <p role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

const providerSchema = z
  .object({
    kind: z.enum(KINDS as [ModelKind, ...ModelKind[]]),
    label: z.string().trim().min(1, t('models.label_required')).max(40),
    baseUrl: z.string(),
    region: z.string(),
    resource: z.string(),
    local: z.boolean(),
    cap: z.string().refine((v) => v === '' || (/^\d{1,7}(\.\d{1,2})?$/.test(v) && Number(v) > 0), t('models.cap_invalid')),
    key: z.string(),
  })
  .superRefine((v, ctx) => {
    const f = fieldsFor(v.kind);
    if (f.baseUrl && v.baseUrl.trim() === '') ctx.addIssue({ code: 'custom', path: ['baseUrl'], message: t('models.url_required') });
    if (f.baseUrl && v.baseUrl.trim() !== '' && !(v.baseUrl.startsWith('https://') || (v.local && v.baseUrl.startsWith('http://')))) ctx.addIssue({ code: 'custom', path: ['baseUrl'], message: v.local ? t('models.url_http_local') : t('models.url_https') });
    if (f.region && !REGION_RE.test(v.region.trim())) ctx.addIssue({ code: 'custom', path: ['region'], message: t('models.region_invalid') });
    if (f.resource && !RESOURCE_RE.test(v.resource.trim())) ctx.addIssue({ code: 'custom', path: ['resource'], message: t('models.resource_invalid') });
  });
type ProviderForm = z.infer<typeof providerSchema>;

function ProviderSheet({ open, onOpenChange, settings, save, existing, store, reload }: { open: boolean; onOpenChange: (o: boolean) => void; settings: Settings; save: (s: Settings) => Promise<string | null>; existing: ModelProvider | null; store: string; reload: () => void }) {
  const { client } = useApp();
  const [err, setErr] = useState<string | null>(null);
  const blank: ProviderForm = existing
    ? { kind: existing.kind, label: existing.label, baseUrl: existing.base_url ?? '', region: existing.region ?? '', resource: existing.resource ?? '', local: existing.local_endpoint, cap: existing.monthly_cap_usd === null ? '' : String(existing.monthly_cap_usd), key: '' }
    : { kind: 'anthropic', label: '', baseUrl: '', region: '', resource: '', local: false, cap: '', key: '' };
  const form = useForm<ProviderForm>({ resolver: zodResolver(providerSchema), defaultValues: blank });
  const errors = form.formState.errors;
  const kind = form.watch('kind');
  const fields = fieldsFor(kind);
  const [guide, setGuide] = useState(false);
  return (
    <PanelSheet open={open} onOpenChange={(o) => { onOpenChange(o); if (o) { form.reset(blank); setErr(null); setGuide(false); } }}>
      <PanelSheetContent size="compact" data-testid="provider-sheet">
        <form
          noValidate
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={form.handleSubmit(async (v) => {
            const id = existing?.id ?? (slug(v.label) || 'provider');
            if (!existing && settings.models.providers.some((p) => p.id === id)) return setErr(t('models.id_taken'));
            const f = fieldsFor(v.kind);
            const next: ModelProvider = { id, kind: v.kind, label: v.label.trim(), base_url: f.baseUrl ? v.baseUrl.trim() : null, local_endpoint: f.baseUrl && v.local, monthly_cap_usd: v.cap === '' ? null : Number(v.cap), region: f.region ? v.region.trim() : null, resource: f.resource ? v.resource.trim() : null, hosted_on: existing?.hosted_on ?? null };
            const providers = existing ? settings.models.providers.map((p) => (p.id === id ? next : p)) : [...settings.models.providers, next];
            const msg = await save({ ...settings, models: { ...settings.models, providers } });
            if (msg) return setErr(msg);
            if (v.key) {
              try {
                await client.putSecret(`model-key-${id}`, v.key);
              } catch (e) {
                return setErr(errorText(e));
              }
            }
            form.setValue('key', '');
            toast.success(t('models.saved'));
            onOpenChange(false);
            reload();
          })}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{existing ? t('models.edit_provider') : t('models.add_provider')}</PanelSheetTitle>
            <PanelSheetDescription>{t('models.secret_where', { store })}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
            {guide ? (
              <div className="space-y-3" data-testid="provider-guide">
                <p className="text-sm">{t('models.guide_intro')}</p>
                <ol className="list-decimal space-y-2 pl-5 text-sm">
                  {GUIDE_STEPS[kind].map((k) => (
                    <li key={k}>{t(k)}</li>
                  ))}
                </ol>
                {fields.ownCloud ? <p className="text-xs text-muted-foreground">{t('models.own_cloud_note')}</p> : null}
                <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => setGuide(false)}>{t('models.guide_done')}</Button>
              </div>
            ) : null}
            <div className={guide ? 'hidden' : 'space-y-4'}>
            <div className="flex items-end justify-between gap-2">
              <div className="min-w-0 flex-1 space-y-1">
              <Label htmlFor="mp-kind">{t('models.kind')}</Label>
              <Select value={kind} disabled={!!existing} onValueChange={(v) => form.setValue('kind', v as ModelKind, { shouldValidate: true })}>
                <SelectTrigger id="mp-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KINDS.map((k) => (
                    <SelectItem key={k} value={k}>{t(KIND_LABEL[k])}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              </div>
              <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => setGuide(true)}>{t('models.guide_button')}</Button>
            </div>
            <div className="space-y-1">
              <Label htmlFor="mp-label">{t('models.label')}</Label>
              <Input id="mp-label" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.label} {...form.register('label')} />
              <FieldError msg={errors.label?.message} />
            </div>
            {fields.region ? (
              <div className="space-y-1">
                <Label htmlFor="mp-region">{t('models.region')}</Label>
                <Input id="mp-region" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.region} {...form.register('region')} />
                <p className="text-xs text-muted-foreground">{t('models.region_hint')}</p>
                <FieldError msg={errors.region?.message} />
              </div>
            ) : null}
            {fields.resource ? (
              <div className="space-y-1">
                <Label htmlFor="mp-resource">{t('models.resource')}</Label>
                <Input id="mp-resource" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.resource} {...form.register('resource')} />
                <p className="text-xs text-muted-foreground">{t('models.resource_hint')}</p>
                <FieldError msg={errors.resource?.message} />
              </div>
            ) : null}
            {fields.ownCloud ? <p className="text-xs text-muted-foreground">{t('models.own_cloud_note')}</p> : null}
            {fields.baseUrl ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor="mp-url">{t('models.base_url')}</Label>
                  <Input id="mp-url" autoComplete="off" inputMode="url" className="max-lg:h-11" aria-invalid={!!errors.baseUrl} {...form.register('baseUrl')} />
                  <FieldError msg={errors.baseUrl?.message} />
                </div>
                <div className="flex min-h-11 items-center gap-3">
                  <TouchCheckbox id="mp-local" checked={form.watch('local')} onCheckedChange={(c) => form.setValue('local', c === true, { shouldValidate: true })} />
                  <Label htmlFor="mp-local">{t('models.local_endpoint')}</Label>
                </div>
                <p className="text-xs text-muted-foreground">{t('models.local_hint')}</p>
              </>
            ) : null}
            <SecretField id="mp-key" label={t('models.key')} hint={existing ? t('models.key_keep') : fields.keyOptional ? t('models.key_optional') : t('models.key_hint')} {...form.register('key')} />
            <div className="space-y-1">
              <Label htmlFor="mp-cap">{t('models.cap')}</Label>
              <Input id="mp-cap" inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.cap} {...form.register('cap')} />
              <FieldError msg={errors.cap?.message} />
            </div>
            </div>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={form.formState.isSubmitting}>{t('common.save')}</Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function DefaultsCard({ settings, save, reload }: { settings: Settings; save: (s: Settings) => Promise<string | null>; reload: () => void }) {
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const providers = settings.models.providers;
  const initial = () => Object.fromEntries(JOBS.map((j) => [j, { provider: settings.models.defaults[j]?.provider_id ?? NONE, model: settings.models.defaults[j]?.model ?? '' }]));
  const [draft, setDraft] = useState<Record<string, { provider: string; model: string }>>(initial);
  const bad = JOBS.some((j) => draft[j] && draft[j].provider !== NONE && !MODEL_RE.test(draft[j].model));
  return (
    <Card className="space-y-3 p-4" data-testid="model-defaults">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('models.defaults_title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" disabled={providers.length === 0} onClick={() => { setDraft(initial()); setErr(null); setOpen(true); }}>{t('common.edit')}</Button>
      </div>
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {JOBS.map((j) => {
          const c = settings.models.defaults[j];
          const p = providers.find((x) => x.id === c?.provider_id);
          return (
            <div key={j}>
              <dt className="text-xs text-muted-foreground">{t(JOB_LABEL[j])}</dt>
              <dd className="text-sm font-medium">{c && p ? `${p.label} · ${c.model}` : '—'}</dd>
            </div>
          );
        })}
      </dl>
      <p className="text-xs text-muted-foreground">{t('models.defaults_help')}</p>
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="defaults-models-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={async (e) => {
              e.preventDefault();
              if (bad) return setErr(t('models.model_invalid'));
              const defaults = Object.fromEntries(JOBS.map((j) => [j, draft[j] && draft[j].provider !== NONE ? { provider_id: draft[j].provider, model: draft[j].model } : null])) as Settings['models']['defaults'];
              const msg = await save({ ...settings, models: { ...settings.models, defaults } });
              if (msg) return setErr(msg);
              toast.success(t('models.saved'));
              setOpen(false);
              reload();
            }}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('models.defaults_title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('models.defaults_help')}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-5">
              {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
              {JOBS.map((j) => (
                <fieldset key={j} className="space-y-2">
                  <legend className="text-sm font-medium">{t(JOB_LABEL[j])}</legend>
                  <Label htmlFor={`md-${j}-p`}>{t('models.provider')}</Label>
                  <Select value={draft[j]?.provider ?? NONE} onValueChange={(v) => setDraft({ ...draft, [j]: { provider: v, model: draft[j]?.model ?? '' } })}>
                    <SelectTrigger id={`md-${j}-p`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>{t('models.none')}</SelectItem>
                      {providers.map((p) => (
                        <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Label htmlFor={`md-${j}-m`}>{t('models.model')}</Label>
                  <Input id={`md-${j}-m`} autoComplete="off" className="max-lg:h-11" disabled={(draft[j]?.provider ?? NONE) === NONE} value={draft[j]?.model ?? ''} onChange={(e) => setDraft({ ...draft, [j]: { provider: draft[j]?.provider ?? NONE, model: e.target.value } })} />
                </fieldset>
              ))}
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
              <Button type="submit">{t('common.save')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}

export function ModelsSection() {
  const { client } = useApp();
  const status = useAsync<ModelsStatus>((s) => client.models(s), [client]);
  const { settings, save, reload: reloadSettings, error: settingsError } = useSettings();
  const [editing, setEditing] = useState<ModelProvider | null>(null);
  const [sheet, setSheet] = useState(false);
  const [remove, setRemove] = useState<ModelProvider | null>(null);
  const [confirmTest, setConfirmTest] = useState<ModelProvider | null>(null);
  const [result, setResult] = useState<{ id: string; r: ModelTestResult } | null>(null);
  const [listing, setListing] = useState<{ id: string; r: ModelListResult } | null>(null);
  const [listingBusy, setListingBusy] = useState<string | null>(null);
  const checkConnection = async (p: ModelProvider) => {
    setListingBusy(p.id);
    try {
      setListing({ id: p.id, r: await client.listModels(p.id) });
    } catch (e) {
      setListing({ id: p.id, r: { ok: false, status: null, latency_ms: 0, detail: errorText(e), models: [], priced: [] } });
    } finally {
      setListingBusy(null);
    }
  };
  const reload = () => {
    status.reload();
    reloadSettings();
  };
  if (status.error && !status.data) return <p role="alert" className="text-sm text-destructive">{status.error.message}</p>;
  // settings that could not be read are said, not a skeleton for ever
  if (settingsError && !settings) return <p role="alert" className="text-sm text-destructive">{settingsError.message}</p>;
  if (!status.data || !settings) return <Skeleton className="h-64 w-full" />;
  const configured = (id: string) => status.data?.providers.find((p) => p.id === id)?.configured ?? false;
  return (
    <div className="space-y-4">
      <Card className="space-y-1 p-4">
        <div className="flex items-start justify-between gap-2">
          <h2 className="text-sm font-semibold">{t('models.title')}</h2>
          <Button size="sm" className="max-lg:h-11" onClick={() => { setEditing(null); setSheet(true); }}>{t('models.add_provider')}</Button>
        </div>
        <p className="text-xs text-muted-foreground" data-testid="models-note">{t('models.intro', { store: status.data.store })}</p>
        <p className="text-xs text-muted-foreground">{status.data.spend_note}</p>
      </Card>
      {settings.models.providers.length === 0 ? (
        <Card className="p-4 text-sm">{t('models.none_yet')}</Card>
      ) : (
        <ul className="grid gap-4 lg:grid-cols-2" aria-label={t('models.title')}>
          {settings.models.providers.map((p) => (
            <li key={p.id}>
              <Card className="h-full space-y-3 p-4" data-testid={`provider-${p.id}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="truncate text-sm font-semibold">{p.label}</h3>
                    <p className="text-xs text-muted-foreground">{t(KIND_LABEL[p.kind])}{p.hosted_on ? ` · ${t('models.hosted_on', { box: p.hosted_on })}` : ''}</p>
                  </div>
                  <Badge variant={configured(p.id) ? 'default' : 'outline'}>{configured(p.id) ? t('models.key_connected') : t('models.key_not_connected')}</Badge>
                </div>
                <dl className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <dt className="text-muted-foreground">{t('models.cap_label')}</dt>
                    <dd className="font-medium">{p.monthly_cap_usd === null ? '—' : t('models.cap_value', { amount: p.monthly_cap_usd.toFixed(2) })}</dd>
                  </div>
                  {p.base_url ? (
                    <div className="min-w-0">
                      <dt className="text-muted-foreground">{t('models.base_url')}</dt>
                      <dd className="truncate font-mono">{p.base_url}</dd>
                    </div>
                  ) : null}
                </dl>
                {listing?.id === p.id ? (
                  <div className="space-y-2" data-testid="model-list-result">
                    <Alert variant={listing.r.ok ? 'default' : 'destructive'} role="status">
                      <AlertDescription>{listing.r.detail}</AlertDescription>
                    </Alert>
                    {listing.r.ok ? <ModelList result={listing.r} /> : null}
                  </div>
                ) : null}
                {result?.id === p.id ? (
                  <Alert variant={result.r.ok ? 'default' : 'destructive'} role="status" data-testid="model-test-result">
                    <AlertDescription>{result.r.detail}</AlertDescription>
                  </Alert>
                ) : null}
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { setEditing(p); setSheet(true); }}>{t('common.edit')}</Button>
                  <Button variant="outline" size="sm" className="max-lg:h-11" disabled={listingBusy === p.id} onClick={() => void checkConnection(p)}>{t('models.test_free')}</Button>
                  <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setConfirmTest(p)}>{t('models.test_message')}</Button>
                  <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(p)}>{t('apps.remove')}</Button>
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
      <DefaultsCard settings={settings} save={save} reload={reload} />
      <EnginesCard settings={settings} save={save} reload={reload} />
      <PricesCard settings={settings} save={save} reload={reload} />
      <LocalAiCard reload={reload} />
      <UsageCard />
      <ProviderSheet key={editing?.id ?? 'new'} open={sheet} onOpenChange={setSheet} settings={settings} save={save} existing={editing} store={status.data.store} reload={reload} />
      <ConfirmDialog
        open={confirmTest !== null}
        onOpenChange={(o) => !o && setConfirmTest(null)}
        title={t('models.test_title')}
        description={t('models.test_body')}
        confirmLabel={t('models.test_confirm')}
        onConfirm={async () => {
          if (!confirmTest) return;
          try {
            const model = settings.models.defaults.coding?.provider_id === confirmTest.id ? settings.models.defaults.coding.model : settings.models.defaults.chat?.provider_id === confirmTest.id ? settings.models.defaults.chat.model : settings.models.defaults.review?.provider_id === confirmTest.id ? settings.models.defaults.review.model : null;
            setResult({ id: confirmTest.id, r: await client.testModel(confirmTest.id, model) });
          } catch (e) {
            setResult({ id: confirmTest.id, r: { ok: false, status: null, latency_ms: 0, detail: errorText(e) } });
          }
        }}
      />
      <ConfirmDialog
        open={remove !== null}
        onOpenChange={(o) => !o && setRemove(null)}
        title={t('models.remove_title')}
        description={t('models.remove_body')}
        confirmLabel={t('apps.remove')}
        destructive
        onConfirm={async () => {
          if (!remove) return;
          const defaults = Object.fromEntries(JOBS.map((j) => [j, settings.models.defaults[j]?.provider_id === remove.id ? null : settings.models.defaults[j]])) as Settings['models']['defaults'];
          const m = settings.models;
          const uses = (e: { provider_id: string; fallback: { provider_id: string } | null }) => e.provider_id === remove.id || e.fallback?.provider_id === remove.id;
          const engines = Object.fromEntries(Object.entries(m.engines).filter(([, e]) => !uses(e)));
          const box_overrides = Object.fromEntries(Object.entries(m.box_overrides).map(([b, per]) => [b, Object.fromEntries(Object.entries(per).filter(([, e]) => !uses(e)))] as const).filter(([, per]) => Object.keys(per).length > 0));
          const prices = Object.fromEntries(Object.entries(m.prices).filter(([k]) => !k.startsWith(`${remove.id}/`)));
          const msg = await save({ ...settings, models: { providers: m.providers.filter((p) => p.id !== remove.id), defaults, engines, box_overrides, prices } });
          if (msg) toast.error(msg);
          reload();
        }}
      />
    </div>
  );
}
