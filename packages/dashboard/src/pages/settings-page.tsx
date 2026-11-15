import { useState } from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useApp } from '../App';
import { FleetNotConnectedNotice } from '../components/fleet-notice';
import { ProviderStatus } from '../components/provider-status';
import { LocaleEditor } from '../components/locale-editor';
import type { Info } from '../api/types';
import { fleetMode, fleetNotConnected } from '../lib/fleet';
import { openFlow } from '../lib/flows';
import { AppPage, PageHeader, SubNav } from '../components/page';
import { DRIFT_MIN_USD_DEFAULT, DRIFT_PCT_DEFAULT, budgetSchema, budgetToForm, defaultsSchema, defaultsToForm, formToBudget, formToDefaults, type BudgetForm, type DefaultsForm } from '../lib/settings-form';
import { t } from '../lib/i18n';
import { useSettings } from '../lib/use-settings';
import { AccessSection } from './settings-access';
import { ApprovalsSection } from './settings-approvals';
import { SecretApprovalsSection } from './settings-secret-approvals';
import { ApproversSection } from './settings-approvers';
import { AppsSection } from './settings-apps';
import { BackupsSection } from './settings-backups';
import { ModelsSection } from './settings-models';
import { MembersSection } from './settings-members';
import { ReadOnlyScope } from '../components/role-scope';
import { hrefs, type SettingsSection } from '../lib/router';

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm font-medium">{value}</dd>
    </div>
  );
}

function FieldError({ msg }: { msg?: string }) {
  return msg ? (
    <p role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

function SaveError({ msg }: { msg: string | null }) {
  return msg ? (
    <Alert variant="destructive" role="alert">
      <AlertDescription>{msg}</AlertDescription>
    </Alert>
  ) : null;
}

function BudgetsSection() {
  const { info } = useApp();
  const { settings, persisted, error, save } = useSettings();
  const [open, setOpen] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const form = useForm<BudgetForm>({ resolver: zodResolver(budgetSchema), defaultValues: settings ? budgetToForm(settings.budget) : undefined });
  const e = form.formState.errors;
  if (error && !settings) return <p role="alert" className="text-sm text-destructive">{error.message}</p>;
  if (!settings) return <Skeleton className="h-40 w-full" />;
  const b = settings.budget;
  const on = (v: boolean) => (v ? t('settings.on') : t('settings.off'));
  const priced = Object.keys(b.size_prices_usd).length;
  const sizes = info?.sizes ?? [];
  return (
    <Card className="space-y-3 p-4">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('settings.budget_title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { form.reset(budgetToForm(b)); setSaveError(null); setOpen(true); }}>
          {t('common.edit')}
        </Button>
      </div>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <Row label={t('settings.monthly_budget')} value={b.monthly_usd === null ? '—' : String(b.monthly_usd)} />
        <Row label={t('settings.max_running')} value={b.max_running_boxes === null ? '—' : String(b.max_running_boxes)} />
        <Row label={t('settings.sizes_priced')} value={t('settings.priced_of', { n: priced, total: sizes.length || '—' })} />
        <Row label={t('settings.alert_50')} value={on(b.alert_50)} />
        <Row label={t('settings.alert_80')} value={on(b.alert_80)} />
        <Row label={t('settings.alert_100')} value={on(b.alert_100)} />
        <Row label={t('settings.quiet_hours')} value={t('settings.quiet_range', { from: b.quiet_from, to: b.quiet_to })} />
        <Row label={t('settings.alerts_in_dashboard')} value={on(b.in_app)} />
        <Row label={t('budget.utc_offset')} value={String(b.utc_offset_minutes)} />
        <Row label={t('budget.drift_row')} value={t('budget.drift_value', { pct: b.drift_alert_pct ?? DRIFT_PCT_DEFAULT, usd: b.drift_alert_min_usd ?? DRIFT_MIN_USD_DEFAULT })} />
      </dl>
      <p className="text-xs text-muted-foreground" data-testid="budget-note">
        {persisted ? t('settings.saved_on_server') : t('settings.no_file')} {t('settings.budget_note')} {t('budget.alerts_note')}
      </p>
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="budget-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={form.handleSubmit(async (v) => {
              const msg = await save({ ...settings, budget: { ...settings.budget, ...formToBudget(v) } });
              if (msg) setSaveError(msg);
              else {
                toast.success(t('settings.budget_saved'));
                setOpen(false);
              }
            })}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('settings.budget_title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('settings.saved_on_server')}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              <SaveError msg={saveError} />
              <div className="space-y-1">
                <Label htmlFor="b-monthly">{t('settings.monthly_budget_field')}</Label>
                <Input id="b-monthly" inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.monthly} {...form.register('monthly')} />
                <FieldError msg={e.monthly?.message} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="b-max">{t('settings.max_running_field')}</Label>
                <Input id="b-max" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.maxRunning} {...form.register('maxRunning')} />
                <FieldError msg={e.maxRunning?.message} />
              </div>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">{t('settings.prices_legend')}</legend>
                <p className="text-xs text-muted-foreground">{t('settings.prices_help')}</p>
                <div className="grid grid-cols-2 gap-3">
                  {sizes.map((z) => (
                    <div key={z.id} className="space-y-1">
                      <Label htmlFor={`b-price-${z.id}`}>{t('settings.size_id', { id: z.id })}</Label>
                      <Input id={`b-price-${z.id}`} inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.prices?.[z.id]} {...form.register(`prices.${z.id}`)} />
                      <FieldError msg={e.prices?.[z.id]?.message} />
                    </div>
                  ))}
                </div>
              </fieldset>
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('settings.alert_when')}</legend>
                {(['at50', 'at80', 'at100'] as const).map((k) => (
                  <div key={k} className="flex min-h-11 items-center gap-3">
                    <TouchCheckbox id={`b-${k}`} checked={form.watch(k)} onCheckedChange={(c) => form.setValue(k, c === true)} />
                    <Label htmlFor={`b-${k}`}>{k.replace('at', '')}%</Label>
                  </div>
                ))}
              </fieldset>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label htmlFor="b-from">{t('settings.quiet_from')}</Label>
                  <Input id="b-from" className="max-lg:h-11" aria-invalid={!!e.quietFrom} {...form.register('quietFrom')} />
                  <FieldError msg={e.quietFrom?.message} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="b-to">{t('settings.quiet_to')}</Label>
                  <Input id="b-to" className="max-lg:h-11" aria-invalid={!!e.quietTo} {...form.register('quietTo')} />
                  <FieldError msg={e.quietTo?.message} />
                </div>
              </div>
              <div className="space-y-1">
                <Label htmlFor="b-offset">{t('budget.utc_offset')}</Label>
                <Input id="b-offset" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.utcOffset} {...form.register('utcOffset')} />
                <p className="text-xs text-muted-foreground">{t('budget.utc_offset_hint')}</p>
                <FieldError msg={e.utcOffset?.message} />
              </div>
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('budget.drift_legend')}</legend>
                <p className="text-xs text-muted-foreground">{t('budget.drift_help')}</p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label htmlFor="b-drift-pct">{t('budget.drift_pct')}</Label>
                    <Input id="b-drift-pct" inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.driftPct} {...form.register('driftPct')} />
                    <FieldError msg={e.driftPct?.message} />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="b-drift-min">{t('budget.drift_min')}</Label>
                    <Input id="b-drift-min" inputMode="decimal" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.driftMinUsd} {...form.register('driftMinUsd')} />
                    <FieldError msg={e.driftMinUsd?.message} />
                  </div>
                </div>
              </fieldset>
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('settings.channels')}</legend>
                <div className="flex min-h-11 items-center gap-3">
                  <TouchCheckbox id="b-inApp" checked={form.watch('inApp')} onCheckedChange={(c) => form.setValue('inApp', c === true)} />
                  <Label htmlFor="b-inApp">{t('settings.in_dashboard')}</Label>
                </div>
                <p className="text-xs text-muted-foreground">{t('budget.channels_elsewhere')}</p>
              </fieldset>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>{t('common.save')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}

function DefaultsSection() {
  const { info } = useApp();
  const { settings, persisted, error, save } = useSettings();
  const [open, setOpen] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const form = useForm<DefaultsForm>({ resolver: zodResolver(defaultsSchema), defaultValues: settings ? defaultsToForm(settings.defaults) : undefined });
  const e = form.formState.errors;
  // defaults are for boxes this dashboard would create; a box's own dashboard has no provider to create them with, so a form
  // here could only ever answer "that size is not offered"
  if (fleetNotConnected(info)) return <FleetNotConnectedNotice info={info} />;
  if (error && !settings) return <p role="alert" className="text-sm text-destructive">{error.message}</p>;
  if (!settings) return <Skeleton className="h-40 w-full" />;
  const value = defaultsToForm(settings.defaults);
  return (
    <Card className="space-y-3 p-4">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('settings.defaults_title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { form.reset(value); setSaveError(null); setOpen(true); }}>
          {t('common.edit')}
        </Button>
      </div>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <Row label={t('settings.size')} value={value.size} />
        <Row label={t('settings.work_disk')} value={t('settings.gb', { n: value.disk })} />
        <Row label={t('settings.auto_pause')} value={t('settings.min', { n: value.autoPauseMinutes })} />
        <Row label={t('settings.always_on')} value={value.alwaysOn ? t('settings.yes') : t('settings.no')} />
        <Row label={t('settings.image_channel')} value={value.imageChannel} />
      </dl>
      <p className="text-xs text-muted-foreground" data-testid="defaults-note">
        {persisted ? t('settings.saved_on_server') : t('settings.no_file')} {t('settings.defaults_note_before')}<code>{'ozbox create'}</code>{t('settings.defaults_note_after')}
      </p>
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="defaults-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={form.handleSubmit(async (v) => {
              const d = formToDefaults(v, info?.sizes ?? []);
              if (!d) {
                setSaveError(t('settings.size_not_offered'));
                return;
              }
              const msg = await save({ ...settings, defaults: d });
              if (msg) setSaveError(msg);
              else {
                toast.success(t('settings.defaults_saved'));
                setOpen(false);
              }
            })}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('settings.defaults_title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('settings.saved_on_server')}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              <SaveError msg={saveError} />
              <div className="space-y-1">
                <Label htmlFor="d-size">{t('settings.size')}</Label>
                <Select value={form.watch('size')} onValueChange={(v) => form.setValue('size', v, { shouldValidate: true })}>
                  <SelectTrigger id="d-size">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(info?.sizes ?? [{ id: 'M', vcpus: 8, memory_gb: 32 }]).map((s) => (
                      <SelectItem key={s.id} value={s.id}>{t('settings.size_option', { id: s.id, vcpus: s.vcpus, memory: s.memory_gb })}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldError msg={e.size?.message} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="d-disk">{t('settings.work_disk_field')}</Label>
                <Input id="d-disk" inputMode="numeric" className="max-lg:h-11" aria-invalid={!!e.disk} {...form.register('disk')} />
                <FieldError msg={e.disk?.message} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="d-idle">{t('settings.auto_pause_field')}</Label>
                <Input id="d-idle" inputMode="numeric" className="max-lg:h-11" aria-invalid={!!e.autoPauseMinutes} {...form.register('autoPauseMinutes')} />
                <FieldError msg={e.autoPauseMinutes?.message} />
              </div>
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="d-always" checked={form.watch('alwaysOn')} onCheckedChange={(c) => form.setValue('alwaysOn', c === true)} />
                <Label htmlFor="d-always">{t('settings.always_on_field')}</Label>
              </div>
              <div className="space-y-1">
                <Label htmlFor="d-image">{t('settings.image_channel')}</Label>
                <Select value={form.watch('imageChannel')} onValueChange={(v) => form.setValue('imageChannel', v === 'next' ? 'next' : 'stable')}>
                  <SelectTrigger id="d-image">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="stable">{t('settings.channel_stable')}</SelectItem>
                    <SelectItem value="next">{t('settings.channel_next')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>{t('common.save')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}

/** The provider's name and, for the two that are not a real fleet, what it is: a demo's data is made up, a box's dashboard sees one box. */
function providerLabel(info: Info): string {
  const mode = fleetMode(info);
  if (mode === 'demo') return `${info.provider} · ${t('provider.state_demo')}`;
  if (mode === 'this_box') return `${info.provider} · ${t('provider.state_this_box')}`;
  return info.provider;
}

export function SettingsPage({ section }: { section: SettingsSection }) {
  const { info } = useApp();
  const items: { href: string; label: string }[] = [
    { href: hrefs.settings('general'), label: t('settings.tab_general') },
    { href: hrefs.settings('providers'), label: t('settings.tab_providers') },
    { href: hrefs.settings('budgets'), label: t('settings.tab_budgets') },
    { href: hrefs.settings('backups'), label: t('nav.settings_backups') },
    { href: hrefs.settings('apps'), label: t('nav.settings_apps') },
    { href: hrefs.settings('access'), label: t('nav.settings_access') },
    { href: hrefs.settings('approvals'), label: t('nav.settings_approvals') },
    { href: hrefs.settings('secret-approvals'), label: t('nav.settings_secret_approvals') },
    { href: hrefs.settings('approvers'), label: t('nav.settings_approvers') },
    { href: hrefs.settings('models'), label: t('nav.settings_models') },
    { href: hrefs.settings('defaults'), label: t('settings.defaults_title') },
    { href: hrefs.settings('members'), label: t('settings.tab_members') },
  ];
  return (
    <AppPage width="narrow">
      <PageHeader title={t('nav.settings')} description={t('settings.description')} />
      <SubNav label={t('settings.sections')} items={items} current={hrefs.settings(section)} />
      <ReadOnlyScope cap="change_settings">
        {section === 'general' && (
          <Card className="space-y-3 p-4">
            <h2 className="text-sm font-semibold">{t('settings.connection')}</h2>
            <dl className="grid grid-cols-2 gap-3">
              <Row label={t('settings.server_version')} value={info?.version ?? '—'} />
              <Row label={t('settings.provider')} value={info ? providerLabel(info) : '—'} />
              <Row label={t('settings.usage_numbers')} value={info ? (info.metrics === 'simulated' ? t('settings.metrics_simulated') : t('settings.metrics_ssh')) : '—'} />
              <Row label={t('settings.box_address')} value={info ? (info.domain ? `https://<name>.${info.domain}` : t('settings.no_domain')) : '—'} />
            </dl>
            <p className="text-xs text-muted-foreground">{t('settings.listens_local')}</p>
          </Card>
        )}
        {section === 'general' && (
          <Card className="space-y-3 p-4" data-testid="locale-card">
            <h2 className="text-sm font-semibold">{t('locale.title')}</h2>
            <p className="text-xs text-muted-foreground">{t('locale.desc')}</p>
            {info?.clock?.now ? (
              <p className="text-xs" data-testid="locale-now">
                {t('locale.now', { now: info.clock.now })}
              </p>
            ) : null}
            <LocaleEditor />
          </Card>
        )}
        {section === 'providers' && (
          <div className="space-y-4">
            <Card className="space-y-3 p-4" data-testid="provider-card">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-semibold">{info?.provider ?? '—'}</h2>
                <Button variant="outline" className="max-lg:h-11" onClick={() => openFlow('setup')} data-testid="add-provider">
                  {t('flow.add_provider')}
                </Button>
              </div>
              <ProviderStatus>
                {(check) => (
                  <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                    <Row label={t('settings.resize_method')} value={info?.capabilities.resize ?? '—'} />
                    <Row label={t('settings.grow_disk')} value={info ? (info.capabilities.online_disk_grow ? t('settings.yes') : t('settings.no')) : '—'} />
                    <Row label={t('settings.snapshots')} value={info ? (info.capabilities.snapshots ? t('settings.yes') : t('settings.no')) : '—'} />
                    {check && check.searched.length > 0 ? <Row label={t('settings.regions')} value={check.searched.join(', ')} /> : null}
                    {check && check.boxes !== null ? <Row label={t('provider.boxes_seen')} value={String(check.boxes)} /> : null}
                  </dl>
                )}
              </ProviderStatus>
            </Card>
            <Card className="overflow-hidden">
              <h2 className="p-4 pb-2 text-sm font-semibold">{t('settings.sizes_offered')}</h2>
              <Table aria-label={t('settings.sizes')}>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('settings.size')}</TableHead>
                    <TableHead>{t('settings.col_vcpu')}</TableHead>
                    <TableHead>{t('settings.col_memory')}</TableHead>
                    <TableHead>{t('settings.col_gpus')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(info?.sizes ?? []).map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.id}</TableCell>
                      <TableCell>{s.vcpus}</TableCell>
                      <TableCell>{t('settings.gb', { n: s.memory_gb })}</TableCell>
                      <TableCell>{s.gpus}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </div>
        )}
        {section === 'budgets' && <BudgetsSection />}
        {section === 'backups' && <BackupsSection />}
        {section === 'apps' && <AppsSection />}
        {section === 'access' && <AccessSection />}
        {section === 'approvals' && <ApprovalsSection />}
        {section === 'secret-approvals' && <SecretApprovalsSection />}
        {section === 'approvers' && <ApproversSection />}
        {section === 'models' && <ModelsSection />}
        {section === 'defaults' && <DefaultsSection />}
        {section === 'members' && <MembersSection />}
      </ReadOnlyScope>
    </AppPage>
  );
}
