import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../api/client';
import type { BackupsSettings, FleetBackups, ResticKind } from '../api/backups';
import { useApp } from '../App';
import { AppLink } from '../components/page';
import { FleetNotConnectedNotice } from '../components/fleet-notice';
import { SecretField } from '../components/secret-field';
import { SourceNote } from '../components/source-badge';
import { backupsSchema, destinationsText, estimateText, fmtWhen, formToSettings, KIND_LABEL, LOCATION_HINT, missingSecret, needsKeys, retentionText, scheduleText, settingsToForm, weekdayName, type BackupsForm } from '../lib/backups';
import { FLEET_NOT_CONNECTED } from '../lib/fleet';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { hrefs } from '../lib/router';
import { useAsync } from '../lib/use-async';

const SECRET_NAMES = { password: 'restic-password', accessKey: 'restic-access-key', secretKey: 'restic-secret-key' } as const;

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm font-medium">{children}</dd>
    </div>
  );
}

function FieldError({ msg }: { msg?: string | undefined }) {
  return msg ? (
    <p role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

function errorText(e: unknown): string {
  return e instanceof ApiError ? e.message : t('common.save_failed');
}

function PolicySheet({ open, onOpenChange, fleet, reload }: { open: boolean; onOpenChange: (o: boolean) => void; fleet: FleetBackups; reload: () => void }) {
  const { client } = useApp();
  const [err, setErr] = useState<string | null>(null);
  const form = useForm<BackupsForm>({ resolver: zodResolver(backupsSchema), defaultValues: settingsToForm(fleet.settings) });
  const e = form.formState.errors;
  const every = form.watch('every');
  const useRepo = form.watch('useRepo');
  const repoKind = form.watch('repoKind');
  const flags = fleet.secrets;
  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent size="wide" data-testid="backups-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          noValidate
          onSubmit={form.handleSubmit(async (v) => {
            setErr(null);
            const missing = missingSecret(v, flags);
            if (missing) return setErr(t('backups.secret_missing', { what: missing }));
            try {
              // The credentials go to the server's secret store first and are never kept in the page.
              for (const [field, name] of Object.entries(SECRET_NAMES) as [keyof typeof SECRET_NAMES, string][]) {
                const value = v[field];
                if (v.useRepo && value !== '' && (field === 'password' || needsKeys(v.repoKind))) await client.putSecret(name, value);
              }
              await client.backups.saveSettings(formToSettings(v, fleet.settings));
            } catch (x) {
              return setErr(errorText(x));
            }
            form.setValue('password', '');
            form.setValue('accessKey', '');
            form.setValue('secretKey', '');
            toast.success(t('backups.saved'));
            onOpenChange(false);
            reload();
          })}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('backups.form_title')}</PanelSheetTitle>
            <PanelSheetDescription>{t('backups.form_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {err ? (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{err}</AlertDescription>
              </Alert>
            ) : null}
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <Label htmlFor="bk-every">{t('backups.f_every')}</Label>
                <Select value={every} onValueChange={(v) => form.setValue('every', v as BackupsForm['every'], { shouldValidate: true })}>
                  <SelectTrigger id="bk-every" className="max-lg:h-11">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="off">{t('backups.every_off')}</SelectItem>
                    <SelectItem value="daily">{t('backups.every_daily')}</SelectItem>
                    <SelectItem value="weekly">{t('backups.every_weekly')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {every === 'weekly' ? (
                <div className="space-y-1">
                  <Label htmlFor="bk-weekday">{t('backups.f_weekday')}</Label>
                  <Select value={form.watch('weekday')} onValueChange={(v) => form.setValue('weekday', v, { shouldValidate: true })}>
                    <SelectTrigger id="bk-weekday" className="max-lg:h-11">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {[0, 1, 2, 3, 4, 5, 6].map((d) => (
                        <SelectItem key={d} value={String(d)}>
                          {weekdayName(d)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ) : null}
              <div className="space-y-1">
                <Label htmlFor="bk-time">{t('backups.f_time')}</Label>
                <Input id="bk-time" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e.time} {...form.register('time')} />
                <FieldError msg={e.time?.message} />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">{t('backups.clock', { zone: fleet.zone })}</p>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('backups.retention')}</legend>
              <div className="grid grid-cols-3 gap-3">
                {(['keepDaily', 'keepWeekly', 'keepMonthly'] as const).map((k) => (
                  <div key={k} className="space-y-1">
                    <Label htmlFor={`bk-${k}`}>{t(k === 'keepDaily' ? 'backups.f_keep_daily' : k === 'keepWeekly' ? 'backups.f_keep_weekly' : 'backups.f_keep_monthly')}</Label>
                    <Input id={`bk-${k}`} inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!e[k]} {...form.register(k)} />
                    <FieldError msg={e[k]?.message} />
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">{t('backups.f_keep_hint')}</p>
            </fieldset>
            <div className="space-y-1">
              <Label htmlFor="bk-catch">{t('backups.f_catch_up')}</Label>
              <Input id="bk-catch" inputMode="numeric" autoComplete="off" className="max-lg:h-11 sm:max-w-40" aria-invalid={!!e.catchUp} {...form.register('catchUp')} />
              <FieldError msg={e.catchUp?.message} />
            </div>
            <div className="space-y-1">
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="bk-provider" checked={form.watch('providerSnapshots')} onCheckedChange={(c) => form.setValue('providerSnapshots', c === true)} />
                <Label htmlFor="bk-provider">{t('backups.f_provider')}</Label>
              </div>
              <p className="text-xs text-muted-foreground">{t('backups.f_provider_hint')}</p>
            </div>
            <div className="space-y-3">
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="bk-repo" checked={useRepo} onCheckedChange={(c) => form.setValue('useRepo', c === true, { shouldValidate: true })} />
                <Label htmlFor="bk-repo">{t('backups.f_repo')}</Label>
              </div>
              {useRepo ? (
                <div className="space-y-3 rounded-md border p-3" data-testid="repo-fields">
                  <div className="space-y-1">
                    <Label htmlFor="bk-kind">{t('backups.f_repo_kind')}</Label>
                    <Select value={repoKind} onValueChange={(v) => form.setValue('repoKind', v as ResticKind, { shouldValidate: true })}>
                      <SelectTrigger id="bk-kind" className="max-lg:h-11">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {(Object.keys(KIND_LABEL) as ResticKind[]).map((k) => (
                          <SelectItem key={k} value={k}>
                            {t(KIND_LABEL[k])}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="bk-location">{t('backups.f_repo_location')}</Label>
                    <Input id="bk-location" autoComplete="off" spellCheck={false} placeholder={t(LOCATION_HINT[repoKind])} className="max-lg:h-11" aria-invalid={!!e.repoLocation} {...form.register('repoLocation')} />
                    <FieldError msg={e.repoLocation?.message} />
                  </div>
                  <SecretField id="bk-password" label={t('backups.f_password')} hint={`${flags.password ? t('backups.secret_set') : t('backups.secret_unset')} ${t('backups.password_hint')}`} {...form.register('password')} />
                  {needsKeys(repoKind) ? (
                    <>
                      <SecretField id="bk-access" label={t('backups.f_access_key')} hint={flags.access_key ? t('backups.secret_set') : t('backups.secret_unset')} {...form.register('accessKey')} />
                      <SecretField id="bk-secret" label={t('backups.f_secret_key')} hint={flags.secret_key ? t('backups.secret_set') : t('backups.secret_unset')} {...form.register('secretKey')} />
                    </>
                  ) : null}
                </div>
              ) : null}
            </div>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" className="max-lg:h-11" disabled={form.formState.isSubmitting}>
              {t('common.save')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

/** One box's own choice: follow the fleet, or off. (A schedule of its own is set with `ozbox backup schedule --box`.) */
function BoxChoice({ name, settings, onSave }: { name: string; settings: BackupsSettings; onSave: (s: BackupsSettings) => Promise<void> }) {
  const o = settings.overrides[name];
  const value = o?.enabled === false ? 'off' : 'follow';
  return (
    <Select
      value={value}
      onValueChange={(v) => {
        const overrides = { ...settings.overrides };
        if (v === 'off') overrides[name] = { enabled: false, schedule: o?.schedule ?? null };
        else if (o?.schedule) overrides[name] = { enabled: null, schedule: o.schedule };
        else delete overrides[name];
        void onSave({ ...settings, overrides });
      }}
    >
      <SelectTrigger aria-label={t('backups.override_title') + ' ' + name} className="max-lg:h-11 sm:w-56">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="follow">{t('backups.override_follow')}</SelectItem>
        <SelectItem value="off">{t('backups.override_off')}</SelectItem>
      </SelectContent>
    </Select>
  );
}

export function BackupsSection() {
  const { client, info } = useApp();
  const q = useAsync<FleetBackups>((s) => client.backups.fleet(s), [client], 10_000);
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // a box's own dashboard has no fleet to back up: say so in the notice every fleet page uses, not as a bare error
  if (q.error instanceof ApiError && q.error.code === FLEET_NOT_CONNECTED) return <FleetNotConnectedNotice info={info} />;
  if (q.error && !q.data) return <p role="alert" className="text-sm text-destructive">{q.error.message}</p>;
  if (!q.data) return <Skeleton className="h-40 w-full" />;
  const f = q.data;
  const s = f.settings;
  const saveSettings = async (next: BackupsSettings) => {
    setErr(null);
    try {
      await client.backups.saveSettings(next);
      q.reload();
    } catch (x) {
      setErr(errorText(x));
    }
  };
  return (
    <div className="space-y-4" data-testid="backups-section">
      <SourceNote source={f.source} what="backups" />
      <Card className="space-y-3 p-4" data-testid="backups-policy">
        <div className="flex items-start justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold">{t('backups.policy')}</h2>
            <p className="text-xs text-muted-foreground">{t('backups.description')}</p>
          </div>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setOpen(true)} data-testid="backups-edit">
            {t('backups.edit')}
          </Button>
        </div>
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Row label={t('backups.schedule')}>{scheduleText(s.schedule)}</Row>
          <Row label={t('backups.retention')}>{retentionText(s.retention)}</Row>
          <Row label={t('backups.destinations')}>
            <ul className="space-y-0.5">
              {destinationsText(s).map((d) => (
                <li key={d} className="break-words">
                  {d}
                </li>
              ))}
            </ul>
          </Row>
          <Row label={t('backups.catch_up')}>{t('backups.catch_up_value', { h: s.catch_up_hours })}</Row>
          <Row label={t('backups.estimate')}>
            <span data-testid="backups-estimate">{estimateText(f.estimate)}</span>
          </Row>
        </dl>
        <p className="text-xs text-muted-foreground">{t('backups.clock', { zone: f.zone })}</p>
        <p className="text-xs text-muted-foreground" data-testid="backups-who-runs">
          {f.source === 'simulated' ? t('backups.who_runs_demo') : t('backups.who_runs')}
        </p>
        {s.restic ? <p className="text-xs text-muted-foreground">{t('backups.estimate_repo')}</p> : null}
      </Card>
      {err ? (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{err}</AlertDescription>
        </Alert>
      ) : null}
      <Card className="overflow-hidden" data-testid="backups-boxes">
        <h2 className="p-4 pb-2 text-sm font-semibold">{t('backups.boxes')}</h2>
        {f.boxes.length === 0 ? (
          <p className="p-4 pt-0 text-sm text-muted-foreground">{t('backups.no_boxes')}</p>
        ) : (
          <Table aria-label={t('backups.boxes')}>
            <TableHeader>
              <TableRow>
                <TableHead>{t('backups.col_box')}</TableHead>
                <TableHead>{t('backups.col_schedule')}</TableHead>
                <TableHead>{t('backups.col_next')}</TableHead>
                <TableHead>{t('backups.col_last')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {f.boxes.map((b) => (
                <TableRow key={b.name} data-testid={`backups-row-${b.name}`}>
                  <TableCell className="font-medium">
                    <AppLink href={hrefs.box(b.name)} className="inline-flex min-h-11 items-center underline-offset-4 hover:underline lg:min-h-0">
                      {b.name}
                    </AppLink>
                  </TableCell>
                  <TableCell>
                    <div className="space-y-1">
                      <span className="block text-sm">{scheduleText(b.schedule)}</span>
                      <BoxChoice name={b.name} settings={s} onSave={saveSettings} />
                    </div>
                  </TableCell>
                  <TableCell className="text-sm">{b.schedule.kind === 'off' ? '—' : fmtWhen(b.next_run_ms, f.zone)}</TableCell>
                  <TableCell className="text-sm">
                    {b.running ? (
                      <Badge variant="secondary">{t('backups.running')}</Badge>
                    ) : b.last ? (
                      <span className={b.last.ok ? '' : 'text-destructive'}>{b.last.ok ? t('backups.last_ok', { when: fmtRelative(new Date(b.last.ts_ms).toISOString()) }) : t('backups.last_failed', { when: fmtRelative(new Date(b.last.ts_ms).toISOString()), detail: b.last.detail })}</span>
                    ) : (
                      <span className="text-muted-foreground">{t('backups.none_yet')}</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
      {open ? <PolicySheet key={JSON.stringify(s)} open={open} onOpenChange={setOpen} fleet={f} reload={q.reload} /> : null}
    </div>
  );
}
