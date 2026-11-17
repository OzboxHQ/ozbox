import { useMemo, useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { z } from 'zod';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Combobox } from '@/components/ui/combobox';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import type { PersonRouting } from '../api/channel-types';
import type { AppsStatus, Settings } from '../api/types';
import { useApp } from '../App';
import { CHANNEL_IDS, defaultPerson, preview } from '../lib/routing';
import { t, type MessageKey } from '../lib/i18n';
import { turnOnThisDevice } from '../lib/push';
import { getTimezoneOptions } from '../lib/timezones';
import { FieldError } from './settings-apps';

interface Props {
  status: AppsStatus;
  settings: Settings;
  save: (s: Settings) => Promise<string | null>;
  reload: () => void;
}

const ADDRESS = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;
const E164 = /^\+[1-9]\d{6,14}$/;
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

const schema = z.object({
  id: z.string().regex(/^[a-z0-9-]{1,24}$/, t('routing.person_bad_id')),
  zone: z.string(),
  quietFrom: z.string().refine((v) => v === '' || HHMM.test(v), t('routing.bad_time')),
  quietTo: z.string().refine((v) => v === '' || HHMM.test(v), t('routing.bad_time')),
  phone: z.string().trim().refine((v) => v === '' || E164.test(v), t('routing.bad_phone')),
  whatsapp: z.string().trim().refine((v) => v === '' || E164.test(v), t('routing.bad_phone')),
  emails: z.string().refine((v) => v.split(',').map((x) => x.trim()).filter(Boolean).every((a) => ADDRESS.test(a)), t('routing.bad_email')),
  urgent: z.array(z.string()),
  bypass: z.boolean(),
  normal: z.array(z.string()),
  digestOn: z.boolean(),
  digestTime: z.string().refine((v) => HHMM.test(v), t('routing.bad_time')),
  digest: z.array(z.string()),
  scheduleRule: z.enum(['', 'urgent', 'normal', 'off']),
});
type Form = z.infer<typeof schema>;

function toForm(id: string, p: PersonRouting): Form {
  return {
    id,
    zone: p.time_zone ?? '',
    quietFrom: p.quiet_from ?? '',
    quietTo: p.quiet_to ?? '',
    phone: p.phone ?? '',
    whatsapp: p.whatsapp ?? '',
    emails: p.emails.join(', '),
    urgent: p.urgent.channels,
    bypass: p.urgent.bypass_quiet,
    normal: p.normal.channels,
    digestOn: p.digest.enabled,
    digestTime: p.digest.time,
    digest: p.digest.channels,
    scheduleRule: p.kind_routes?.schedule ?? '',
  };
}

function fromForm(v: Form, existing: PersonRouting | undefined): PersonRouting {
  const emails = v.emails.split(',').map((x) => x.trim()).filter(Boolean);
  return {
    time_zone: v.zone || null,
    quiet_from: v.quietFrom && v.quietTo ? v.quietFrom : null,
    quiet_to: v.quietFrom && v.quietTo ? v.quietTo : null,
    phone: v.phone || null,
    whatsapp: v.whatsapp || null,
    emails,
    push: existing?.push ?? [],
    urgent: { channels: v.urgent, bypass_quiet: v.bypass },
    normal: { channels: v.normal, bypass_quiet: false },
    digest: { enabled: v.digestOn, time: v.digestTime, channels: v.digest },
    ...(v.scheduleRule ? { kind_routes: { schedule: v.scheduleRule } } : {}),
  };
}

function useChannelNames(status: AppsStatus, settings: Settings) {
  const label = (id: string): string => {
    if (id.startsWith('webhook:')) return settings.apps.webhooks.find((w) => `webhook:${w.id}` === id)?.label ?? t('ch.webhook');
    return t(`ch.${id}` as MessageKey);
  };
  const ready = (id: string): boolean => {
    switch (id) {
      case 'sms': return status.sms.configured;
      case 'email': return status.email.configured;
      case 'telegram': return status.telegram.configured && status.telegram.chats.length > 0;
      case 'slack': return status.slack.configured;
      case 'whatsapp': return status.whatsapp.configured;
      case 'discord': return status.discord.configured;
      case 'teams': return status.teams.configured;
      case 'push': return status.push.configured;
      default: return status.webhooks.find((w) => `webhook:${w.id}` === id)?.configured ?? false;
    }
  };
  const all = [...CHANNEL_IDS, ...settings.apps.webhooks.map((w) => `webhook:${w.id}`)] as string[];
  return { label, ready, all };
}

function ChannelBoxes({ legend, name, value, onChange, names }: { legend: string; name: string; value: string[]; onChange: (v: string[]) => void; names: ReturnType<typeof useChannelNames> }) {
  return (
    <fieldset className="space-y-1" data-testid={`routing-${name}`}>
      <legend className="text-sm font-medium">{legend}</legend>
      <div className="grid gap-x-4 sm:grid-cols-2">
        {names.all.map((id) => {
          const on = value.includes(id);
          const box = `rt-${name}-${id.replace(':', '-')}`;
          return (
            <div key={id} className="flex min-h-11 items-center gap-3 lg:min-h-8">
              <TouchCheckbox id={box} checked={on} onCheckedChange={(c) => onChange(c === true ? [...value, id] : value.filter((x) => x !== id))} />
              <Label htmlFor={box} className="text-sm">
                {names.ready(id) ? names.label(id) : t('routing.channel_note_off', { channel: names.label(id) })}
              </Label>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}

function PersonSheet({ open, onOpenChange, personId, status, settings, save, reload }: Props & { open: boolean; onOpenChange: (o: boolean) => void; personId: string | null }) {
  const { client } = useApp();
  const existing = personId ? settings.routing.people[personId] : undefined;
  const [err, setErr] = useState<string | null>(null);
  const [busyDevice, setBusyDevice] = useState(false);
  const zones = useMemo(() => getTimezoneOptions(), []);
  const names = useChannelNames(status, settings);
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: toForm(personId ?? '', existing ?? defaultPerson()) });
  const errors = form.formState.errors;
  const v = form.watch();
  const fleetZone = settings.locale.time_zone ?? 'UTC';
  const lines = preview(fromForm(v, existing), {
    zone: v.zone || fleetZone,
    fleetQuiet: { from: settings.budget.quiet_from, to: settings.budget.quiet_to },
    channelLabel: names.label,
  });
  const isNew = personId === null;

  async function turnOn() {
    if (!existing || !personId) return setErr(t('routing.device_need_save'));
    setBusyDevice(true);
    const label = (navigator.userAgent.match(/(Firefox|Edg|Chrome|Safari)/)?.[1] ?? 'Browser') + ' · ' + new Date().toISOString().slice(0, 10);
    const r = await turnOnThisDevice(client, personId, label);
    setBusyDevice(false);
    if (r.ok) {
      toast.success(t('routing.device_on'));
      reload();
    } else setErr(t(r.reason === 'denied' ? 'routing.device_denied' : r.reason === 'unsupported' ? 'routing.device_unsupported' : 'routing.device_failed'));
  }

  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent data-testid="routing-sheet">
        <form
          noValidate
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={form.handleSubmit(async (f) => {
            if ((f.quietFrom === '') !== (f.quietTo === '')) return setErr(t('routing.quiet_both'));
            if (isNew && settings.routing.people[f.id]) return setErr(t('routing.person_exists'));
            const msg = await save({ ...settings, routing: { people: { ...settings.routing.people, [f.id]: fromForm(f, existing) } } });
            if (msg) return setErr(msg);
            toast.success(t('routing.saved'));
            onOpenChange(false);
            reload();
          })}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('routing.title_sheet', { person: personId ?? t('routing.add') })}</PanelSheetTitle>
            <PanelSheetDescription>{t('routing.intro')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-5">
            {err ? (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{err}</AlertDescription>
              </Alert>
            ) : null}
            {isNew ? (
              <div className="space-y-1">
                <Label htmlFor="rt-id">{t('routing.person_id')}</Label>
                <Input id="rt-id" autoComplete="off" list="rt-people" className="max-lg:h-11" aria-invalid={!!errors.id} {...form.register('id')} />
                <datalist id="rt-people">
                  {status.people.filter((p) => !settings.routing.people[p.id]).map((p) => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </datalist>
                <p className="text-xs text-muted-foreground">{t('routing.person_id_hint')}</p>
                <FieldError msg={errors.id?.message} />
              </div>
            ) : null}
            <div className="space-y-1">
              <Label htmlFor="rt-zone">{t('routing.zone')}</Label>
              <Combobox id="rt-zone" label={t('routing.zone')} options={zones} value={v.zone} onValueChange={(z) => form.setValue('zone', z)} placeholder={fleetZone} emptyText={t('locale.zone_empty')} />
              <p className="text-xs text-muted-foreground">{t('routing.zone_hint')}</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="rt-qf">{t('routing.quiet_from')}</Label>
                <Input id="rt-qf" autoComplete="off" placeholder={settings.budget.quiet_from} className="max-lg:h-11" aria-invalid={!!errors.quietFrom} {...form.register('quietFrom')} />
                <FieldError msg={errors.quietFrom?.message} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="rt-qt">{t('routing.quiet_to')}</Label>
                <Input id="rt-qt" autoComplete="off" placeholder={settings.budget.quiet_to} className="max-lg:h-11" aria-invalid={!!errors.quietTo} {...form.register('quietTo')} />
                <FieldError msg={errors.quietTo?.message} />
              </div>
            </div>
            <p className="-mt-3 text-xs text-muted-foreground">{t('routing.quiet_hint')}</p>
            <div className="space-y-1">
              <Label htmlFor="rt-phone">{t('routing.phone')}</Label>
              <Input id="rt-phone" type="tel" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.phone} {...form.register('phone')} />
              <p className="text-xs text-muted-foreground">{t('routing.phone_hint')}</p>
              <FieldError msg={errors.phone?.message} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="rt-wa">{t('routing.whatsapp')}</Label>
              <Input id="rt-wa" type="tel" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.whatsapp} {...form.register('whatsapp')} />
              <FieldError msg={errors.whatsapp?.message} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="rt-emails">{t('routing.emails')}</Label>
              <Input id="rt-emails" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.emails} {...form.register('emails')} />
              <FieldError msg={errors.emails?.message} />
            </div>

            <section className="space-y-2">
              <h3 className="text-sm font-semibold">{t('routing.sev_urgent')}</h3>
              <p className="text-xs text-muted-foreground">{t('routing.sev_urgent_hint')}</p>
              <ChannelBoxes legend={t('routing.channels_for', { kind: t('routing.sev_urgent') })} name="urgent" value={v.urgent} onChange={(x) => form.setValue('urgent', x)} names={names} />
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="rt-bypass" checked={v.bypass} onCheckedChange={(c) => form.setValue('bypass', c === true)} />
                <Label htmlFor="rt-bypass">{t('routing.bypass')}</Label>
              </div>
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">{t('routing.sev_normal')}</h3>
              <p className="text-xs text-muted-foreground">{t('routing.sev_normal_hint')}</p>
              <ChannelBoxes legend={t('routing.channels_for', { kind: t('routing.sev_normal') })} name="normal" value={v.normal} onChange={(x) => form.setValue('normal', x)} names={names} />
            </section>
            <section className="space-y-2" data-testid="routing-schedule-rule">
              <h3 className="text-sm font-semibold">{t('routing.schedule_rule')}</h3>
              <p className="text-xs text-muted-foreground">{t('routing.schedule_rule_hint')}</p>
              <Label htmlFor="rt-schedule-rule">{t('routing.schedule_rule_label')}</Label>
              <Select value={v.scheduleRule === '' ? 'default' : v.scheduleRule} onValueChange={(x) => form.setValue('scheduleRule', x === 'default' ? '' : (x as Form['scheduleRule']))}>
                <SelectTrigger id="rt-schedule-rule" className="max-lg:h-11 sm:max-w-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">{t('routing.schedule_rule_default')}</SelectItem>
                  <SelectItem value="urgent">{t('routing.schedule_rule_urgent')}</SelectItem>
                  <SelectItem value="normal">{t('routing.schedule_rule_normal')}</SelectItem>
                  <SelectItem value="off">{t('routing.schedule_rule_off')}</SelectItem>
                </SelectContent>
              </Select>
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">{t('routing.sev_digest')}</h3>
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="rt-digest-on" checked={v.digestOn} onCheckedChange={(c) => form.setValue('digestOn', c === true)} />
                <Label htmlFor="rt-digest-on">{t('routing.digest_on')}</Label>
              </div>
              <div className="space-y-1">
                <Label htmlFor="rt-digest-time">{t('routing.digest_time')}</Label>
                <Input id="rt-digest-time" autoComplete="off" className="max-lg:h-11 sm:max-w-40" aria-invalid={!!errors.digestTime} {...form.register('digestTime')} />
                <p className="text-xs text-muted-foreground">{t('routing.digest_time_hint')}</p>
                <FieldError msg={errors.digestTime?.message} />
              </div>
              <ChannelBoxes legend={t('routing.channels_for', { kind: t('routing.sev_digest') })} name="digest" value={v.digest} onChange={(x) => form.setValue('digest', x)} names={names} />
            </section>

            <section className="space-y-2" data-testid="routing-devices">
              <h3 className="text-sm font-semibold">{t('routing.devices')}</h3>
              {existing && existing.push.length > 0 ? (
                <ul className="space-y-1" aria-label={t('routing.devices')}>
                  {existing.push.map((d) => (
                    <li key={d.id} className="flex items-center justify-between gap-2 text-sm">
                      <span className="min-w-0 truncate">{d.label} <span className="text-xs text-muted-foreground">({d.host})</span></span>
                      <Button type="button" variant="outline" size="sm" className="max-lg:h-11" onClick={async () => { await client.removePushDevice(d.id); reload(); }}>
                        {t('routing.device_remove')}
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted-foreground">{t('routing.devices_none')}</p>
              )}
              <Button type="button" variant="outline" size="sm" className="max-lg:h-11" disabled={busyDevice || isNew} onClick={turnOn}>
                {t('routing.device_this')}
              </Button>
              {isNew ? <p className="text-xs text-muted-foreground">{t('routing.device_need_save')}</p> : null}
            </section>

            <section className="space-y-2" data-testid="routing-chats">
              <h3 className="text-sm font-semibold">{t('routing.chats')}</h3>
              <p className="text-xs text-muted-foreground">{t('routing.chats_hint')}</p>
              {status.telegram.chats.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t('routing.chats_none')}</p>
              ) : (
                <ul className="space-y-1" aria-label={t('routing.chats')}>
                  {status.telegram.chats.map((c) => {
                    const other = c.person && c.person !== personId && settings.routing.people[c.person] ? c.person : null;
                    const box = `rt-chat-${c.id}`;
                    return (
                      <li key={c.id} className="flex min-h-11 items-center gap-3 lg:min-h-8">
                        <TouchCheckbox
                          id={box}
                          checked={c.person === personId}
                          disabled={isNew}
                          onCheckedChange={async (on) => {
                            if (!personId) return;
                            try {
                              await client.linkChat(c.id, on === true ? personId : null);
                              reload();
                            } catch {
                              setErr(t('routing.chat_link_failed'));
                            }
                          }}
                        />
                        <Label htmlFor={box} className="text-sm">
                          {other ? t('routing.chat_linked_other', { name: c.name, person: status.people.find((x) => x.id === other)?.label ?? other }) : c.name}
                        </Label>
                      </li>
                    );
                  })}
                </ul>
              )}
              <Button asChild variant="outline" size="sm" className="max-lg:h-11" disabled={isNew || !status.telegram.configured}>
                <a href="/account" data-testid="routing-chat-link-account">{t('routing.chat_pair')}</a>
              </Button>
            </section>

            <section className="space-y-1 rounded-md border bg-muted/40 p-3" aria-live="polite" data-testid="routing-preview">
              <h3 className="text-sm font-semibold">{t('routing.preview_title')}</h3>
              {lines.map((l) => (
                <p key={l} className="text-sm">{l}</p>
              ))}
            </section>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={form.formState.isSubmitting}>
              {t('common.save')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

export function RoutingSection(props: Props) {
  const { settings, status } = props;
  const [edit, setEdit] = useState<{ id: string | null } | null>(null);
  const [remove, setRemove] = useState<string | null>(null);
  const names = useChannelNames(status, settings);
  const people = Object.entries(settings.routing.people);
  return (
    <Card className="space-y-3 p-4" data-testid="routing-section">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('routing.title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setEdit({ id: null })}>
          {t('routing.add')}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('routing.intro')}</p>
      {people.length === 0 ? (
        <p className="text-sm">{t('routing.none')}</p>
      ) : (
        <ul className="space-y-2" aria-label={t('routing.title')}>
          {people.map(([id, p]) => (
            <li key={id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3" data-testid={`routing-person-${id}`}>
              <div className="min-w-0 space-y-1">
                <p className="truncate text-sm font-medium">{status.people.find((x) => x.id === id)?.label ?? id}</p>
                <p className="text-xs text-muted-foreground">
                  {t('routing.summary_row', { count: p.urgent.channels.length, normal: p.normal.channels.length })}
                </p>
                <div className="flex flex-wrap gap-1">
                  {p.urgent.channels.map((c) => (
                    <Badge key={c} variant="outline">{names.label(c)}</Badge>
                  ))}
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setEdit({ id })}>
                  {t('routing.edit')}
                </Button>
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(id)}>
                  {t('routing.remove_person')}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {edit ? <PersonSheet key={edit.id ?? 'new'} {...props} open onOpenChange={(o) => !o && setEdit(null)} personId={edit.id} /> : null}
      <ConfirmDialog
        open={remove !== null}
        onOpenChange={(o) => !o && setRemove(null)}
        title={t('routing.remove_title')}
        description={t('routing.remove_body')}
        confirmLabel={t('apps.remove')}
        destructive
        onConfirm={async () => {
          if (!remove) return;
          const rest = Object.fromEntries(Object.entries(settings.routing.people).filter(([k]) => k !== remove));
          const msg = await props.save({ ...settings, routing: { people: rest } });
          if (msg) toast.error(msg);
          props.reload();
        }}
      />
    </Card>
  );
}
