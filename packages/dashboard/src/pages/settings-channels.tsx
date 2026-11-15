import { useState, type ReactNode } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { z } from 'zod';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import type { EmailProvider, SmsProvider, SmtpSecurity } from '../api/channel-types';
import type { AppsStatus, Settings } from '../api/types';
import { SecretField } from '../components/secret-field';
import { ChannelGuide, type GuideChannel } from '../components/setup/channel-guide';
import type { MessageKey } from '../lib/i18n';
import { t } from '../lib/i18n';
import { ChannelCard, EnableToggle, FieldError, SecretSheet, StatusBadge, useChannelTest, useRemoveChannel, useSecretSave } from './settings-apps';

interface CardProps {
  status: AppsStatus;
  settings: Settings;
  save: (s: Settings) => Promise<string | null>;
  reload: () => void;
}

const ADDRESS = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;
const E164 = /^\+[1-9]\d{6,14}$/;

function ErrorNote({ err }: { err: string | null }) {
  return err ? (
    <Alert variant="destructive" role="alert">
      <AlertDescription>{err}</AlertDescription>
    </Alert>
  ) : null;
}

function Labelled({ id, label, hint, error, children }: { id: string; label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
      <FieldError msg={error} />
    </div>
  );
}

function SheetFooter({ onCancel, busy }: { onCancel: () => void; busy: boolean }) {
  return (
    <PanelSheetFooter>
      <Button type="button" variant="outline" onClick={onCancel}>
        {t('common.cancel')}
      </Button>
      <Button type="submit" disabled={busy}>
        {t('common.save')}
      </Button>
    </PanelSheetFooter>
  );
}

// ---------- Email ----------

const EMAIL_PROVIDERS: EmailProvider[] = ['resend', 'postmark', 'sendgrid', 'ses', 'smtp'];
const emailName = (p: EmailProvider) => t(`em.p_${p}` as MessageKey);
const emailKeyLabel = (p: EmailProvider) => (p === 'postmark' ? t('em.key_postmark') : p === 'sendgrid' ? t('em.key_sendgrid') : t('apps.email_key'));

const emailSchema = z.object({
  enabled: z.boolean(),
  provider: z.enum(['resend', 'smtp', 'ses', 'postmark', 'sendgrid']),
  from: z.string().trim().refine((v) => v === '' || ADDRESS.test(v), t('apps.email_bad_address')),
  to: z.string().refine((v) => v.split(',').map((x) => x.trim()).filter(Boolean).every((a) => ADDRESS.test(a)), t('apps.email_bad_address')),
  replyTo: z.string().trim().refine((v) => v === '' || ADDRESS.test(v), t('apps.email_bad_address')),
  unsub: z.string().refine((v) => v.split(',').map((x) => x.trim()).filter(Boolean).every((a) => ADDRESS.test(a)), t('apps.email_bad_address')),
  apiKey: z.string(),
  region: z.string().trim().refine((v) => v === '' || /^[a-z0-9-]{1,20}$/.test(v), t('sms.region_hint')),
  smtpHost: z.string().trim(),
  smtpPort: z.string().refine((v) => v === '' || (/^\d{1,5}$/.test(v) && Number(v) > 0 && Number(v) < 65536), t('em.smtp_port')),
  smtpSecurity: z.enum(['tls', 'starttls']),
  smtpUser: z.string().trim(),
  smtpPassword: z.string(),
});
type EmailForm = z.infer<typeof emailSchema>;

export function EmailCard({ status, settings, save, reload }: CardProps) {
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const putSecret = useSecretSave(reload);
  const test = useChannelTest();
  const e = settings.apps.email;
  const defaults = (): EmailForm => ({
    enabled: e.enabled,
    provider: e.provider,
    from: e.from,
    to: e.to.join(', '),
    replyTo: e.reply_to,
    unsub: e.unsubscribed.join(', '),
    apiKey: '',
    region: e.region ?? '',
    smtpHost: e.smtp.host,
    smtpPort: e.smtp.port ? String(e.smtp.port) : '',
    smtpSecurity: e.smtp.security,
    smtpUser: e.smtp.username,
    smtpPassword: '',
  });
  const form = useForm<EmailForm>({ resolver: zodResolver(emailSchema), defaultValues: defaults() });
  const errors = form.formState.errors;
  const provider = form.watch('provider');
  const guide = `email_${provider}` as GuideChannel;
  return (
    <ChannelCard
      id="email"
      title={t('apps.email_title')}
      status={<StatusBadge enabled={status.email.enabled} configured={status.email.configured} />}
      actions={
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { form.reset(defaults()); setErr(null); setOpen(true); }}>
            {status.email.configured ? t('common.edit') : t('apps.set_up')}
          </Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!status.email.configured || test.busy === 'email'} onClick={() => test.run('email', reload)}>
            {t('apps.send_test')}
          </Button>
        </>
      }
    >
      <p className="text-xs text-muted-foreground">{t('em.help')}</p>
      <p className="text-xs">{emailName(status.email.provider)}</p>
      <ChannelGuide channel={guide} />
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="email-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={form.handleSubmit(async (v) => {
              if (v.provider === 'smtp' && !/^[A-Za-z0-9.-]{1,253}$/.test(v.smtpHost)) return setErr(t('em.bad_host'));
              const to = v.to.split(',').map((x) => x.trim()).filter(Boolean);
              const next = {
                ...e,
                enabled: v.enabled,
                provider: v.provider,
                from: v.from,
                to,
                reply_to: v.replyTo,
                unsubscribed: v.unsub.split(',').map((x) => x.trim()).filter(Boolean),
                region: v.provider === 'ses' && v.region ? v.region : null,
                smtp: { host: v.smtpHost, port: v.smtpPort ? Number(v.smtpPort) : 0, security: v.smtpSecurity as SmtpSecurity, username: v.smtpUser },
              };
              // The key first, then the settings that use it: if the key is refused nothing else changed, and if the
              // settings are refused afterwards the channel is as it was (a stored key alone sends nothing).
              const secret = v.provider === 'smtp' ? { name: 'smtp-password', value: v.smtpPassword } : { name: 'email-api-key', value: v.apiKey };
              if (secret.value && v.provider !== 'ses') {
                const m2 = await putSecret(secret.name, secret.value);
                if (m2) return setErr(m2);
              }
              const msg = await save({ ...settings, apps: { ...settings.apps, email: next } });
              if (msg) return setErr(secret.value && v.provider !== 'ses' ? t('apps.key_saved_settings_not', { why: msg }) : msg);
              form.setValue('apiKey', '');
              form.setValue('smtpPassword', '');
              toast.success(t('apps.saved'));
              setOpen(false);
            })}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('apps.email_title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('apps.secret_where', { store: status.store })}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              <ErrorNote err={err} />
              <Labelled id="em-provider" label={t('em.provider')}>
                <Select value={provider} onValueChange={(v) => form.setValue('provider', v as EmailProvider)}>
                  <SelectTrigger id="em-provider" className="max-lg:h-11">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EMAIL_PROVIDERS.map((p) => (
                      <SelectItem key={p} value={p} className="max-lg:min-h-11">
                        {emailName(p)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Labelled>
              <Labelled id="em-from" label={t('apps.email_from')} error={errors.from?.message}>
                <Input id="em-from" type="email" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.from} {...form.register('from')} />
              </Labelled>
              <Labelled id="em-to" label={t('apps.email_to')} error={errors.to?.message}>
                <Input id="em-to" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.to} {...form.register('to')} />
              </Labelled>
              <Labelled id="em-reply" label={t('em.reply_to')} error={errors.replyTo?.message}>
                <Input id="em-reply" type="email" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.replyTo} {...form.register('replyTo')} />
              </Labelled>
              <Labelled id="em-unsub" label={t('em.unsub')} hint={t('em.unsub_hint')} error={errors.unsub?.message}>
                <Input id="em-unsub" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.unsub} {...form.register('unsub')} />
              </Labelled>
              {provider === 'smtp' ? (
                <>
                  <Labelled id="em-host" label={t('em.smtp_host')} hint={t('em.smtp_host_hint')}>
                    <Input id="em-host" autoComplete="off" className="max-lg:h-11" {...form.register('smtpHost')} />
                  </Labelled>
                  <Labelled id="em-sec" label={t('em.smtp_security')}>
                    <Select value={form.watch('smtpSecurity')} onValueChange={(v) => form.setValue('smtpSecurity', v as SmtpSecurity)}>
                      <SelectTrigger id="em-sec" className="max-lg:h-11">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="starttls" className="max-lg:min-h-11">{t('em.smtp_starttls')}</SelectItem>
                        <SelectItem value="tls" className="max-lg:min-h-11">{t('em.smtp_tls')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </Labelled>
                  <Labelled id="em-port" label={t('em.smtp_port')} error={errors.smtpPort?.message}>
                    <Input id="em-port" inputMode="numeric" autoComplete="off" className="max-lg:h-11" {...form.register('smtpPort')} />
                  </Labelled>
                  <Labelled id="em-user" label={t('em.smtp_user')}>
                    <Input id="em-user" autoComplete="off" className="max-lg:h-11" {...form.register('smtpUser')} />
                  </Labelled>
                  <SecretField id="em-pass" label={t('em.smtp_password')} hint={status.email.configured ? t('apps.secret_keep') : t('em.smtp_password_hint')} {...form.register('smtpPassword')} />
                  <p className="text-xs text-muted-foreground">{t('em.smtp_note')}</p>
                </>
              ) : null}
              {provider === 'ses' ? (
                <>
                  <p className="text-xs text-muted-foreground">{t('em.ses_note')}</p>
                  <Labelled id="em-region" label={t('em.ses_region')} error={errors.region?.message}>
                    <Input id="em-region" autoComplete="off" className="max-lg:h-11" {...form.register('region')} />
                  </Labelled>
                </>
              ) : null}
              {provider === 'resend' || provider === 'postmark' || provider === 'sendgrid' ? (
                <SecretField id="em-key" label={emailKeyLabel(provider)} hint={status.email.configured ? t('apps.secret_keep') : t('apps.email_key_hint')} {...form.register('apiKey')} />
              ) : null}
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="em-on" checked={form.watch('enabled')} onCheckedChange={(c) => form.setValue('enabled', c === true)} />
                <Label htmlFor="em-on">{t('apps.send_alerts_here')}</Label>
              </div>
              <p className="text-xs text-muted-foreground">{t('ch.recipient_note')}</p>
            </PanelSheetBody>
            <SheetFooter onCancel={() => setOpen(false)} busy={form.formState.isSubmitting} />
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </ChannelCard>
  );
}

// ---------- SMS ----------

const SMS_PROVIDERS: SmsProvider[] = ['twilio', 'vonage', 'sns', 'africas_talking', 'telnyx'];
const smsName = (p: SmsProvider) => t(`sms.p_${p}` as MessageKey);
const smsAccountLabel = (p: SmsProvider): string | null => (p === 'sns' || p === 'telnyx' ? null : t(`sms.account_${p}` as MessageKey));
const smsSecretLabel = (p: SmsProvider): string | null => (p === 'sns' ? null : t(`sms.secret_${p}` as MessageKey));

const smsSchema = z.object({
  provider: z.enum(['twilio', 'vonage', 'sns', 'africas_talking', 'telnyx']),
  from: z.string().trim().refine((v) => v === '' || E164.test(v) || /^[A-Za-z0-9]{1,11}$/.test(v) || /^MG[0-9a-f]{32}$/i.test(v), t('sms.bad_from')),
  region: z.string().trim().refine((v) => v === '' || /^[a-z0-9-]{1,20}$/.test(v), t('sms.region_hint')),
  sandbox: z.boolean(),
  account: z.string(),
  secret: z.string(),
});
type SmsForm = z.infer<typeof smsSchema>;

export function SmsCard({ status, settings, save, reload }: CardProps) {
  const removeChannel = useRemoveChannel(reload);
  const [open, setOpen] = useState(false);
  const [remove, setRemove] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const putSecret = useSecretSave(reload);
  const test = useChannelTest();
  const c = settings.apps.sms;
  const defaults = (): SmsForm => ({ provider: c.provider, from: c.from, region: c.region ?? '', sandbox: c.sandbox, account: '', secret: '' });
  const form = useForm<SmsForm>({ resolver: zodResolver(smsSchema), defaultValues: defaults() });
  const errors = form.formState.errors;
  const provider = form.watch('provider');
  const accountLabel = smsAccountLabel(provider);
  const secretLabel = smsSecretLabel(provider);
  return (
    <ChannelCard
      id="sms"
      title={t('sms.title')}
      status={<StatusBadge enabled={status.sms.enabled} configured={status.sms.configured} />}
      actions={
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { form.reset(defaults()); setErr(null); setOpen(true); }}>
            {status.sms.configured ? t('common.edit') : t('apps.set_up')}
          </Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!status.sms.configured || test.busy === 'sms'} onClick={() => test.run('sms', reload)}>
            {t('apps.send_test')}
          </Button>
          {status.sms.configured ? (
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(true)}>
              {t('apps.remove')}
            </Button>
          ) : null}
        </>
      }
    >
      <p className="text-xs text-muted-foreground">{t('sms.help')}</p>
      <p className="text-xs">{smsName(status.sms.provider)}</p>
      <ChannelGuide channel={`sms_${c.provider}` as GuideChannel} />
      <EnableToggle id="sms-on" checked={c.enabled} disabled={!status.sms.configured} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, sms: { ...c, enabled: v } } }); if (m) toast.error(m); else reload(); }} />
      <p className="text-xs text-muted-foreground">{t('ch.recipient_note')}</p>
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="sms-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={form.handleSubmit(async (v) => {
              let keySaved = false;
              for (const [name, value] of [['sms-account', v.account], ['sms-secret', v.secret]] as const) {
                if (!value) continue;
                const m2 = await putSecret(name, value);
                if (m2) return setErr(keySaved ? t('apps.key_saved_settings_not', { why: m2 }) : m2);
                keySaved = true;
              }
              const msg = await save({ ...settings, apps: { ...settings.apps, sms: { ...c, provider: v.provider, from: v.from, region: v.provider === 'sns' && v.region ? v.region : null, sandbox: v.provider === 'africas_talking' && v.sandbox } } });
              if (msg) return setErr(keySaved ? t('apps.key_saved_settings_not', { why: msg }) : msg);
              form.setValue('account', '');
              form.setValue('secret', '');
              toast.success(t('apps.saved'));
              setOpen(false);
            })}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('sms.title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('apps.secret_where', { store: status.store })}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              <ErrorNote err={err} />
              <Labelled id="sms-provider" label={t('sms.provider')}>
                <Select value={provider} onValueChange={(v) => form.setValue('provider', v as SmsProvider)}>
                  <SelectTrigger id="sms-provider" className="max-lg:h-11">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SMS_PROVIDERS.map((p) => (
                      <SelectItem key={p} value={p} className="max-lg:min-h-11">
                        {smsName(p)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Labelled>
              <ChannelGuide channel={`sms_${provider}` as GuideChannel} />
              <Labelled id="sms-from" label={t('sms.from')} hint={t('sms.from_hint')} error={errors.from?.message}>
                <Input id="sms-from" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.from} {...form.register('from')} />
              </Labelled>
              {provider === 'sns' ? (
                <>
                  <p className="text-xs text-muted-foreground">{t('sms.sns_note')}</p>
                  <Labelled id="sms-region" label={t('sms.region')} hint={t('sms.region_hint')} error={errors.region?.message}>
                    <Input id="sms-region" autoComplete="off" className="max-lg:h-11" {...form.register('region')} />
                  </Labelled>
                </>
              ) : null}
              {accountLabel ? <SecretField id="sms-account" label={accountLabel} hint={status.sms.configured ? t('apps.secret_keep') : t('apps.email_key_hint')} {...form.register('account')} /> : null}
              {secretLabel ? <SecretField id="sms-secret" label={secretLabel} hint={status.sms.configured ? t('apps.secret_keep') : t('apps.email_key_hint')} {...form.register('secret')} /> : null}
              {provider === 'africas_talking' ? (
                <div className="flex min-h-11 items-center gap-3">
                  <TouchCheckbox id="sms-sandbox" checked={form.watch('sandbox')} onCheckedChange={(c2) => form.setValue('sandbox', c2 === true)} />
                  <Label htmlFor="sms-sandbox">{t('sms.sandbox')}</Label>
                </div>
              ) : null}
            </PanelSheetBody>
            <SheetFooter onCancel={() => setOpen(false)} busy={form.formState.isSubmitting} />
          </form>
        </PanelSheetContent>
      </PanelSheet>
      <ConfirmDialog
        open={remove}
        onOpenChange={setRemove}
        title={t('sms.remove_title')}
        description={t('sms.remove_body')}
        confirmLabel={t('apps.remove')}
        destructive
        onConfirm={() =>
          removeChannel(
            [
              { name: 'sms-account', label: t('sms.account_label') },
              { name: 'sms-secret', label: t('sms.secret_label') },
            ],
            () => save({ ...settings, apps: { ...settings.apps, sms: { ...c, enabled: false } } }),
          )
        }
      />
    </ChannelCard>
  );
}

// ---------- WhatsApp ----------

const whatsappSchema = z.object({
  phoneId: z.string().trim().refine((v) => v === '' || /^\d{1,24}$/.test(v), t('wa.bad_id')),
  template: z.string().trim().refine((v) => v === '' || /^[a-z0-9_]{1,512}$/.test(v), t('wa.bad_template')),
  language: z.string().trim().refine((v) => v === '' || /^[A-Za-z_]{2,8}$/.test(v), t('wa.bad_language')),
  token: z.string(),
});
type WhatsappForm = z.infer<typeof whatsappSchema>;

export function WhatsappCard({ status, settings, save, reload }: CardProps) {
  const removeChannel = useRemoveChannel(reload);
  const [open, setOpen] = useState(false);
  const [remove, setRemove] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const putSecret = useSecretSave(reload);
  const test = useChannelTest();
  const w = settings.apps.whatsapp;
  const defaults = (): WhatsappForm => ({ phoneId: w.phone_number_id, template: w.template, language: w.language || 'en_US', token: '' });
  const form = useForm<WhatsappForm>({ resolver: zodResolver(whatsappSchema), defaultValues: defaults() });
  const errors = form.formState.errors;
  return (
    <ChannelCard
      id="whatsapp"
      title={t('wa.title')}
      status={<StatusBadge enabled={status.whatsapp.enabled} configured={status.whatsapp.configured} />}
      actions={
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { form.reset(defaults()); setErr(null); setOpen(true); }}>
            {status.whatsapp.configured ? t('common.edit') : t('apps.set_up')}
          </Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!status.whatsapp.configured || test.busy === 'whatsapp'} onClick={() => test.run('whatsapp', reload)}>
            {t('apps.send_test')}
          </Button>
          {status.whatsapp.configured ? (
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(true)}>
              {t('apps.remove')}
            </Button>
          ) : null}
        </>
      }
    >
      <p className="text-xs text-muted-foreground">{t('wa.help')}</p>
      <ChannelGuide channel="whatsapp" />
      <EnableToggle id="wa-on" checked={w.enabled} disabled={!status.whatsapp.configured} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, whatsapp: { ...w, enabled: v } } }); if (m) toast.error(m); else reload(); }} />
      <p className="text-xs text-muted-foreground">{t('ch.recipient_note')}</p>
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="whatsapp-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={form.handleSubmit(async (v) => {
              if (v.token) {
                const m2 = await putSecret('whatsapp-token', v.token);
                if (m2) return setErr(m2);
              }
              const msg = await save({ ...settings, apps: { ...settings.apps, whatsapp: { ...w, phone_number_id: v.phoneId, template: v.template, language: v.language } } });
              if (msg) return setErr(v.token ? t('apps.key_saved_settings_not', { why: msg }) : msg);
              form.setValue('token', '');
              toast.success(t('apps.saved'));
              setOpen(false);
            })}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('wa.title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('apps.secret_where', { store: status.store })}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              <ErrorNote err={err} />
              <Labelled id="wa-id" label={t('wa.phone_id')} hint={t('wa.phone_id_hint')} error={errors.phoneId?.message}>
                <Input id="wa-id" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.phoneId} {...form.register('phoneId')} />
              </Labelled>
              <Labelled id="wa-template" label={t('wa.template')} hint={t('wa.template_hint')} error={errors.template?.message}>
                <Input id="wa-template" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.template} {...form.register('template')} />
              </Labelled>
              <Labelled id="wa-lang" label={t('wa.language')} hint={t('wa.language_hint')} error={errors.language?.message}>
                <Input id="wa-lang" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.language} {...form.register('language')} />
              </Labelled>
              <SecretField id="wa-token" label={t('wa.token')} hint={status.whatsapp.configured ? t('apps.secret_keep') : t('wa.token_hint')} {...form.register('token')} />
            </PanelSheetBody>
            <SheetFooter onCancel={() => setOpen(false)} busy={form.formState.isSubmitting} />
          </form>
        </PanelSheetContent>
      </PanelSheet>
      <ConfirmDialog
        open={remove}
        onOpenChange={setRemove}
        title={t('wa.remove_title')}
        description={t('wa.remove_body')}
        confirmLabel={t('apps.remove')}
        destructive
        onConfirm={() => removeChannel([{ name: 'whatsapp-token', label: t('wa.token') }], () => save({ ...settings, apps: { ...settings.apps, whatsapp: { ...w, enabled: false } } }))}
      />
    </ChannelCard>
  );
}

// ---------- Discord and Teams ----------

export function WebhookUrlCard({ kind, status, settings, save, reload }: CardProps & { kind: 'discord' | 'teams' }) {
  const removeChannel = useRemoveChannel(reload);
  const [open, setOpen] = useState(false);
  const [remove, setRemove] = useState(false);
  const test = useChannelTest();
  const st = status[kind];
  const secretName = `${kind}-webhook-url`;
  return (
    <ChannelCard
      id={kind}
      title={t(`${kind}.title` as MessageKey)}
      status={<StatusBadge enabled={st.enabled} configured={st.configured} />}
      actions={
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setOpen(true)}>
            {st.configured ? t('apps.replace_address') : t('apps.set_up')}
          </Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!st.configured || test.busy === kind} onClick={() => test.run(kind, reload)}>
            {t('apps.send_test')}
          </Button>
          {st.configured ? (
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(true)}>
              {t('apps.remove')}
            </Button>
          ) : null}
        </>
      }
    >
      <p className="text-xs text-muted-foreground">{t(`${kind}.help` as MessageKey)}</p>
      <ChannelGuide channel={kind} />
      <EnableToggle id={`${kind}-on`} checked={settings.apps[kind].enabled} disabled={!st.configured} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, [kind]: { enabled: v } } }); if (m) toast.error(m); else reload(); }} />
      <p className="text-xs text-muted-foreground">{t('ch.recipient_note')}</p>
      <SecretSheet open={open} onOpenChange={setOpen} title={t(`${kind}.title` as MessageKey)} description={t('apps.secret_where', { store: status.store })} label={t(`${kind}.label` as MessageKey)} hint={t(`${kind}.hint` as MessageKey)} name={secretName} testid={`${kind}-sheet`} onSaved={reload} />
      <ConfirmDialog
        open={remove}
        onOpenChange={setRemove}
        title={t(`${kind}.remove_title` as MessageKey)}
        description={t(`${kind}.remove_body` as MessageKey)}
        confirmLabel={t('apps.remove')}
        destructive
        onConfirm={() => removeChannel([{ name: secretName, label: t(`${kind}.label` as MessageKey) }], () => save({ ...settings, apps: { ...settings.apps, [kind]: { enabled: false } } }))}
      />
    </ChannelCard>
  );
}

// ---------- Push ----------

export function PushCard({ status, settings, save, reload }: CardProps) {
  const test = useChannelTest();
  const p = status.push;
  return (
    <ChannelCard
      id="push"
      title={t('push.title')}
      status={<StatusBadge enabled={p.enabled && p.devices > 0} configured={p.devices > 0} />}
      actions={
        <Button variant="outline" size="sm" className="max-lg:h-11" disabled={p.devices === 0 || test.busy === 'push'} onClick={() => test.run('push', reload)}>
          {t('apps.send_test')}
        </Button>
      }
    >
      <p className="text-xs text-muted-foreground">{t('push.help')}</p>
      <p className="text-xs" data-testid="push-devices">{t('push.devices', { count: p.devices })}</p>
      <ChannelGuide channel="push" />
      <EnableToggle id="push-on" checked={settings.apps.push.enabled} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, push: { enabled: v } } }); if (m) toast.error(m); else reload(); }} />
      <p className="text-xs text-muted-foreground">{t('ch.recipient_note')}</p>
    </ChannelCard>
  );
}
