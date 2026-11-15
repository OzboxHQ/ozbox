import { useEffect, useRef, useState, type ReactNode } from 'react';
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
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/client';
import type { AppsStatus, RecentAlert, Settings } from '../api/types';
import { useApp } from '../App';
import { SecretField } from '../components/secret-field';
import { ChannelGuide } from '../components/setup/channel-guide';
import { formatWithUtc, windowWithUtc } from '../lib/locale';
import { t } from '../lib/i18n';
import { allSent, runTestSend } from '../lib/test-send';
import { testSendStore } from '../lib/test-send-store';
import { useAsync } from '../lib/use-async';
import { useSettings } from '../lib/use-settings';
import { OutcomeBlock, SummarySheet, TestResults } from './settings-alerts';
import { EmailCard, PushCard, SmsCard, WebhookUrlCard, WhatsappCard } from './settings-channels';
import { RoutingSection } from './settings-routing';

export const errorText = (e: unknown) => (e instanceof ApiError ? e.message : t('common.request_failed'));

export function FieldError({ msg }: { msg?: string }) {
  return msg ? (
    <p role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

export function StatusBadge({ enabled, configured }: { enabled: boolean; configured: boolean }) {
  if (!configured) return <Badge variant="outline">{t('apps.not_connected')}</Badge>;
  return <Badge variant={enabled ? 'default' : 'outline'}>{enabled ? t('apps.connected') : t('apps.connected_off')}</Badge>;
}

export function ChannelCard({ id, title, status, children, actions }: { id: string; title: string; status: ReactNode; children?: ReactNode; actions: ReactNode }) {
  return (
    <Card className="space-y-3 p-4" data-testid={`app-${id}`}>
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        {status}
      </div>
      {children}
      <TestResults channel={id} />
      <div className="flex flex-wrap gap-2">{actions}</div>
    </Card>
  );
}

export function useChannelTest() {
  const { client } = useApp();
  const [busy, setBusy] = useState<string | null>(null);
  /** Starts the test and follows it: each channel shows on its card as pending, then sent or failed with the reason. */
  async function run(channel: string, after: () => void) {
    setBusy(channel);
    try {
      const { run: r, timedOut } = await runTestSend(client, channel, (x) => testSendStore.set(channel, x));
      testSendStore.set(channel, r, timedOut);
      if (!timedOut) {
        if (allSent(r)) toast.success(t('apps.test_sent'));
        else toast.error(t('apps.test_failed', { detail: r.items.find((i) => i.status === 'failed')?.detail ?? '' }));
      }
    } catch (e) {
      testSendStore.clear(channel);
      toast.error(errorText(e));
    } finally {
      setBusy(null);
      after();
    }
  }
  return { busy, run };
}

/** Saves the typed secret, then forgets it. The value never comes back from the server. */
export function useSecretSave(reload: () => void) {
  const { client } = useApp();
  return async (name: string, value: string): Promise<string | null> => {
    try {
      await client.putSecret(name, value);
      reload();
      return null;
    } catch (e) {
      return errorText(e);
    }
  };
}

/**
 * Removing a channel is two calls (turn it off, delete its stored keys), so it is done in the order that never leaves a
 * channel sending without its key: off first, then the keys one by one. A failure is said, in words, with what is still
 * stored, and thrown so the confirm dialog stays open and Remove can be chosen again (both steps are safe to repeat). A key
 * that was never stored (404) is not a failure.
 */
export function useRemoveChannel(reload: () => void) {
  const { client } = useApp();
  return async (keys: { name: string; label: string }[], turnOff: () => Promise<string | null>): Promise<void> => {
    const off = await turnOff();
    if (off) {
      const m = t('apps.remove_off_failed', { why: off });
      toast.error(m);
      throw new Error(m);
    }
    const left: string[] = [];
    for (const k of keys) {
      try {
        await client.deleteSecret(k.name);
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 404)) left.push(k.label);
      }
    }
    reload();
    if (left.length > 0) {
      const m = t('apps.remove_partial', { names: left.join(', ') });
      toast.error(m);
      throw new Error(m);
    }
  };
}

/** Run a confirmed change; if it fails, say why (the confirm dialog stays open on a throw, with no message of its own). */
export async function sayIfFails(run: () => Promise<unknown>): Promise<void> {
  try {
    await run();
  } catch (e) {
    toast.error(errorText(e));
    throw e;
  }
}

export function EnableToggle({ id, checked, disabled, onChange }: { id: string; checked: boolean; disabled?: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex min-h-11 items-center gap-3">
      <TouchCheckbox id={id} checked={checked} disabled={disabled} onCheckedChange={(c) => onChange(c === true)} />
      <Label htmlFor={id}>{t('apps.send_alerts_here')}</Label>
    </div>
  );
}

const secretSchema = z.object({ value: z.string().min(1, t('apps.secret_required')) });
type SecretForm = z.infer<typeof secretSchema>;

/** One write-only value in its own sheet: Telegram's bot token, Slack's webhook address. */
export function SecretSheet({ open, onOpenChange, title, description, label, hint, name, testid, onSaved }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description: string; label: string; hint: string; name: string; testid: string; onSaved: () => void }) {
  const [err, setErr] = useState<string | null>(null);
  const putSecret = useSecretSave(onSaved);
  const form = useForm<SecretForm>({ resolver: zodResolver(secretSchema), defaultValues: { value: '' } });
  return (
    <PanelSheet open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) form.reset({ value: '' }); }}>
      <PanelSheetContent size="compact" data-testid={testid}>
        <form
          noValidate
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={form.handleSubmit(async (v) => {
            const m = await putSecret(name, v.value);
            if (m) return setErr(m);
            form.reset({ value: '' });
            setErr(null);
            toast.success(t('apps.saved'));
            onOpenChange(false);
          })}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{title}</PanelSheetTitle>
            <PanelSheetDescription>{description}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
            <SecretField id={`${testid}-value`} label={label} hint={hint} aria-invalid={!!form.formState.errors.value} {...form.register('value')} />
            <FieldError msg={form.formState.errors.value?.message} />
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

export function PairingSheet({ open, onOpenChange, status, reload, person }: { open: boolean; onOpenChange: (o: boolean) => void; status: AppsStatus; reload: () => void; person?: string }) {
  const { client } = useApp();
  const [code, setCode] = useState<{ code: string; bot: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const chats = status.telegram.chats.length;
  const startRef = useRef(chats);
  useEffect(() => {
    if (!open) return;
    setErr(null);
    setCode(null);
    startRef.current = chats;
    client.startPairing(undefined, person).then((c) => setCode({ code: c.code, bot: c.bot })).catch((e: unknown) => setErr(errorText(e)));
    const id = window.setInterval(reload, 3000);
    return () => window.clearInterval(id);
  }, [open, client, person]);
  useEffect(() => {
    if (open && chats > startRef.current) {
      toast.success(t('apps.paired'));
      onOpenChange(false);
    }
  }, [chats]);
  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent size="compact" data-testid="pairing-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('apps.pair_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('apps.pair_help')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          {code ? (
            <>
              <p className="text-sm">{t('apps.pair_send', { bot: code.bot })}</p>
              <div role="group" aria-label={t('apps.pair_code_label')}>
                <p className="rounded-md border bg-muted p-4 text-center font-mono text-2xl tracking-widest" data-testid="pairing-code">{code.code}</p>
              </div>
              <p className="text-xs text-muted-foreground">{t('apps.pair_expiry')}</p>
            </>
          ) : err ? null : (
            <Skeleton className="h-16 w-full" />
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>{t('common.close')}</Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function TelegramCard({ status, settings, save, reload }: { status: AppsStatus; settings: Settings; save: (s: Settings) => Promise<string | null>; reload: () => void }) {
  const { client } = useApp();
  const removeChannel = useRemoveChannel(reload);
  const [tokenOpen, setTokenOpen] = useState(false);
  const [pairOpen, setPairOpen] = useState(false);
  const [removeToken, setRemoveToken] = useState(false);
  const [unpair, setUnpair] = useState<number | null>(null);
  const test = useChannelTest();
  const tg = status.telegram;
  return (
    <ChannelCard
      id="telegram"
      title={t('apps.telegram_title')}
      status={<StatusBadge enabled={tg.enabled && tg.chats.length > 0} configured={tg.configured} />}
      actions={
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setTokenOpen(true)}>{tg.configured ? t('apps.replace_token') : t('apps.add_token')}</Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!tg.configured} onClick={() => setPairOpen(true)}>{t('apps.pair_chat')}</Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={tg.chats.length === 0 || test.busy === 'telegram'} onClick={() => test.run('telegram', reload)}>{t('apps.send_test')}</Button>
          {tg.configured ? <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemoveToken(true)}>{t('apps.remove_token')}</Button> : null}
        </>
      }
    >
      {tg.demo ? (
        <div role="status" data-testid="telegram-demo-note" className="flex flex-wrap items-center gap-2 rounded-md border border-amber-600/50 bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:border-amber-400/50 dark:bg-amber-950/40 dark:text-amber-100">
          <Badge variant="outline" data-testid="telegram-demo-badge">{t('source.simulated')}</Badge>
          <span className="min-w-0 flex-1 break-words">{t('apps.tg_demo')}</span>
        </div>
      ) : null}
      <p className="text-xs text-muted-foreground" data-testid="telegram-notify-only">{t('apps.notify_only')}</p>
      <ol className="list-decimal space-y-1 pl-5 text-xs text-muted-foreground">
        <li>{t('apps.tg_step1')}</li>
        <li>{t('apps.tg_step2')}</li>
        <li>{t('apps.tg_step3')}</li>
        <li>{t('apps.tg_step4')}</li>
      </ol>
      <EnableToggle id="tg-on" checked={settings.apps.telegram.enabled} disabled={!tg.configured} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, telegram: { enabled: v } } }); if (m) toast.error(m); else reload(); }} />
      <div>
        <h3 className="text-xs font-medium">{t('apps.paired_chats')}</h3>
        {tg.chats.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t('apps.no_paired_chats')}</p>
        ) : (
          <ul className="mt-1 space-y-1" aria-label={t('apps.paired_chats')}>
            {tg.chats.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-2 text-sm">
                <span className="min-w-0 truncate">
                  {c.name}
                  <span className="block text-xs text-muted-foreground">{c.person ? t('apps.chat_linked', { person: status.people.find((x) => x.id === c.person)?.label ?? c.person }) : t('apps.chat_unlinked')}</span>
                </span>
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setUnpair(c.id)}>{t('apps.unpair')}</Button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <SecretSheet open={tokenOpen} onOpenChange={setTokenOpen} title={t('apps.token_title')} description={t('apps.secret_where', { store: status.store })} label={t('apps.token_label')} hint={t('apps.token_hint')} name="telegram-bot-token" testid="telegram-token-sheet" onSaved={reload} />
      <PairingSheet open={pairOpen} onOpenChange={setPairOpen} status={status} reload={reload} />
      <ConfirmDialog open={removeToken} onOpenChange={setRemoveToken} title={t('apps.remove_token_title')} description={t('apps.remove_token_body')} confirmLabel={t('apps.remove')} destructive onConfirm={() => removeChannel([{ name: 'telegram-bot-token', label: t('apps.token_label') }], () => save({ ...settings, apps: { ...settings.apps, telegram: { enabled: false } } }))} />
      <ConfirmDialog open={unpair !== null} onOpenChange={(o) => !o && setUnpair(null)} title={t('apps.unpair_title')} description={t('apps.unpair_body')} confirmLabel={t('apps.unpair')} destructive onConfirm={async () => { if (unpair !== null) await sayIfFails(() => client.unpairChat(unpair)); reload(); }} />
    </ChannelCard>
  );
}

/** Chat with coding agents from Slack (Socket Mode) and WhatsApp: the keys are write-only, and each channel has its own switch. */
function AgentChatCard({ status, settings, save, reload }: { status: AppsStatus; settings: Settings; save: (s: Settings) => Promise<string | null>; reload: () => void }) {
  const [sheet, setSheet] = useState<null | 'slack-app-token' | 'slack-bot-token' | 'whatsapp-app-secret' | 'whatsapp-verify-token'>(null);
  const chat = settings.apps.chat ?? { slack: false, whatsapp: false };
  const flip = async (key: 'slack' | 'whatsapp', v: boolean) => {
    const m = await save({ ...settings, apps: { ...settings.apps, chat: { ...chat, [key]: v } } });
    if (m) toast.error(m);
    else reload();
  };
  const sheets: { name: NonNullable<typeof sheet>; label: string; hint: string }[] = [
    { name: 'slack-app-token', label: t('apps.chat_slack_app_label'), hint: t('apps.chat_slack_app_hint') },
    { name: 'slack-bot-token', label: t('apps.chat_slack_bot_label'), hint: t('apps.chat_slack_bot_hint') },
    { name: 'whatsapp-app-secret', label: t('apps.chat_wa_secret_label'), hint: t('apps.chat_wa_secret_hint') },
    { name: 'whatsapp-verify-token', label: t('apps.chat_wa_verify_label'), hint: t('apps.chat_wa_verify_hint') },
  ];
  const open = sheets.find((x) => x.name === sheet);
  return (
    <ChannelCard
      id="agent-chat"
      title={t('apps.chat_title')}
      status={<Badge variant={chat.slack || chat.whatsapp ? 'default' : 'secondary'}>{chat.slack || chat.whatsapp ? t('apps.chat_on') : t('apps.chat_off')}</Badge>}
      actions={
        <div className="flex flex-wrap gap-2">
          {sheets.map((x) => (
            <Button key={x.name} variant="outline" size="sm" className="max-lg:h-11" onClick={() => setSheet(x.name)}>
              {x.label}
            </Button>
          ))}
        </div>
      }
    >
      <p className="text-xs text-muted-foreground">{t('apps.chat_help')}</p>
      <p className="text-xs text-muted-foreground" data-testid="agent-chat-notify-only">{t('apps.notify_only')}</p>
      {!status.public_url_set ? (
        <p role="status" className="text-xs text-destructive" data-testid="agent-chat-no-public-url">{t('apps.chat_no_public_url')}</p>
      ) : null}
      <div className="flex min-h-11 items-center gap-3">
        <TouchCheckbox id="chat-slack-on" checked={chat.slack} onCheckedChange={(c) => void flip('slack', c === true)} />
        <Label htmlFor="chat-slack-on">{t('apps.chat_slack_on')}</Label>
      </div>
      <div className="flex min-h-11 items-center gap-3">
        <TouchCheckbox id="chat-wa-on" checked={chat.whatsapp} onCheckedChange={(c) => void flip('whatsapp', c === true)} />
        <Label htmlFor="chat-wa-on">{t('apps.chat_wa_on')}</Label>
      </div>
      <p className="text-xs text-muted-foreground">{t('apps.chat_wa_webhook')}</p>
      {open ? <SecretSheet open onOpenChange={(o) => !o && setSheet(null)} title={open.label} description={t('apps.secret_where', { store: status.store })} label={open.label} hint={open.hint} name={open.name} testid="chat-secret-sheet" onSaved={reload} /> : null}
    </ChannelCard>
  );
}

function SlackCard({ status, settings, save, reload }: { status: AppsStatus; settings: Settings; save: (s: Settings) => Promise<string | null>; reload: () => void }) {
  const removeChannel = useRemoveChannel(reload);
  const [open, setOpen] = useState(false);
  const [remove, setRemove] = useState(false);
  const test = useChannelTest();
  return (
    <ChannelCard
      id="slack"
      title={t('apps.slack_title')}
      status={<StatusBadge enabled={status.slack.enabled} configured={status.slack.configured} />}
      actions={
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setOpen(true)}>{status.slack.configured ? t('apps.replace_address') : t('apps.set_up')}</Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!status.slack.configured || test.busy === 'slack'} onClick={() => test.run('slack', reload)}>{t('apps.send_test')}</Button>
          {status.slack.configured ? <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(true)}>{t('apps.remove')}</Button> : null}
        </>
      }
    >
      <p className="text-xs text-muted-foreground">{t('apps.slack_help')}</p>
      <ChannelGuide channel="slack" />
      <EnableToggle id="sl-on" checked={settings.apps.slack.enabled} disabled={!status.slack.configured} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, slack: { enabled: v } } }); if (m) toast.error(m); else reload(); }} />
      <SecretSheet open={open} onOpenChange={setOpen} title={t('apps.slack_title')} description={t('apps.secret_where', { store: status.store })} label={t('apps.slack_label')} hint={t('apps.slack_hint')} name="slack-webhook-url" testid="slack-sheet" onSaved={reload} />
      <ConfirmDialog open={remove} onOpenChange={setRemove} title={t('apps.remove_slack_title')} description={t('apps.remove_slack_body')} confirmLabel={t('apps.remove')} destructive onConfirm={() => removeChannel([{ name: 'slack-webhook-url', label: t('apps.slack_label') }], () => save({ ...settings, apps: { ...settings.apps, slack: { enabled: false } } }))} />
    </ChannelCard>
  );
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24);
const webhookSchema = z.object({
  label: z.string().trim().min(1, t('apps.webhook_label_required')).max(40),
  url: z.string().min(1, t('apps.webhook_url_required')).refine((v) => v.startsWith('https://'), t('apps.webhook_https')),
  secret: z.string().min(16, t('apps.webhook_secret_short')),
});
type WebhookForm = z.infer<typeof webhookSchema>;

function WebhooksCard({ status, settings, save, reload }: { status: AppsStatus; settings: Settings; save: (s: Settings) => Promise<string | null>; reload: () => void }) {
  const { client } = useApp();
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [remove, setRemove] = useState<string | null>(null);
  const test = useChannelTest();
  const form = useForm<WebhookForm>({ resolver: zodResolver(webhookSchema), defaultValues: { label: '', url: '', secret: '' } });
  const errors = form.formState.errors;
  return (
    <Card className="space-y-3 p-4" data-testid="app-webhooks">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('apps.webhooks_title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => { form.reset({ label: '', url: '', secret: '' }); setRevealed(false); setErr(null); setOpen(true); }}>{t('apps.add_webhook')}</Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('apps.webhooks_help')}</p>
      <ChannelGuide channel="webhook" />
      <TestResults prefix="webhook:" />
      {status.webhooks.length === 0 ? (
        <p className="text-sm">{t('apps.no_webhooks')}</p>
      ) : (
        <ul className="space-y-3" aria-label={t('apps.webhooks_title')}>
          {status.webhooks.map((w) => (
            <li key={w.id} className="space-y-2 rounded-md border p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{w.label}</p>
                  <p className="truncate font-mono text-xs text-muted-foreground">{w.host}</p>
                </div>
                <StatusBadge enabled={w.enabled} configured={w.configured} />
              </div>
              <EnableToggle id={`wh-${w.id}`} checked={w.enabled} onChange={async (v) => { const m = await save({ ...settings, apps: { ...settings.apps, webhooks: settings.apps.webhooks.map((x) => (x.id === w.id ? { ...x, enabled: v } : x)) } }); if (m) toast.error(m); else reload(); }} />
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" className="max-lg:h-11" disabled={test.busy === `webhook:${w.id}`} onClick={() => test.run(`webhook:${w.id}`, reload)}>{t('apps.send_test')}</Button>
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemove(w.id)}>{t('apps.remove')}</Button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-muted-foreground">{t('apps.webhooks_verify')}</p>
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="webhook-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={form.handleSubmit(async (v) => {
              try {
                await client.addWebhook({ id: slug(v.label) || 'hook', label: v.label.trim(), url: v.url, secret: v.secret });
              } catch (e) {
                return setErr(errorText(e));
              }
              form.reset({ label: '', url: '', secret: '' });
              setRevealed(false);
              toast.success(t('apps.saved'));
              setOpen(false);
              reload();
            })}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('apps.add_webhook')}</PanelSheetTitle>
              <PanelSheetDescription>{t('apps.secret_where', { store: status.store })}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
              <div className="space-y-1">
                <Label htmlFor="wh-label">{t('apps.webhook_label')}</Label>
                <Input id="wh-label" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.label} {...form.register('label')} />
                <FieldError msg={errors.label?.message} />
              </div>
              <SecretField id="wh-url" label={t('apps.webhook_url')} hint={t('apps.webhook_url_hint')} aria-invalid={!!errors.url} {...form.register('url')} />
              <FieldError msg={errors.url?.message} />
              <SecretField id="wh-secret" label={t('apps.webhook_secret')} hint={revealed ? t('apps.webhook_secret_copy') : t('apps.webhook_secret_hint')} revealed={revealed} aria-invalid={!!errors.secret} {...form.register('secret')} />
              <FieldError msg={errors.secret?.message} />
              <Button type="button" variant="outline" size="sm" className="max-lg:h-11" onClick={() => { const b = new Uint8Array(24); crypto.getRandomValues(b); form.setValue('secret', Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''), { shouldValidate: true }); setRevealed(true); }}>
                {t('apps.generate_secret')}
              </Button>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>{t('common.save')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
      <ConfirmDialog open={remove !== null} onOpenChange={(o) => !o && setRemove(null)} title={t('apps.remove_webhook_title')} description={t('apps.remove_webhook_body')} confirmLabel={t('apps.remove')} destructive onConfirm={async () => { if (remove) await sayIfFails(() => client.removeWebhook(remove)); reload(); }} />
    </Card>
  );
}

function RecentAlerts({ entries }: { entries: RecentAlert[] | undefined }) {
  const { info } = useApp();
  const [summaryOpen, setSummaryOpen] = useState(false);
  const list = [...(entries ?? [])].reverse().slice(0, 15);
  return (
    <Card className="space-y-2 p-4" data-testid="recent-alerts">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('apps.recent_title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setSummaryOpen(true)}>{t('summary.open')}</Button>
      </div>
      <SummarySheet open={summaryOpen} onOpenChange={setSummaryOpen} />
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('apps.recent_none')}</p>
      ) : (
        <ul className="space-y-2" aria-label={t('apps.recent_title')}>
          {list.map((a) => (
            <li key={`${a.key}-${a.ts_ms}`} className="rounded-md border p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{a.title}</span>
                {a.severity === 'urgent' ? <Badge variant="destructive">{t('apps.urgent')}</Badge> : null}
              </div>
              <p className="text-xs text-muted-foreground">{formatWithUtc(a.ts_ms, info?.clock?.time_zone)}</p>
              <OutcomeBlock alert={a} />
              {a.deliveries.length > 0 ? (
                <p className="text-xs">{a.deliveries.map((d) => `${d.channel}${d.person ? ` (${d.person})` : ''}${d.attempts && d.attempts > 1 ? ` ${t('apps.attempts', { count: d.attempts })}` : ''}: ${d.ok ? t('apps.delivered') : d.detail}`).join(' · ')}</p>
              ) : (
                <p className="text-xs text-muted-foreground">{t('apps.dashboard_only')}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function AppsSection() {
  const { client } = useApp();
  const status = useAsync<AppsStatus>((s) => client.apps(s), [client], 15_000);
  const alerts = useAsync((s) => client.alerts(s), [client], 15_000);
  const { settings, save, reload: reloadSettings } = useSettings();
  const reload = () => {
    status.reload();
    alerts.reload();
    reloadSettings();
  };
  if (status.error && !status.data) return <p role="alert" className="text-sm text-destructive">{status.error.message}</p>;
  if (!status.data || !settings) return <Skeleton className="h-64 w-full" />;
  const s = status.data;
  const offset = s.quiet_hours.utc_offset_minutes;
  const utc = `UTC${offset >= 0 ? '+' : '-'}${String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0')}:${String(Math.abs(offset) % 60).padStart(2, '0')}`;
  return (
    <div className="space-y-4">
      <Card className="space-y-1 p-4">
        <h2 className="text-sm font-semibold">{t('apps.title')}</h2>
        <p className="text-xs text-muted-foreground" data-testid="apps-note">{t('apps.intro', { store: s.store })}</p>
        <p className="text-xs text-muted-foreground">{t('apps.quiet', { window: windowWithUtc(s.quiet_hours.from, s.quiet_hours.to, s.quiet_hours.time_zone), zone: s.quiet_hours.time_zone ?? utc })}</p>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <EmailCard status={s} settings={settings} save={save} reload={reload} />
        <SmsCard status={s} settings={settings} save={save} reload={reload} />
        <TelegramCard status={s} settings={settings} save={save} reload={reload} />
        <SlackCard status={s} settings={settings} save={save} reload={reload} />
        <WhatsappCard status={s} settings={settings} save={save} reload={reload} />
        <AgentChatCard status={s} settings={settings} save={save} reload={reload} />
        <WebhookUrlCard kind="discord" status={s} settings={settings} save={save} reload={reload} />
        <WebhookUrlCard kind="teams" status={s} settings={settings} save={save} reload={reload} />
        <PushCard status={s} settings={settings} save={save} reload={reload} />
      </div>
      <WebhooksCard status={s} settings={settings} save={save} reload={reload} />
      <RoutingSection status={s} settings={settings} save={save} reload={reload} />
      <Card className="space-y-2 p-4">
        <ChannelGuide channel="sign_in" />
      </Card>
      <RecentAlerts entries={alerts.data?.entries} />
    </div>
  );
}
