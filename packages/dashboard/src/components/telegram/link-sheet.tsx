import { useEffect, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Spinner } from '@/components/ui/spinner';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../../api/error';
import type { TgStatus } from '../../api/telegram';
import { useApp } from '../../App';
import { t } from '../../lib/i18n';
import { normaliseCode, validDays } from '../../lib/telegram-flow';
import { usePasskeyStep } from './use-passkey';

type Step = 'start' | 'code' | 'confirm' | 'done';

/**
 * Linking a Telegram account (ADR 0050 §6): the pairing is reversed. A passkey opens a ten-minute window; the bot answers
 * `/link` only while it is open; the person types the code it sent back here; one more passkey confirms the link and, when
 * asked for, converse on the named boxes. Nothing here shows a token or the bot's code to anyone but the person who types it.
 */
export function TelegramLinkSheet({ open, onOpenChange, status, boxes, reload }: { open: boolean; onOpenChange: (o: boolean) => void; status: TgStatus; boxes: string[]; reload: () => void }) {
  const { client } = useApp();
  const pk = usePasskeyStep();
  const [step, setStep] = useState<Step>('start');
  const [bot, setBot] = useState<string>(status.bot ?? '');
  const [code, setCode] = useState('');
  const [account, setAccount] = useState<{ id_tail: string; first_name: string } | null>(null);
  const [label, setLabel] = useState(t('tg.label_default'));
  const [chat, setChat] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  const [days, setDays] = useState('7');
  const [hub, setHub] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setStep(status.window ? 'code' : 'start');
    setCode('');
    setAccount(null);
    setErr(null);
    pk.setNote(null);
  // eslint-disable-next-line react-hooks/exhaustive-deps -- starts a fresh run each time the sheet opens
  }, [open]);

  // while the window is open, look for the bot's answer
  useEffect(() => {
    if (!open || step !== 'code') return;
    const id = window.setInterval(reload, 2000);
    return () => window.clearInterval(id);
  }, [open, step, reload]);

  useEffect(() => {
    if (open && step === 'code' && !status.window) {
      setErr(t('tg.window_closed'));
      setStep('start');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reacts to the window closing only
  }, [status.window]);

  const hubPicked = status.marks.hub !== null && picked.includes(status.marks.hub);
  const daysN = validDays(days);

  async function openWindow() {
    const r = await pk.run(
      () => client.telegram.windowChallenge(),
      (a) => client.telegram.windowOpen(a),
    );
    if (r) {
      const c = await client.telegram.status().catch(() => null);
      setBot(c?.bot ?? r.bot ?? bot);
      setStep('code');
      reload();
    }
  }

  async function checkCode() {
    setBusy(true);
    setErr(null);
    try {
      const r = await client.telegram.candidate(normaliseCode(code));
      setAccount(r.account);
      setStep('confirm');
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('tg.failed'));
      reload();
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    const wish = chat && picked.length > 0 ? { boxes: picked, days: daysN ?? 7, hub_ack: hubPicked && hub } : null;
    const r = await pk.run(
      () => client.telegram.linkChallenge(label.trim() || t('tg.label_default'), wish),
      (a) => client.telegram.linkConfirm(a),
    );
    if (r) {
      toast.success(t('tg.linked'));
      setStep('done');
      reload();
      onOpenChange(false);
    }
  }

  const canConfirm = !pk.busy && pk.supported && (!chat || (picked.length > 0 && daysN !== null && (!hubPicked || hub)));

  return (
    <PanelSheet open={open} onOpenChange={(o) => !pk.busy && onOpenChange(o)}>
      <PanelSheetContent size="compact" data-testid="tg-link-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tg.link_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('tg.link_help')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? <Alert variant="destructive" role="alert" data-testid="tg-link-error"><AlertDescription>{err}</AlertDescription></Alert> : null}
          {pk.note ? <Alert variant="destructive" role="alert" data-testid="tg-link-note"><AlertDescription>{pk.note}</AlertDescription></Alert> : null}
          {!pk.supported ? <Alert variant="destructive" role="alert"><AlertDescription>{t('tg.passkey_needed')}</AlertDescription></Alert> : null}
          {step === 'start' ? (
            <section className="space-y-2" aria-labelledby="tg-s1">
              <h3 id="tg-s1" className="text-sm font-medium">{t('tg.step1')}</h3>
              <p className="text-sm text-muted-foreground">{t('tg.step1_help')}</p>
            </section>
          ) : null}
          {step === 'code' ? (
            <section className="space-y-3" aria-labelledby="tg-s2">
              <h3 id="tg-s2" className="text-sm font-medium" data-testid="tg-step2">{t('tg.step2', { bot: bot || status.bot || '' })}</h3>
              <p className="text-sm text-muted-foreground">{t('tg.step2_help')}</p>
              <p className="text-xs text-muted-foreground" role="status" data-testid="tg-window-state">
                {status.window?.code_offered ? t('tg.step2_heard') : t('tg.step2_wait', { s: status.window?.expires_in_s ?? 0 })}
              </p>
              <div className="space-y-1.5">
                <Label htmlFor="tg-code">{t('tg.code_label')}</Label>
                <Input id="tg-code" data-testid="tg-code" value={code} autoComplete="off" autoCapitalize="characters" spellCheck={false} onChange={(e) => setCode(e.target.value)} />
              </div>
            </section>
          ) : null}
          {step === 'confirm' && account ? (
            <section className="space-y-3" aria-labelledby="tg-s3">
              <h3 id="tg-s3" className="text-sm font-medium">{t('tg.step3')}</h3>
              <p className="text-sm text-muted-foreground">{t('tg.step3_help')}</p>
              <p className="rounded-md border bg-muted p-3 text-sm" data-testid="tg-account">{t('tg.account', { tail: account.id_tail, name: account.first_name || '—' })}</p>
              <div className="space-y-1.5">
                <Label htmlFor="tg-label">{t('tg.label_label')}</Label>
                <Input id="tg-label" data-testid="tg-label" value={label} maxLength={40} onChange={(e) => setLabel(e.target.value)} />
              </div>
              <div className="space-y-2">
                <div className="flex items-start gap-3">
                  <TouchCheckbox id="tg-chat" checked={chat} onCheckedChange={(v) => setChat(v === true)} data-testid="tg-enable-chat" />
                  <div>
                    <Label htmlFor="tg-chat" className="text-sm font-medium">{t('tg.enable_chat')}</Label>
                    <p className="text-xs text-muted-foreground">{t('tg.enable_chat_help')}</p>
                  </div>
                </div>
                {chat ? (
                  <div className="space-y-2 pl-1">
                    <p className="text-xs font-medium">{t('tg.pick_boxes')}</p>
                    {boxes.length === 0 ? <p className="text-xs text-muted-foreground">{t('tg.no_boxes')}</p> : null}
                    <ul className="space-y-1">
                      {boxes.map((b) => (
                        <li key={b} className="flex items-center gap-3 text-sm">
                          <TouchCheckbox id={`tg-box-${b}`} checked={picked.includes(b)} onCheckedChange={(v) => setPicked((p) => (v === true ? [...p, b] : p.filter((x) => x !== b)))} data-testid={`tg-box-${b}`} />
                          <Label htmlFor={`tg-box-${b}`}>{b}</Label>
                        </li>
                      ))}
                    </ul>
                    <div className="space-y-1.5">
                      <Label htmlFor="tg-days">{t('tg.days_label')}</Label>
                      <Input id="tg-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} data-testid="tg-days" />
                    </div>
                    {hubPicked ? (
                      <div className="flex items-start gap-3">
                        <TouchCheckbox id="tg-hub" checked={hub} onCheckedChange={(v) => setHub(v === true)} data-testid="tg-hub-ack" />
                        <Label htmlFor="tg-hub" className="text-xs">{t('tg.hub_ack')}</Label>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            </section>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" className="max-lg:h-11" disabled={pk.busy} onClick={() => onOpenChange(false)}>{t('common.close')}</Button>
          {step === 'start' ? (
            <Button type="button" className="max-lg:h-11" disabled={pk.busy || !pk.supported} onClick={() => void openWindow()} data-testid="tg-open-window">
              {pk.busy ? <Spinner className="mr-2 h-4 w-4" /> : null}
              {t('tg.step1_go')}
            </Button>
          ) : null}
          {step === 'code' ? (
            <Button type="button" className="max-lg:h-11" disabled={busy || normaliseCode(code).length < 4} onClick={() => void checkCode()} data-testid="tg-check-code">
              {busy ? <Spinner className="mr-2 h-4 w-4" /> : null}
              {t('tg.code_check')}
            </Button>
          ) : null}
          {step === 'confirm' ? (
            <Button type="button" className="max-lg:h-11" disabled={!canConfirm} onClick={() => void confirm()} data-testid="tg-confirm-link">
              {pk.busy ? <Spinner className="mr-2 h-4 w-4" /> : null}
              {t('tg.confirm')}
            </Button>
          ) : null}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
