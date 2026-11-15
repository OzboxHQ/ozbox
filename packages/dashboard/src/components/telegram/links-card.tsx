import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../../api/error';
import type { TgLink, TgStatus, TranscriptLine } from '../../api/telegram';
import { useApp } from '../../App';
import { fmtRelative } from '../../lib/format';
import { t } from '../../lib/i18n';
import { delegationStateText, linkIsLive, linkStateText, validDays } from '../../lib/telegram-flow';
import { useAsync } from '../../lib/use-async';
import { TelegramLinkSheet } from './link-sheet';
import { usePasskeyStep } from './use-passkey';

const BTN = 'h-11 lg:h-9';

function when(ms: number): string {
  return new Date(ms).toLocaleString();
}

/** Allow chat on boxes: a passkey-signed delegation to one link (ADR 0050 decision 2). Converse only in this release. */
function DelegationSheet({ link, boxes, status, onClose, onDone }: { link: TgLink; boxes: string[]; status: TgStatus; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const pk = usePasskeyStep();
  const [picked, setPicked] = useState<string[]>([]);
  const [days, setDays] = useState('7');
  const [hub, setHub] = useState(false);
  const hubPicked = status.marks.hub !== null && picked.includes(status.marks.hub);
  const n = validDays(days);
  const ok = picked.length > 0 && n !== null && (!hubPicked || hub) && !pk.busy && pk.supported;
  async function go() {
    const r = await pk.run(
      () => client.telegram.delegationChallenge(link.id, { acts: ['converse'], boxes: picked, days: n ?? 7, hub_ack: hubPicked && hub }),
      (a) => client.telegram.delegationCreate(link.id, a),
    );
    if (r) {
      toast.success(t('tg.allow_chat'));
      onDone();
    }
  }
  return (
    <PanelSheet open onOpenChange={(o) => !o && !pk.busy && onClose()}>
      <PanelSheetContent size="compact" data-testid="tg-delegation-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tg.allow_chat')}</PanelSheetTitle>
          <PanelSheetDescription>{t('tg.enable_chat_help')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {pk.note ? <Alert variant="destructive" role="alert" data-testid="tg-delegation-note"><AlertDescription>{pk.note}</AlertDescription></Alert> : null}
          <p className="text-xs font-medium">{t('tg.pick_boxes')}</p>
          {boxes.length === 0 ? <p className="text-xs text-muted-foreground">{t('tg.no_boxes')}</p> : null}
          <ul className="space-y-1">
            {boxes.map((b) => (
              <li key={b} className="flex items-center gap-3 text-sm">
                <TouchCheckbox id={`tgd-${b}`} checked={picked.includes(b)} onCheckedChange={(v) => setPicked((p) => (v === true ? [...p, b] : p.filter((x) => x !== b)))} data-testid={`tgd-box-${b}`} />
                <Label htmlFor={`tgd-${b}`}>{b}</Label>
              </li>
            ))}
          </ul>
          <div className="space-y-1.5">
            <Label htmlFor="tgd-days">{t('tg.days_label')}</Label>
            <Input id="tgd-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} data-testid="tgd-days" className="max-lg:h-11" />
          </div>
          {hubPicked ? (
            <div className="flex items-start gap-3">
              <TouchCheckbox id="tgd-hub" checked={hub} onCheckedChange={(v) => setHub(v === true)} />
              <Label htmlFor="tgd-hub" className="text-xs">{t('tg.hub_ack')}</Label>
            </div>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" disabled={pk.busy} onClick={onClose}>{t('common.close')}</Button>
          <Button className="max-lg:h-11" disabled={!ok} onClick={() => void go()} data-testid="tgd-confirm">{t('tg.confirm')}</Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function TranscriptSheet({ link, onClose }: { link: TgLink; onClose: () => void }) {
  const { client } = useApp();
  const { data, error } = useAsync<{ lines: TranscriptLine[] }>(() => client.telegram.transcript(link.id).then((r) => ({ lines: r.lines })), [link.id]);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="tg-transcript-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tg.transcript_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('tg.transcript_help')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-2">
          {error ? <Alert variant="destructive" role="alert"><AlertDescription>{error.message}</AlertDescription></Alert> : null}
          {!data && !error ? <Skeleton className="h-16 w-full" /> : null}
          {data && data.lines.length === 0 ? <p className="text-sm text-muted-foreground">{t('tg.transcript_empty')}</p> : null}
          <ul className="space-y-2" aria-label={t('tg.transcript_title')}>
            {data?.lines.map((l, i) => (
              <li key={`${l.ts_ms}-${i}`} className="rounded-md border p-2 text-sm" data-testid="tg-transcript-line">
                <p className="text-xs text-muted-foreground">{l.dir === 'in' ? t('tg.dir_in') : t('tg.dir_out')} · {when(l.ts_ms)}</p>
                <p className="whitespace-pre-wrap [overflow-wrap:anywhere]">{l.text}</p>
              </li>
            ))}
          </ul>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" onClick={onClose}>{t('common.close')}</Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function LinkRow({ link, ownerView, boxes, status, reload }: { link: TgLink; ownerView: boolean; boxes: string[]; status: TgStatus; reload: () => void }) {
  // lifting a lock, renewing and delegating are the link's own person's, with their own passkey; an owner may read and cut any link
  const own = link.person === status.me;
  const { client } = useApp();
  const pk = usePasskeyStep();
  const [unlink, setUnlink] = useState(false);
  const [deleg, setDeleg] = useState(false);
  const [transcript, setTranscript] = useState(false);
  const live = linkIsLive(link.state);
  const act = async (f: () => Promise<unknown>) => {
    try {
      await f();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('tg.failed'));
    }
    reload();
  };
  return (
    <li className="space-y-2 rounded-md border p-3" data-testid={`tg-link-${link.id}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="min-w-0 break-words text-sm font-medium" data-testid="tg-link-label">{t('tg.link_row', { label: link.label, tail: link.account })}</span>
        <Badge variant={link.state === 'active' ? 'default' : 'outline'} data-testid="tg-link-state">{linkStateText(link.state)}</Badge>
      </div>
      <p className="text-xs text-muted-foreground">
        {ownerView && !own ? `${link.person} · ` : ''}
        {link.last_seen_ms > 0 ? t('tg.last_seen', { when: fmtRelative(new Date(link.last_seen_ms).toISOString()) }) : t('tg.never_used')} · {t('tg.expires', { when: when(link.expires_ms) })}
      </p>
      <div>
        <p className="text-xs font-medium">{t('tg.delegations')}</p>
        {link.delegations.filter((d) => d.state !== 'revoked').length === 0 ? (
          <p className="text-xs text-muted-foreground" data-testid="tg-no-delegation">{t('tg.delegation_none')}</p>
        ) : (
          <ul className="mt-1 space-y-1">
            {link.delegations.filter((d) => d.state !== 'revoked').map((d) => (
              <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 text-xs" data-testid="tg-delegation">
                <span className="min-w-0 break-words">{t('tg.delegation_line', { boxes: d.boxes.join(', '), state: delegationStateText(d.state), when: when(d.expires_ms) })}</span>
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => void act(() => client.telegram.delegationRevoke(d.id))} data-testid="tg-revoke-delegation">{t('tg.revoke')}</Button>
              </li>
            ))}
          </ul>
        )}
      </div>
      {pk.note ? <Alert variant="destructive" role="alert"><AlertDescription>{pk.note}</AlertDescription></Alert> : null}
      <div className="flex flex-wrap gap-2">
        {link.state === 'active' ? <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => void act(() => client.telegram.lock(link.id))} data-testid="tg-lock">{t('tg.lock')}</Button> : null}
        {link.state === 'locked' && own ? (
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled={pk.busy} data-testid="tg-unlock" onClick={() => void pk.run(() => client.telegram.unlockChallenge(link.id), (a) => client.telegram.unlock(link.id, a)).then(reload)}>
            {t('tg.unlock')}
          </Button>
        ) : null}
        {live && own ? (
          <>
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setDeleg(true)} data-testid="tg-allow-chat">{t('tg.allow_chat')}</Button>
            <Button variant="outline" size="sm" className="max-lg:h-11" disabled={pk.busy} data-testid="tg-renew" onClick={() => void pk.run(() => client.telegram.renewChallenge(link.id), (a) => client.telegram.renew(link.id, a)).then(reload)}>
              {t('tg.renew')}
            </Button>
          </>
        ) : null}
        {ownerView ? <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setTranscript(true)} data-testid="tg-transcript">{t('tg.transcript')}</Button> : null}
        {link.state !== 'revoked' ? <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setUnlink(true)} data-testid="tg-unlink">{t('tg.unlink')}</Button> : null}
      </div>
      <ConfirmDialog open={unlink} onOpenChange={setUnlink} title={t('tg.unlink_title')} description={t('tg.unlink_body')} confirmLabel={t('tg.unlink')} destructive onConfirm={async () => { await act(() => client.telegram.unlink(link.id)); }} />
      {deleg ? <DelegationSheet link={link} boxes={boxes} status={status} onClose={() => setDeleg(false)} onDone={() => { setDeleg(false); reload(); }} /> : null}
      {transcript ? <TranscriptSheet link={link} onClose={() => setTranscript(false)} /> : null}
    </li>
  );
}

/** The Account page's Telegram section: this person's links (every link, for an owner), what each is allowed, and the way to change it. */
export function TelegramLinksCard({ ownerView }: { ownerView: boolean }) {
  const { client } = useApp();
  const status = useAsync<TgStatus>((s) => client.telegram.status(s), []);
  const boxes = useAsync<string[]>((s) => client.listBoxes(s).then((b) => b.map((x) => x.spec.name)), []);
  const [linkOpen, setLinkOpen] = useState(false);
  const [lockAll, setLockAll] = useState(false);
  const pk = usePasskeyStep();
  const reload = status.reload;
  useEffect(() => {
    const id = window.setInterval(reload, 15000);
    return () => window.clearInterval(id);
  }, [reload]);
  const s = status.data;
  const act = useCallback(
    async (f: () => Promise<unknown>) => {
      try {
        await f();
      } catch (e) {
        toast.error(e instanceof ApiError ? e.message : t('tg.failed'));
      }
      reload();
    },
    [reload],
  );
  if (!s) return <Card className="p-4" data-testid="tg-links-card">{status.error ? <Alert variant="destructive" role="alert"><AlertDescription>{status.error.message}</AlertDescription></Alert> : <Skeleton className="h-20 w-full" />}</Card>;
  const live = s.links.filter((l) => l.state !== 'revoked');
  return (
    <Card className="space-y-3 p-4" data-testid="tg-links-card">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold">{t('tg.links')}</h2>
        <Badge variant="outline" data-testid="tg-preview-badge">{t('tg.preview')}</Badge>
      </div>
      <p className="text-xs text-muted-foreground">{t('tg.never')}</p>
      {s.needs_sign_in ? <Alert role="status" data-testid="tg-needs-sign-in"><AlertDescription>{t('tg.needs_sign_in')}</AlertDescription></Alert> : null}
      {!s.public_address ? <Alert role="status" data-testid="tg-no-address"><AlertDescription>{t('tg.no_address')}</AlertDescription></Alert> : null}
      {s.halted ? (
        <Alert variant="destructive" role="alert" data-testid="tg-halted">
          <AlertDescription className="space-y-2">
            <span className="block font-medium">{t('tg.halted')}</span>
            <span className="block">{s.halted.message}</span>
            {ownerView ? <Button size="sm" className="max-lg:h-11" onClick={() => void act(() => client.telegram.resume())} data-testid="tg-resume">{t('tg.resume')}</Button> : null}
          </AlertDescription>
        </Alert>
      ) : null}
      {live.length === 0 ? <p className="text-sm text-muted-foreground" data-testid="tg-no-links">{t('tg.no_links')}</p> : null}
      <ul className="space-y-3" aria-label={t('tg.links')}>
        {live.map((l) => (
          <LinkRow key={l.id} link={l} ownerView={ownerView} boxes={boxes.data ?? []} status={s} reload={reload} />
        ))}
      </ul>
      {s.legacy_chats.length > 0 ? (
        <div data-testid="tg-legacy">
          <p className="text-xs font-medium">{t('tg.legacy_title')}</p>
          <ul className="space-y-1">
            {s.legacy_chats.map((c) => (
              <li key={c.id} className="text-xs text-muted-foreground">{t('tg.legacy_line', { name: c.name })}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {ownerView && s.pending_owner.length > 0 ? (
        <div className="space-y-2" data-testid="tg-pending-owner">
          <p className="text-xs font-medium">{t('tg.cosign_title')}</p>
          {s.pending_owner.map((p) => (
            <div key={p.id} className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="min-w-0 break-words">{t('tg.cosign_line', { person: p.person, boxes: p.boxes.join(', ') })}</span>
              <Button size="sm" variant="outline" className="max-lg:h-11" disabled={pk.busy} onClick={() => void pk.run(() => client.telegram.cosignChallenge(p.id), (a) => client.telegram.cosign(p.id, a)).then(reload)} data-testid="tg-cosign">{t('tg.cosign')}</Button>
            </div>
          ))}
          {pk.note ? <Alert variant="destructive" role="alert"><AlertDescription>{pk.note}</AlertDescription></Alert> : null}
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button className={BTN} onClick={() => setLinkOpen(true)} disabled={!s.enabled || s.needs_sign_in} data-testid="tg-link-open">{t('tg.link_open')}</Button>
        {ownerView && live.some((l) => l.state === 'active') ? <Button variant="outline" className={BTN} onClick={() => setLockAll(true)} data-testid="tg-lock-all">{t('tg.lock_all')}</Button> : null}
      </div>
      <TelegramLinkSheet open={linkOpen} onOpenChange={setLinkOpen} status={s} boxes={boxes.data ?? []} reload={reload} />
      <ConfirmDialog open={lockAll} onOpenChange={setLockAll} title={t('tg.lock_all')} description={t('tg.lock_all_body')} confirmLabel={t('tg.lock')} destructive onConfirm={async () => { await act(() => client.telegram.lockAll()); }} />
    </Card>
  );
}
