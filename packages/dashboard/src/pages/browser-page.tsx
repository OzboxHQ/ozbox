import { useState } from 'react';
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
import { Textarea } from '@/components/ui/textarea';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../App';
import { ApiError } from '../api/client';
import type { BrowserPolicy, Recording, SessionState } from '../api/browser';
import { LiveSheet } from '../components/browser/live-sheet';
import { ReplaySheet } from '../components/browser/replay-sheet';
import { CannotNote } from '../components/role-scope';
import { SourceNote } from '../components/source-badge';
import { UnreachableNote } from '../components/unreachable-note';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { withStepUp } from '../components/perm/with-step-up';
import { t, type MessageKey } from '../lib/i18n';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const STATE_KEY: Record<SessionState, MessageKey> = {
  running: 'browser.state_running',
  taken_over: 'browser.state_taken_over',
  paused: 'browser.state_paused',
  closed: 'browser.state_closed',
};

const message = (e: unknown, fallback: string) => (e instanceof ApiError ? e.message : fallback);
const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);

/**
 * The browsers on your boxes: open now, recordings, and the settings that govern them. The pictures of a browser show
 * what is on a person's screen, so a viewer is not offered them; a member may watch and take over; only an owner changes
 * the settings (ADR 0039).
 */
export function BrowserPage() {
  const { can } = useCan();
  if (!can('watch_browser')) {
    return (
      <AppPage>
        <PageHeader title={t('browser.title')} description={t('browser.desc')} />
        <div data-testid="browser-no-access">
          <EmptyState title={t('roles.cannot_watch_title')}>{t('roles.cannot_watch_body')}</EmptyState>
          <div className="mt-3">
            <CannotNote cap="watch_browser" />
          </div>
        </div>
      </AppPage>
    );
  }
  return <BrowserPageBody />;
}

function BrowserPageBody() {
  const { client } = useApp();
  const { can } = useCan();
  const list = useAsync((s) => client.browser.sessions(undefined, s), [client], 3000);
  const [watching, setWatching] = useState<string | null>(null);
  const [replaying, setReplaying] = useState<Recording | null>(null);
  const [opening, setOpening] = useState(false);
  const [settings, setSettings] = useState(false);
  const [closing, setClosing] = useState<string | null>(null);
  // a server with no task store has nowhere to keep browser sessions: say so, not a generic failure
  const unavailable = list.error instanceof ApiError && list.error.status === 501 && list.error.code === 'browser_unavailable';
  const live = list.data?.recordings.filter((r) => r.live) ?? [];
  const past = list.data?.recordings.filter((r) => !r.live) ?? [];

  async function resume(r: Recording) {
    try {
      await withStepUp(() => client.browser.resume(r.session, r.box));
      toast.success(t('browser.resumed'));
      list.reload();
      setWatching(r.session);
    } catch (e) {
      toast.error(message(e, t('browser.open_failed')));
    }
  }

  const row = (r: Recording, isLive: boolean) => (
    <li key={`${r.box}:${r.session}`}>
      <Card className="space-y-2 p-4" data-testid="browser-session" data-session={r.session} data-state={r.state}>
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="break-all text-sm font-semibold">{t('browser.session_on', { id: r.session, box: r.box })}</h3>
          <Badge variant={r.state === 'taken_over' ? 'default' : 'outline'}>{t(STATE_KEY[r.state])}</Badge>
          <Badge variant="outline">{r.device}</Badge>
          <span className="text-xs text-muted-foreground">{t('browser.actions_n', { n: r.actions })}</span>
        </div>
        {r.paused_reason && r.state !== 'running' ? <p className="text-xs text-muted-foreground">{r.paused_reason}</p> : null}
        <div className="flex flex-wrap gap-2">
          {isLive ? (
            <>
              <Button className={TAP_ACTION_DEFAULT} onClick={() => setWatching(r.session)}>
                {t('browser.watch')}
              </Button>
              {can('control_browser') ? (
                <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setClosing(r.session)}>
                  {t('browser.close')}
                </Button>
              ) : null}
            </>
          ) : null}
          {r.state === 'paused' && !isLive && can('control_browser') ? (
            <Button className={TAP_ACTION_DEFAULT} onClick={() => void resume(r)}>
              {t('browser.resume')}
            </Button>
          ) : null}
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setReplaying(r)}>
            {t('browser.replay')}
          </Button>
        </div>
      </Card>
    </li>
  );

  return (
    <AppPage>
      <PageHeader
        title={t('browser.title')}
        description={t('browser.desc')}
        actions={
          <div className="flex flex-wrap gap-2">
            {can('change_settings') && !unavailable ? (
              <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setSettings(true)}>
                {t('browser.settings')}
              </Button>
            ) : null}
            {can('control_browser') && !unavailable ? (
              <Button className={TAP_ACTION_DEFAULT} onClick={() => setOpening(true)}>
                {t('browser.open')}
              </Button>
            ) : null}
          </div>
        }
      />
      <SourceNote source={list.data?.source} what="browser" />
      <UnreachableNote items={list.data?.unreachable ?? []} />
      {!list.data && !list.error ? <Skeleton className="h-32 w-full" /> : null}
      {unavailable ? (
        <div data-testid="browser-unavailable">
          <EmptyState title={t('browser.unavailable')}>{t('browser.unavailable_body')}</EmptyState>
        </div>
      ) : null}
      {list.error && !unavailable ? (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{message(list.error, t('browser.live_lost'))}</AlertDescription>
        </Alert>
      ) : null}
      {list.data ? (
        <>
          <section className="space-y-3" aria-label={t('browser.live_title')}>
            <h2 className="text-sm font-semibold">{t('browser.live_title')}</h2>
            {live.length === 0 ? <EmptyState title={t('browser.live_none')}>{t('browser.live_none_body')}</EmptyState> : null}
            <ul className="space-y-3" aria-label={t('browser.list_label')} data-testid="browser-live-list">
              {live.map((r) => row(r, true))}
            </ul>
          </section>
          <section className="space-y-3" aria-label={t('browser.recordings_title')}>
            <h2 className="text-sm font-semibold">{t('browser.recordings_title')}</h2>
            {past.length === 0 ? <p className="text-sm text-muted-foreground">{t('browser.recordings_none')}</p> : null}
            <ul className="space-y-3" aria-label={t('browser.recordings_label')} data-testid="browser-recordings">
              {past.map((r) => row(r, false))}
            </ul>
          </section>
        </>
      ) : null}
      {watching ? <LiveSheet key={watching} session={watching} onClose={() => { setWatching(null); list.reload(); }} /> : null}
      {replaying ? <ReplaySheet box={replaying.box} session={replaying.session} onClose={() => setReplaying(null)} /> : null}
      {opening ? <OpenSheet onClose={() => setOpening(false)} onOpened={(id) => { setOpening(false); list.reload(); setWatching(id); }} /> : null}
      {settings ? <SettingsSheet onClose={() => setSettings(false)} /> : null}
      <ConfirmDialog
        open={closing !== null}
        onOpenChange={(o) => !o && setClosing(null)}
        title={t('browser.close_title')}
        description={t('browser.close_body')}
        confirmLabel={t('browser.close_go')}
        destructive
        onConfirm={async () => {
          if (!closing) return;
          try {
            await client.browser.close(closing);
          } catch (e) {
            toast.error(message(e, t('browser.live_lost')));
          }
          setClosing(null);
          list.reload();
        }}
      />
    </AppPage>
  );
}

function OpenSheet({ onClose, onOpened }: { onClose: () => void; onOpened: (id: string) => void }) {
  const { client } = useApp();
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const names = (boxes.data ?? []).filter((b) => b.state === 'running').map((b) => b.spec.name);
  const [box, setBox] = useState('');
  const [device, setDevice] = useState('desktop');
  const [err, setErr] = useState<string | null>(null);
  const chosen = box || names[0] || '';
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="browser-open-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('browser.open')}</PanelSheetTitle>
          <PanelSheetDescription>{t('browser.desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="br-box">{t('browser.open_box')}</Label>
            <Select value={chosen} onValueChange={setBox}>
              <SelectTrigger id="br-box" className="max-lg:h-11"><SelectValue /></SelectTrigger>
              <SelectContent>
                {names.map((n) => <SelectItem key={n} value={n}>{n}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="br-device">{t('browser.open_device')}</Label>
            <Select value={device} onValueChange={setDevice}>
              <SelectTrigger id="br-device" className="max-lg:h-11"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="desktop">{t('browser.device_desktop')}</SelectItem>
                <SelectItem value="tablet">{t('browser.device_tablet')}</SelectItem>
                <SelectItem value="phone">{t('browser.device_phone')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            className={TAP_ACTION_DEFAULT}
            disabled={!chosen}
            onClick={async () => {
              try {
                onOpened((await client.browser.open(chosen, device)).id);
              } catch (e) {
                setErr(message(e, t('browser.open_failed')));
              }
            }}
          >
            {t('browser.open_go')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function SettingsSheet({ onClose }: { onClose: () => void }) {
  const { client } = useApp();
  const data = useAsync((s) => client.browser.settings(undefined, s), [client]);
  const [draft, setDraft] = useState<BrowserPolicy | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const p = draft ?? data.data?.settings ?? null;
  const set = (patch: Partial<BrowserPolicy>) => p && setDraft({ ...p, ...patch });
  const num = (id: string, label: MessageKey, key: 'retention_days' | 'max_actions' | 'max_minutes' | 'max_sessions' | 'wait_minutes' | 'memory_mb') =>
    p ? (
      <div className="space-y-1">
        <Label htmlFor={id}>{t(label)}</Label>
        <Input id={id} type="number" min={1} className="max-lg:h-11" value={p[key]} onChange={(e) => set({ [key]: Number(e.target.value) } as Partial<BrowserPolicy>)} />
      </div>
    ) : null;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="browser-settings-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('browser.s_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('browser.s_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          {!p ? <Skeleton className="h-40 w-full" /> : (
            <>
              <div className="space-y-1">
                <Label htmlFor="br-pay">{t('browser.s_payments')}</Label>
                <Select value={p.payments} onValueChange={(v) => set({ payments: v as 'refuse' | 'ask' })}>
                  <SelectTrigger id="br-pay" className="max-lg:h-11"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="refuse">{t('browser.s_payments_refuse')}</SelectItem>
                    <SelectItem value="ask">{t('browser.s_payments_ask')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {num('br-ret', 'browser.s_retention', 'retention_days')}
                {num('br-act', 'browser.s_max_actions', 'max_actions')}
                {num('br-min', 'browser.s_max_minutes', 'max_minutes')}
                {num('br-ses', 'browser.s_max_sessions', 'max_sessions')}
                {num('br-wait', 'browser.s_wait', 'wait_minutes')}
                {num('br-mem', 'browser.s_memory', 'memory_mb')}
              </div>
              <div className="flex min-h-11 items-center gap-2">
                <input id="br-robots" type="checkbox" className="size-5" checked={p.respect_robots} onChange={(e) => set({ respect_robots: e.target.checked })} />
                <Label htmlFor="br-robots">{t('browser.s_robots')}</Label>
              </div>
              <div className="space-y-1">
                <Label htmlFor="br-safe">{t('browser.s_safe')}</Label>
                <Textarea id="br-safe" rows={3} value={p.safe_sites.join('\n')} onChange={(e) => set({ safe_sites: lines(e.target.value) })} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="br-exempt">{t('browser.s_exempt')}</Label>
                <Textarea id="br-exempt" rows={3} value={p.exempt_sites.join('\n')} onChange={(e) => set({ exempt_sites: lines(e.target.value) })} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="br-local">{t('browser.s_local')}</Label>
                <Textarea id="br-local" rows={3} value={p.local_model_sites.join('\n')} onChange={(e) => set({ local_model_sites: lines(e.target.value) })} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="br-uploads">{t('browser.s_uploads')}</Label>
                <Textarea id="br-uploads" rows={2} value={p.upload_dirs.join('\n')} onChange={(e) => set({ upload_dirs: lines(e.target.value) })} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="br-proxy">{t('browser.s_proxy')}</Label>
                <Input id="br-proxy" className="max-lg:h-11" value={p.proxy ?? ''} placeholder={t('browser.s_proxy_placeholder')} onChange={(e) => set({ proxy: e.target.value.trim() === '' ? null : e.target.value.trim() })} autoComplete="off" />
              </div>
              <p className="text-xs text-muted-foreground">{t('browser.s_note')}</p>
            </>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            className={TAP_ACTION_DEFAULT}
            disabled={!p}
            onClick={async () => {
              if (!p) return;
              try {
                await withStepUp(() => client.browser.saveSettings(p));
                toast.success(t('browser.s_saved'));
                onClose();
              } catch (e) {
                setErr(message(e, t('browser.s_failed')));
              }
            }}
          >
            {t('browser.s_save')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
