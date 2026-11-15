import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { Frame, SessionStatus } from '../../api/browser';
import { keyName, toPagePoint } from '../../lib/browser';
import { withStepUp } from '../perm/with-step-up';
import { t } from '../../lib/i18n';
import { useCan } from '../../lib/use-can';

const POLL_MS = 400;

const message = (e: unknown, fallback: string) => (e instanceof ApiError ? e.message : fallback);

/**
 * The live view: the page as pictures the worker takes (a few a second), take over and hand back, and, while you hold the
 * browser, your clicks and keys go back through the same session. Nothing you type is recorded.
 */
export function LiveSheet({ session, onClose }: { session: string; onClose: () => void }) {
  const { client } = useApp();
  const { can } = useCan();
  const [frame, setFrame] = useState<Frame | null>(null);
  const [status, setStatus] = useState<SessionStatus | null>(null);
  const [lost, setLost] = useState(false);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  /** What the server said when a click or key could not be delivered. While it shows, nothing more is sent. */
  const [inputError, setInputError] = useState<string | null>(null);
  const inputFailed = useRef(false);
  const img = useRef<HTMLImageElement>(null);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const [f, s] = await Promise.all([client.browser.frame(session), client.browser.status(session)]);
        if (stop) return;
        setFrame(f);
        setStatus(s);
        setLost(false);
      } catch {
        if (!stop) setLost(true);
      }
      if (!stop) timer = setTimeout(() => void tick(), document.hidden ? 2000 : POLL_MS);
    };
    void tick();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [client, session]);

  // a person holds the browser once someone has taken it over: a page that asked for a human check waits for that
  const mine = frame?.control === 'person' && !!status?.holder;
  const waitingForPerson = frame?.control === 'person' && !status?.holder;

  const act = useCallback(
    async (fn: () => Promise<unknown>, failed: string, ok?: string) => {
      setBusy(true);
      try {
        await fn();
        if (ok) toast.success(ok);
      } catch (e) {
        toast.error(message(e, failed));
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  const send = (event: Parameters<typeof client.browser.input>[1]) => {
    if (inputFailed.current) return;
    client.browser.input(session, event).catch((e: unknown) => {
      if (inputFailed.current) return;
      inputFailed.current = true;
      setInputError(message(e, t('browser.input_failed')));
    });
  };

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="browser-live-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('browser.live_heading')}</PanelSheetTitle>
          <PanelSheetDescription>{frame ? frame.page : t('browser.live_waiting')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {lost ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{t('browser.live_lost')}</AlertDescription>
            </Alert>
          ) : null}
          {inputError ? (
            <Alert variant="destructive" role="alert" data-testid="browser-input-error">
              <AlertDescription className="space-y-2">
                <span className="block break-words">{t('browser.input_not_sent', { why: inputError })}</span>
                <Button
                  size="sm"
                  variant="outline"
                  className={TAP_ACTION_DEFAULT}
                  onClick={() => {
                    inputFailed.current = false;
                    setInputError(null);
                  }}
                >
                  {t('browser.input_dismiss')}
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="flex flex-wrap items-center gap-2" data-testid="browser-control" data-control={frame?.control ?? 'unknown'}>
            <Badge variant={mine ? 'default' : 'secondary'}>{mine ? t('browser.you_have') : t('browser.agent_has')}</Badge>
            {status ? (
              <span className="text-xs text-muted-foreground" data-testid="browser-limits">
                {t('browser.limits', { actions: status.actions, max: status.max_actions, minutes: status.minutes, maxMinutes: status.max_minutes })}
              </span>
            ) : null}
          </div>
          {frame?.control === 'person' && status?.held_reason.startsWith('challenge') ? <p className="text-sm" data-testid="browser-challenge-note">{t('browser.challenge_note')}</p> : null}
          {waitingForPerson ? <p className="text-xs text-muted-foreground">{t('browser.take_to_continue')}</p> : null}
          {mine && frame?.dialog ? (
            <Alert role="alert" data-testid="browser-dialog">
              <AlertDescription className="space-y-2">
                <span className="block break-words">{t('browser.dialog_note', { message: frame.dialog.message })}</span>
                <span className="flex flex-wrap gap-2">
                  <Button size="sm" className={TAP_ACTION_DEFAULT} onClick={() => send({ t: 'dialog', accept: true })}>
                    {t('browser.dialog_accept')}
                  </Button>
                  <Button size="sm" variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => send({ t: 'dialog', accept: false })}>
                    {t('browser.dialog_dismiss')}
                  </Button>
                </span>
              </AlertDescription>
            </Alert>
          ) : null}
          {mine ? <p className="text-xs text-muted-foreground">{t('browser.you_have_hint')}</p> : null}
          {frame ? (
            <div className="overflow-hidden rounded-md border bg-muted">
              <img
                ref={img}
                data-testid="browser-picture"
                alt={t('browser.live_picture')}
                src={`data:image/jpeg;base64,${frame.jpeg}`}
                className={`block h-auto w-full ${mine ? 'cursor-pointer' : ''}`}
                tabIndex={mine ? 0 : -1}
                draggable={false}
                onMouseDown={(e) => {
                  if (!mine || !img.current) return;
                  send({ t: 'mouse', kind: 'down', ...toPagePoint(e, img.current, frame.device) });
                }}
                onMouseUp={(e) => {
                  if (!mine || !img.current) return;
                  send({ t: 'mouse', kind: 'up', ...toPagePoint(e, img.current, frame.device) });
                }}
                onWheel={(e) => {
                  if (!mine || !img.current) return;
                  send({ t: 'mouse', kind: 'wheel', dy: Math.round(e.deltaY), ...toPagePoint(e, img.current, frame.device) });
                }}
                onKeyDown={(e) => {
                  if (!mine) return;
                  const k = keyName(e);
                  if (!k) return;
                  e.preventDefault();
                  send({ t: 'key', kind: 'press', key: k });
                }}
              />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('browser.live_waiting')}</p>
          )}
          {mine ? (
            <form
              className="flex flex-col gap-2 sm:flex-row sm:items-end"
              onSubmit={(e) => {
                e.preventDefault();
                if (!text) return;
                send({ t: 'text', text });
                setText('');
              }}
            >
              <div className="min-w-0 flex-1 space-y-1">
                <Label htmlFor="browser-type">{t('browser.type_label')}</Label>
                <Input id="browser-type" className="max-lg:h-11" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off" />
              </div>
              <Button type="submit" variant="outline" className={TAP_ACTION_DEFAULT} disabled={!text}>
                {t('browser.type_send')}
              </Button>
            </form>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.close')}
          </Button>
          {mine ? (
            <Button className={TAP_ACTION_DEFAULT} disabled={busy} onClick={() => void act(() => client.browser.handback(session), t('browser.handback_failed'), t('browser.handed_back'))}>
              {t('browser.handback')}
            </Button>
          ) : can('control_browser') ? (
            <Button className={TAP_ACTION_DEFAULT} disabled={busy || lost} onClick={() => void act(() => withStepUp(() => client.browser.takeover(session)), t('browser.takeover_failed'))}>
              {t('browser.takeover')}
            </Button>
          ) : null}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
