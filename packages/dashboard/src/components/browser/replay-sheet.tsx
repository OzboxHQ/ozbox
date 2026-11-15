import { useEffect, useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { ReplayStep } from '../../api/browser';
import { t } from '../../lib/i18n';
import { useAsync } from '../../lib/use-async';

/** A picture from the recording. The request carries the sign-in, so it is fetched and shown from memory. */
function Shot({ box, session, name }: { box: string; session: string; name: string | undefined }) {
  const { client } = useApp();
  const [src, setSrc] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    setFailed(false);
    if (!name) {
      setSrc(null);
      return;
    }
    let url: string | null = null;
    let stop = false;
    void client
      .fetchBlob(`/v1/browser/recordings/${encodeURIComponent(box)}/${encodeURIComponent(session)}/shots/${encodeURIComponent(name)}`)
      .then((b) => {
        if (stop) return;
        url = URL.createObjectURL(b);
        setSrc(url);
      })
      .catch(() => {
        if (stop) return;
        setSrc(null);
        setFailed(true);
      });
    return () => {
      stop = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [client, box, session, name]);
  if (!name) return <p className="text-sm text-muted-foreground">{t('browser.step_no_picture')}</p>;
  if (failed) return <p role="alert" className="text-sm text-destructive" data-testid="replay-picture-failed">{t('browser.step_picture_failed')}</p>;
  if (!src) return <Skeleton className="h-40 w-full" />;
  return <img data-testid="replay-picture" src={src} alt={t('browser.live_picture')} className="block h-auto w-full rounded-md border" />;
}

/** The replay: every step with its page, the names of the fields it touched, and a picture. Never a typed value. */
export function ReplaySheet({ box, session, onClose }: { box: string; session: string; onClose: () => void }) {
  const { client } = useApp();
  const data = useAsync((s) => client.browser.replay(box, session, s), [client, box, session]);
  const [at, setAt] = useState(0);
  const steps: ReplayStep[] = data.data?.steps ?? [];
  const step = steps[Math.min(at, Math.max(steps.length - 1, 0))];
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="browser-replay-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('browser.replay_heading')}</PanelSheetTitle>
          <PanelSheetDescription>{t('browser.replay_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {data.error ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{data.error instanceof ApiError ? data.error.message : t('browser.live_lost')}</AlertDescription>
            </Alert>
          ) : null}
          {!data.data && !data.error ? <Skeleton className="h-40 w-full" /> : null}
          {data.data && steps.length === 0 ? <p className="text-sm text-muted-foreground">{t('browser.replay_none')}</p> : null}
          {step ? (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
              <div className="space-y-2" data-testid="replay-current" data-step={step.n}>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-sm font-semibold">{t('browser.step_n', { n: step.n })}</h2>
                  <Badge variant="outline">{step.actor === 'agent' ? t('browser.step_agent') : t('browser.step_person')}</Badge>
                  <Badge>{step.action}</Badge>
                </div>
                <p className="break-all text-xs text-muted-foreground">{step.page}</p>
                {step.names.length > 0 ? <p className="text-xs">{t('browser.step_fields', { names: step.names.join(', ') })}</p> : null}
                <p className="text-xs text-muted-foreground">
                  {t('browser.step_risk', { risk: step.risk })} · {t('browser.step_outcome', { outcome: step.outcome })}
                  {step.approval ? <> · {t('browser.step_approval', { id: step.approval })}</> : null}
                </p>
                <Shot box={box} session={session} name={step.shot} />
              </div>
              <ol className="max-h-80 space-y-1 overflow-y-auto" aria-label={t('browser.replay_list')} data-testid="replay-timeline">
                {steps.map((s, i) => (
                  <li key={s.n}>
                    <button
                      type="button"
                      className={`flex min-h-11 w-full items-center gap-2 rounded-md border px-3 py-2 text-left text-sm lg:min-h-8 ${i === at ? 'bg-accent' : ''}`}
                      aria-current={i === at ? 'step' : undefined}
                      data-testid="replay-step"
                      onClick={() => setAt(i)}
                    >
                      <span className="w-6 shrink-0 text-xs text-muted-foreground">{s.n}</span>
                      <span className="min-w-0 flex-1 truncate">{s.action}</span>
                      <span className="shrink-0 text-xs text-muted-foreground">{s.outcome}</span>
                    </button>
                  </li>
                ))}
              </ol>
            </div>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} disabled={at <= 0} onClick={() => setAt((a) => Math.max(a - 1, 0))}>
            ←
          </Button>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} disabled={at >= steps.length - 1} onClick={() => setAt((a) => Math.min(a + 1, steps.length - 1))}>
            →
          </Button>
          <Button className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('browser.replay_back')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
