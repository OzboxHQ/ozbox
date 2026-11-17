import { useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { SkillReview } from '../../api/memory';
import { t } from '../../lib/i18n';
import { ASK_KEY } from '../../lib/skills';
import { useAsync } from '../../lib/use-async';
import { ProvenanceLine } from './provenance';

const message = (e: unknown) => (e instanceof ApiError ? e.message : t('skills.failed'));

/** Every file an agent would be told, as plain text, with where the skill came from and what to look for. `hash` reads an earlier version. */
export function ReviewSheet({ name, hash, write, onClose, onDone }: { name: string; hash?: string; write: boolean; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const review = useAsync<SkillReview>((s) => client.memory.review(name, s, hash), [client, name, hash]);
  const [err, setErr] = useState<string | null>(null);
  const [acked, setAcked] = useState<Set<string>>(new Set());
  const r = review.data;
  const asks = r?.asks;
  const need = asks?.acknowledge ?? [];
  const allAcked = need.every((a) => acked.has(a.key));
  const runsInText = need.some((a) => a.key === 'shell-injection');
  const scripts = r?.files.some((f) => f.kind === 'script') ?? false;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="skill-review-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('skills.review_title', { name })}</PanelSheetTitle>
          <PanelSheetDescription>{t('skills.review_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          {!r && !review.error ? <Skeleton className="h-24 w-full" /> : null}
          {review.error ? <Alert variant="destructive" role="alert" data-testid="skill-review-error"><AlertDescription>{message(review.error)}</AlertDescription></Alert> : null}
          {r ? (
            <>
              <p className="text-sm" data-testid="skill-review-provenance"><span className="font-medium">{t('skills.review_provenance')}: </span><ProvenanceLine p={r.provenance} /></p>
              <Alert data-testid="skill-review-injection"><AlertDescription>{t('skills.review_injection')}</AlertDescription></Alert>
              {scripts ? <Alert data-testid="skill-review-scripts"><AlertDescription>{t('skills.review_scripts')}</AlertDescription></Alert> : null}
              <section className="space-y-2 rounded-md border p-3" aria-label={t('skills.asks_title')} data-testid="skill-review-asks">
                <h3 className="text-sm font-semibold">{t('skills.asks_title')}</h3>
                {need.length === 0 ? <p className="text-sm" data-testid="skill-asks-none">{t('skills.asks_none')}</p> : <p className="text-xs text-muted-foreground">{t('skills.asks_desc')}</p>}
                <ul className="space-y-3">
                  {need.map((a) => (
                    <li key={a.key} className="space-y-1" data-testid="skill-ask" data-ask={a.key}>
                      <p className="text-sm font-medium">{t(ASK_KEY[a.key].what)}</p>
                      {a.detail.length > 0 ? (
                        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted p-2 text-xs" tabIndex={0}>{a.detail.join('\n')}</pre>
                      ) : null}
                      {write && !hash ? (
                        <div className="flex items-start gap-2">
                          <TouchCheckbox
                            id={`ack-${a.key}`}
                            data-testid={`skill-ack-${a.key}`}
                            checked={acked.has(a.key)}
                            onCheckedChange={(c) =>
                              setAcked((prev) => {
                                const next = new Set(prev);
                                if (c === true) next.add(a.key);
                                else next.delete(a.key);
                                return next;
                              })
                            }
                          />
                          <label htmlFor={`ack-${a.key}`} className="text-sm">{t(ASK_KEY[a.key].ack)}</label>
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
                {asks && asks.shown.length > 0 ? (
                  <dl className="space-y-1 text-sm" data-testid="skill-asks-shown">
                    {asks.shown.map(([k, v]) => (
                      <div key={k} className="flex flex-wrap gap-1"><dt className="font-medium">{t('skills.asks_also')} {k}:</dt><dd className="break-words">{v}</dd></div>
                    ))}
                  </dl>
                ) : null}
                {asks && asks.unknown.length > 0 ? <p className="text-xs text-muted-foreground" data-testid="skill-asks-unknown">{t('skills.asks_unknown', { names: asks.unknown.join(', ') })}</p> : null}
                <p className="text-xs text-muted-foreground">{t('skills.asks_scope')}</p>
              </section>
            </>
          ) : null}
          {r?.files.map((f) => (
            <section key={f.path} className="space-y-1" aria-label={f.path}>
              <h3 className="flex flex-wrap items-center gap-2 text-xs font-semibold">
                {f.path}
                {f.kind === 'script' ? <Badge variant="outline" data-testid="skill-script-badge">{t('skills.script_badge')}</Badge> : null}
                {f.path === 'SKILL.md' && runsInText ? <Badge variant="outline" data-testid="skill-runs-badge">{t('skills.runs_in_text')}</Badge> : null}
              </h3>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border p-3 text-xs" tabIndex={0}>{f.text}</pre>
            </section>
          ))}
          {r ? <p className="text-xs text-muted-foreground">{t('skills.review_hash', { hash: r.hash.slice(0, 12) })}</p> : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {write ? t('common.cancel') : t('common.close')}
          </Button>
          {write && !hash && !allAcked ? <p className="mr-auto self-center text-xs text-muted-foreground" data-testid="skill-asks-need">{t('skills.asks_need')}</p> : null}
          {write && !hash ? (
            <Button
              className={TAP_ACTION_DEFAULT}
              disabled={!r || !allAcked}
              onClick={async () => {
                if (!r) return;
                try {
                  await client.memory.approveSkill(name, r.hash, need.map((a) => a.key));
                  onDone();
                } catch (e) {
                  setErr(e instanceof ApiError && e.status === 409 ? t('skills.stale') : message(e));
                }
              }}
            >
              {t('skills.approve_go')}
            </Button>
          ) : null}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
