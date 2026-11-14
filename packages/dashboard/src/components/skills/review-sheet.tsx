import { useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { SkillReview } from '../../api/memory';
import { t } from '../../lib/i18n';
import { useAsync } from '../../lib/use-async';
import { ProvenanceLine } from './provenance';

const message = (e: unknown) => (e instanceof ApiError ? e.message : t('skills.failed'));

/** Every file an agent would be told, as plain text, with where the skill came from and what to look for. `hash` reads an earlier version. */
export function ReviewSheet({ name, hash, write, onClose, onDone }: { name: string; hash?: string; write: boolean; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const review = useAsync<SkillReview>((s) => client.memory.review(name, s, hash), [client, name, hash]);
  const [err, setErr] = useState<string | null>(null);
  const r = review.data;
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
            </>
          ) : null}
          {r?.files.map((f) => (
            <section key={f.path} className="space-y-1" aria-label={f.path}>
              <h3 className="flex flex-wrap items-center gap-2 text-xs font-semibold">
                {f.path}
                {f.kind === 'script' ? <Badge variant="outline" data-testid="skill-script-badge">{t('skills.script_badge')}</Badge> : null}
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
          {write && !hash ? (
            <Button
              className={TAP_ACTION_DEFAULT}
              disabled={!r}
              onClick={async () => {
                if (!r) return;
                try {
                  await client.memory.approveSkill(name, r.hash);
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
