import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Spinner } from '@/components/ui/spinner';
import { ApiError } from '../../api/error';
import type { ApiClient } from '../../api/client';
import type { RequestCard } from '../../api/approval-requests';
import { scopeName, shortDigest } from '../../lib/approval-requests';
import { t } from '../../lib/i18n';
import { getPasskey, passkeysSupported, wasCancelled } from '../../lib/webauthn';

type Phase = 'ready' | 'working' | 'done';

/**
 * The passkey step. It names what is being approved first. One press makes one challenge, one assertion and one decision:
 * a challenge is never kept for a second try, so every attempt starts again from the server.
 */
export function ApproveSheet({ client, card, onClose, onDecided }: { client: ApiClient; card: RequestCard; onClose: () => void; onDecided: () => void }) {
  const [phase, setPhase] = useState<Phase>('ready');
  const [note, setNote] = useState<string | null>(null);
  const supported = passkeysSupported();

  async function confirm() {
    setPhase('working');
    setNote(null);
    try {
      const challenge = await client.approvalRequests.challenge(card.id);
      // what was read on the card is what the passkey signs: a request that changed since is not approved
      if (challenge.outcome !== 'approve' || challenge.subject_digest !== card.subject_digest) {
        setNote(t('areq.sheet_changed'));
        setPhase('ready');
        onDecided();
        return;
      }
      const assertion = await getPasskey(challenge.options);
      await client.approvalRequests.approve(card.id, assertion);
      toast.success(t('areq.approved_toast'));
      setPhase('done');
      onDecided();
    } catch (e) {
      setPhase('ready');
      if (wasCancelled(e)) {
        setNote(t('areq.sheet_cancelled'));
        return;
      }
      // the server's sentence, as it is ("already approved by Alice on the dashboard (passkey), 12:03")
      setNote(e instanceof ApiError ? e.message : t('areq.approve_failed'));
      if (e instanceof ApiError) onDecided();
    }
  }

  return (
    <PanelSheet open onOpenChange={(o) => !o && phase !== 'working' && onClose()}>
      <PanelSheetContent data-testid="approve-sheet" size="compact">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('areq.sheet_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('areq.sheet_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          <dl className="space-y-3 text-sm">
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">{t('areq.sheet_what')}</dt>
              <dd className="font-medium [overflow-wrap:anywhere]" data-testid="approve-sheet-scope">
                {scopeName(card.scope)}
              </dd>
            </div>
            {card.display.map((row, i) => (
              <div key={`${i}-${row.label}`} className="min-w-0">
                <dt className="text-xs text-muted-foreground [overflow-wrap:anywhere]">{row.label}</dt>
                <dd className="whitespace-pre-wrap [overflow-wrap:anywhere]">{row.value}</dd>
              </div>
            ))}
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">{t('areq.sheet_digest')}</dt>
              <dd className="break-all font-mono text-xs" data-testid="approve-sheet-digest">
                {shortDigest(card.subject_digest)}
              </dd>
            </div>
          </dl>
          {phase === 'done' ? (
            <Alert data-testid="approve-sheet-done">
              <AlertDescription>{t('areq.sheet_approved')}</AlertDescription>
            </Alert>
          ) : (
            <p className="text-xs text-muted-foreground">{t('areq.sheet_will')}</p>
          )}
          {!supported && phase !== 'done' ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{t('areq.sheet_no_passkeys')}</AlertDescription>
            </Alert>
          ) : null}
          {note ? (
            <Alert variant="destructive" role="alert" data-testid="approve-sheet-note">
              <AlertDescription className="[overflow-wrap:anywhere]">{note}</AlertDescription>
            </Alert>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          {phase === 'done' ? (
            <Button className="max-lg:h-11" onClick={onClose} data-testid="approve-sheet-close">
              {t('areq.sheet_done')}
            </Button>
          ) : (
            <>
              <Button variant="outline" className="max-lg:h-11" disabled={phase === 'working'} onClick={onClose} data-testid="approve-sheet-close">
                {t('areq.sheet_close')}
              </Button>
              <Button className="max-lg:h-11" disabled={phase === 'working' || !supported} onClick={() => void confirm()} data-testid="approve-sheet-confirm">
                {phase === 'working' ? (
                  <>
                    <Spinner className="mr-2 h-4 w-4" />
                    {t('areq.sheet_confirming')}
                  </>
                ) : (
                  t('areq.sheet_confirm')
                )}
              </Button>
            </>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
