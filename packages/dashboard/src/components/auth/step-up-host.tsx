import { useEffect, useRef, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { signInMessage } from '../../lib/auth-errors';
import { t } from '../../lib/i18n';
import { useSession } from '../../lib/session-context';
import { setStepUpHandler } from '../../lib/step-up';
import { getPasskey } from '../../lib/webauthn';

/**
 * Mounted once under the sign-in. When a change needs a fresh passkey, the caller's `askStepUp()` lands here: the prompt
 * opens, and the caller's promise settles with whether the person confirmed.
 */
export function StepUpHost() {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const settle = useRef<((ok: boolean) => void) | null>(null);
  const hasPasskey = session?.status.second_factors?.passkey ?? true;

  useEffect(() => {
    if (!session) return;
    setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          settle.current = resolve;
          setError(null);
          setCode('');
          setOpen(true);
        }),
    );
    return () => setStepUpHandler(null);
  }, [session]);

  if (!session) return null;
  const { api } = session;

  const done = (ok: boolean) => {
    setOpen(false);
    settle.current?.(ok);
    settle.current = null;
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      if (hasPasskey) {
        const o = await api.stepUpOptions();
        await api.stepUpVerify(o.ceremony, await getPasskey(o.options));
      } else {
        await api.stepUpTotp(code);
      }
      done(true);
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && !busy && done(false)}>
      <PanelSheetContent size="compact" data-testid="step-up">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('stepup.title')}</PanelSheetTitle>
          <PanelSheetDescription>{hasPasskey ? t('stepup.body', { minutes: Math.max(1, Math.round(session.status.stepup_window_s / 60)) }) : t('stepup.totp_body')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {!hasPasskey && (
            <div className="space-y-1">
              <Label htmlFor="stepup-code">{t('auth.second_totp_label')}</Label>
              <Input className="h-11 lg:h-10" id="stepup-code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} />
            </div>
          )}
          {busy && hasPasskey && (
            <p role="status" className="text-sm text-muted-foreground">
              {t('stepup.working')}
            </p>
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="h-11 lg:h-9" disabled={busy} onClick={() => done(false)}>
            {t('stepup.cancel')}
          </Button>
          <Button className="h-11 lg:h-9" disabled={busy || (!hasPasskey && code.replace(/\s/g, '').length < 6)} onClick={() => void confirm()} data-testid="step-up-confirm">
            {hasPasskey ? t('stepup.passkey') : t('stepup.totp_button')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
