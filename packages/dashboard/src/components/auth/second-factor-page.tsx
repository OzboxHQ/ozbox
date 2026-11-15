import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { SessionApi, SessionStatus } from '../../api/session';
import { signInMessage } from '../../lib/auth-errors';
import { t } from '../../lib/i18n';
import { getPasskey } from '../../lib/webauthn';

const BTN = 'h-11 w-full lg:h-10';

/** After GitHub, Google or a setup code: a passkey or an authenticator code finishes the sign-in. */
export function SecondFactorPage({ api, status, onStatus, onSignOut }: { api: SessionApi; status: SessionStatus; onStatus: (s: SessionStatus) => void; onSignOut: () => void }) {
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const f = status.second_factors;

  const run = async (go: () => Promise<SessionStatus>) => {
    setBusy(true);
    setError(null);
    try {
      onStatus(await go());
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main id="main" className="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-4 p-4 sm:p-6">
      <Card className="space-y-4 p-5">
        <h1 className="text-2xl font-semibold tracking-tight">{t('auth.second_title')}</h1>
        <p className="text-sm text-muted-foreground">{t('auth.second_body', { via: status.user?.label ?? '' })}</p>
        {error && (
          <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">
            {error}
          </p>
        )}
        {f?.passkey && (
          <Button
            className={BTN}
            disabled={busy}
            data-testid="second-passkey"
            onClick={() =>
              void run(async () => {
                const o = await api.secondOptions();
                return api.secondVerify(o.ceremony, await getPasskey(o.options));
              })
            }
          >
            {t('auth.second_passkey')}
          </Button>
        )}
        {f?.totp && (
          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() => api.secondTotp(code));
            }}
          >
            <Label htmlFor="second-code">{t('auth.second_totp_label')}</Label>
            <Input className="h-11 lg:h-10" id="second-code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} aria-describedby="second-code-hint" />
            <p id="second-code-hint" className="text-xs text-muted-foreground">
              {t('auth.code_hint')}
            </p>
            <Button type="submit" variant="outline" className={BTN} disabled={busy || code.replace(/\s/g, '').length < 6}>
              {t('auth.second_totp_button')}
            </Button>
          </form>
        )}
        <Button variant="ghost" className={BTN} onClick={onSignOut}>
          {t('auth.second_signout')}
        </Button>
      </Card>
    </main>
  );
}
