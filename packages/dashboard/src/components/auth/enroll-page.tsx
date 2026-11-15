import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { SessionApi, SessionStatus } from '../../api/session';
import { signInMessage } from '../../lib/auth-errors';
import { t } from '../../lib/i18n';
import { createPasskey, passkeysSupported } from '../../lib/webauthn';
import { TotpSetup } from './totp-setup';

/** The person has no second factor yet: only enrolling one is allowed until they do. */
export function EnrollPage({ api, onStatus, onSignOut }: { api: SessionApi; onStatus: (s: SessionStatus) => void; onSignOut: () => void }) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [totp, setTotp] = useState(false);

  const addPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      const o = await api.registerOptions();
      const cred = await createPasskey(o.options);
      const r = await api.registerVerify(o.ceremony, cred, name.trim());
      if ('state' in r) onStatus(r);
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main id="main" className="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-4 p-4 sm:p-6">
      <Card className="space-y-4 p-5">
        <h1 className="text-2xl font-semibold tracking-tight">{t('auth.enroll_title')}</h1>
        <p className="text-sm text-muted-foreground">{t('auth.enroll_body')}</p>
        {error && (
          <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">
            {error}
          </p>
        )}
        {!totp && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void addPasskey();
            }}
          >
            <div className="space-y-1">
              <Label htmlFor="enroll-name">{t('auth.enroll_passkey_name')}</Label>
              <Input className="h-11 lg:h-10" id="enroll-name" value={name} maxLength={40} onChange={(e) => setName(e.target.value)} autoComplete="off" />
            </div>
            <Button type="submit" className="h-11 w-full lg:h-10" disabled={busy || !passkeysSupported()} data-testid="enroll-passkey">
              {t('auth.enroll_passkey')}
            </Button>
            <Button type="button" variant="outline" className="h-11 w-full lg:h-10" onClick={() => setTotp(true)}>
              {t('auth.enroll_totp')}
            </Button>
          </form>
        )}
        {totp && <TotpSetup api={api} onDone={(s) => s && onStatus(s)} />}
        <Button variant="ghost" className="h-11 w-full lg:h-10" onClick={onSignOut}>
          {t('auth.second_signout')}
        </Button>
      </Card>
    </main>
  );
}
