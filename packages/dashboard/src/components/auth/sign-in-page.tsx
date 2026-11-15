import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { SessionApi, SessionStatus } from '../../api/session';
import { returnMessage, signInMessage } from '../../lib/auth-errors';
import { t } from '../../lib/i18n';
import { getPasskey, passkeysSupported } from '../../lib/webauthn';
import { GithubDevice } from './github-device';

const BTN = 'h-11 w-full lg:h-10';

export function SignInPage({ api, status, onStatus }: { api: SessionApi; status: SessionStatus; onStatus: (s: SessionStatus) => void }) {
  const [error, setError] = useState<string | null>(() => returnMessage(window.location.search));
  const [busy, setBusy] = useState(false);
  const [github, setGithub] = useState(false);
  const [code, setCode] = useState('');
  const [person, setPerson] = useState('');
  const m = status.methods;

  const passkey = async () => {
    setBusy(true);
    setError(null);
    try {
      const o = await api.loginOptions();
      const cred = await getPasskey(o.options);
      onStatus(await api.loginVerify(o.ceremony, cred));
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async () => {
    setBusy(true);
    setError(null);
    try {
      onStatus(await api.setupCode(code, person.trim().toLowerCase()));
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main id="main" className="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-4 p-4 sm:p-6">
      <Card className="space-y-4 p-5">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">{t('auth.title')}</h1>
          <p className="text-sm text-muted-foreground">{t('auth.intro')}</p>
        </div>
        {error && (
          <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">
            {error}
          </p>
        )}
        <Button className={BTN} onClick={() => void passkey()} disabled={busy || !passkeysSupported()} data-testid="passkey-signin">
          {busy ? t('auth.passkey_working') : t('auth.passkey_button')}
        </Button>
        {!passkeysSupported() && <p className="text-sm text-muted-foreground">{t('auth.passkey_unsupported')}</p>}

        {(m.github || m.google || m.access) && (
          <>
            <p className="text-center text-xs uppercase tracking-wide text-muted-foreground">{t('auth.or')}</p>
            <div className="space-y-2">
              {m.github && (
                <Button variant="outline" className={BTN} onClick={() => setGithub(true)} data-testid="github-signin">
                  {t('auth.github_button')}
                </Button>
              )}
              {m.google && (
                <Button asChild variant="outline" className={BTN}>
                  <a href="/auth/google/start">{t('auth.google_button')}</a>
                </Button>
              )}
              {m.access && (
                <Button variant="outline" className={BTN} onClick={() => void api.accessExchange().then(onStatus).catch((e: unknown) => setError(signInMessage(e)))}>
                  {t('auth.access_button')}
                </Button>
              )}
            </div>
          </>
        )}
        {github && <GithubDevice api={api} onStatus={onStatus} onCancel={() => setGithub(false)} />}
      </Card>

      {m.setup_code && (
        <Card className="p-5">
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void submitCode();
            }}
          >
            <h2 className="text-base font-semibold">{t('auth.setup_code_heading')}</h2>
            <p className="text-sm text-muted-foreground">{t('auth.setup_code_body')}</p>
            <div className="space-y-1">
              <Label htmlFor="setup-code">{t('auth.setup_code_label')}</Label>
              <Input id="setup-code" autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} className="h-11 font-mono lg:h-10" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="setup-person">{t('auth.setup_person_label')}</Label>
              <Input className="h-11 lg:h-10" id="setup-person" autoComplete="username" value={person} onChange={(e) => setPerson(e.target.value)} />
            </div>
            <Button type="submit" className={BTN} disabled={busy || !code || !person}>
              {t('auth.setup_code_button')}
            </Button>
          </form>
        </Card>
      )}
    </main>
  );
}
