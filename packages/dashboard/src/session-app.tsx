import { useCallback, useEffect, useMemo, useState } from 'react';

import { App } from './App';
import { createApiClient } from './api/client';
import type { SessionApi, SessionStatus } from './api/session';
import { EnrollPage } from './components/auth/enroll-page';
import { SecondFactorPage } from './components/auth/second-factor-page';
import { SignInPage } from './components/auth/sign-in-page';
import { StepUpHost } from './components/auth/step-up-host';
import { t } from './lib/i18n';
import { SessionCtx, type SessionValue } from './lib/session-context';

/** The dashboard behind a sign-in: shows whichever step the person is at, and the app once they are in. */
export function SessionApp({ api, initial }: { api: SessionApi; initial: SessionStatus }) {
  const [status, setStatus] = useState<SessionStatus>(initial);
  const [lost, setLost] = useState(false);

  const refresh = useCallback(async () => {
    const s = await api.status();
    if (s.mode === 'session') setStatus(s);
  }, [api]);

  const signOut = useCallback(
    async (everywhere: boolean) => {
      try {
        await api.signOut(everywhere);
      } finally {
        await refresh().catch(() => undefined);
      }
    },
    [api, refresh],
  );

  // A session can end on the server (idle, revoked): the next ask of the server says so, and we go back to the start.
  useEffect(() => {
    const on = (e: Event) => {
      if ((e as CustomEvent<number>).detail === 401) void refresh().then(() => setLost(true)).catch(() => undefined);
    };
    window.addEventListener('ozbox:unauthorized', on);
    return () => window.removeEventListener('ozbox:unauthorized', on);
  }, [refresh]);

  // Drop the address's `?signin=` once it has been read.
  useEffect(() => {
    if (window.location.search.includes('signin=')) window.history.replaceState(null, '', window.location.pathname);
  }, []);

  const client = useMemo(() => createApiClient({ csrf: () => api.csrf() }), [api]);
  const value = useMemo<SessionValue>(() => ({ api, status, refresh, signOut }), [api, status, refresh, signOut]);

  if (status.state === 'signed_in') {
    return (
      <SessionCtx.Provider value={value}>
        <App client={client} onSignOut={() => void signOut(false)} />
        <StepUpHost />
      </SessionCtx.Provider>
    );
  }
  if (status.state === 'needs_second_factor') return <SecondFactorPage api={api} status={status} onStatus={setStatus} onSignOut={() => void signOut(false)} />;
  if (status.state === 'enroll_required') return <EnrollPage api={api} onStatus={setStatus} onSignOut={() => void signOut(false)} />;
  return (
    <>
      {lost && (
        <p role="status" className="p-3 text-center text-sm text-muted-foreground">
          {t('auth.error_expired')}
        </p>
      )}
      <SignInPage api={api} status={status} onStatus={setStatus} />
    </>
  );
}
