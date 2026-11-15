import { useEffect, useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { useApp } from '../App';
import { AppPage, PageHeader } from '../components/page';
import { t } from '../lib/i18n';
import { navigate } from '../lib/router';
import { pointerToken, safeInternalPath } from '../lib/telegram-flow';

/**
 * Where a link from a chat lands (ADR 0050 §2). The token is in the address's fragment, so no server, tunnel or proxy ever sees
 * it in a request line; the page takes it out of the address bar at once and sends it in a request body. Opening it changes
 * nothing and spends nothing: it only names the page to go to, and anything that needs approval asks for a passkey there.
 */
export function GoPage() {
  const { client } = useApp();
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const token = pointerToken(window.location.hash);
    // the fragment leaves the address bar whatever happens next
    window.history.replaceState(null, '', window.location.pathname);
    if (!token) {
      setFailed(true);
      return;
    }
    client.telegram
      .openPointer(token)
      .then((r) => {
        const p = safeInternalPath(r.path);
        if (p) navigate(p);
        else setFailed(true);
      })
      .catch(() => setFailed(true));
  }, [client]);
  return (
    <AppPage>
      <PageHeader title={t('tg.go_title')} description={t('tg.go_help')} />
      {failed ? (
        <Alert variant="destructive" role="alert" data-testid="go-failed">
          <AlertDescription>{t('tg.go_failed')}</AlertDescription>
        </Alert>
      ) : (
        <Skeleton className="h-10 w-full" />
      )}
    </AppPage>
  );
}
