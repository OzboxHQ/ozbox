import { useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useApp } from '../App';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { providerState, STATE_LABEL, STATE_NOTE, type ProviderState } from '../lib/provider-check';
import { useAsync } from '../lib/use-async';
import type { ProviderCheck } from '../api/types';

const VARIANT: Record<ProviderState, 'default' | 'outline' | 'destructive' | 'secondary'> = {
  checking: 'outline',
  connected: 'default',
  failed: 'destructive',
  demo: 'secondary',
  this_box: 'secondary',
  unknown: 'destructive',
};

/**
 * The provider's connection, asked of the provider just now (not read off a loaded page). The badge says Connected only for a
 * real provider that answered; the demo says Demo and a box's own dashboard says This box. A check that fails says why.
 */
export function ProviderStatus({ children }: { children: (check: ProviderCheck | null) => React.ReactNode }) {
  const { client } = useApp();
  const [round, setRound] = useState(0);
  const q = useAsync<ProviderCheck>((s) => client.providerCheck(s), [client, round]);
  const check = q.data ?? null;
  const state = providerState(check, !!q.error && !check);
  const note = STATE_NOTE[state];
  return (
    <>
      <div className="flex flex-wrap items-center gap-2" data-testid="provider-status" data-state={state}>
        <Badge variant={VARIANT[state]} data-testid="provider-badge">
          {t(STATE_LABEL[state])}
        </Badge>
        <Button variant="outline" size="sm" className="max-lg:h-11" disabled={state === 'checking'} onClick={() => setRound((n) => n + 1)} data-testid="provider-recheck">
          {t('provider.check_now')}
        </Button>
        {check ? <span className="text-xs text-muted-foreground">{t('provider.checked', { when: fmtRelative(new Date(check.checked_ms).toISOString()) })}</span> : null}
      </div>
      {state === 'failed' && check?.error ? (
        <Alert variant="destructive" role="alert" data-testid="provider-error">
          <AlertDescription>{check.error}</AlertDescription>
        </Alert>
      ) : null}
      {state === 'unknown' && q.error ? (
        <Alert variant="destructive" role="alert" data-testid="provider-error">
          <AlertDescription>{q.error.message}</AlertDescription>
        </Alert>
      ) : null}
      {note ? (
        <p className="text-xs text-muted-foreground" data-testid="provider-note">
          {t(note)}
        </p>
      ) : null}
      {children(check)}
    </>
  );
}
