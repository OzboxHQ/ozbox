import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/error';
import type { LaptopKey } from '../api/approval-requests';
import type { Account } from '../api/session';
import { useApp } from '../App';
import { withStepUp } from '../components/perm/with-step-up';
import { AppLink } from '../components/page';
import { coolingUntil, enrolledViaText, keyPresenceText } from '../lib/approval-requests';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { hrefs } from '../lib/router';
import { useSession } from '../lib/session-context';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

function PasskeysCard() {
  const session = useSession();
  const account = useAsync<Account>((s) => (session ? session.api.account(s) : Promise.reject(new Error('no session'))), [session]);
  return (
    <Card className="min-w-0 space-y-3 p-4" data-testid="approvers-passkeys">
      <h2 className="text-sm font-semibold">{t('approvers.passkeys')}</h2>
      {!session ? (
        <p className="text-sm text-muted-foreground" data-testid="approvers-no-sign-in">{t('approvers.passkeys_no_sign_in')}</p>
      ) : !account.data ? (
        account.error ? <p role="alert" className="text-sm text-destructive">{account.error.message}</p> : <Skeleton className="h-16 w-full" />
      ) : (
        <>
          {account.data.passkeys.length === 0 ? <p className="text-sm text-muted-foreground">{t('approvers.passkeys_none')}</p> : null}
          <ul className="divide-y">
            {account.data.passkeys.map((p) => (
              <li key={p.id} className="min-w-0 py-2" data-testid="approvers-passkey">
                <p className="truncate text-sm font-medium">{p.name}</p>
                <p className="text-xs text-muted-foreground">{t('approvers.passkey_line', { created: fmtRelative(new Date(p.created_ms).toISOString()), used: fmtRelative(new Date(p.last_used_ms).toISOString()) })}</p>
              </li>
            ))}
          </ul>
          <AppLink href={hrefs.account} className="inline-flex min-h-11 items-center text-sm underline-offset-4 hover:underline lg:min-h-0" data-testid="approvers-add-passkey">
            {t('approvers.passkeys_add')}
          </AppLink>
        </>
      )}
    </Card>
  );
}

function KeyRow({ k, now, owner, onRevoke }: { k: LaptopKey; now: number; owner: boolean; onRevoke: (k: LaptopKey) => void }) {
  const presence = keyPresenceText(k);
  const cooling = coolingUntil(k, now);
  return (
    <li className="min-w-0 space-y-2 py-3" data-testid="approvers-key" data-key-id={k.id}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium [overflow-wrap:anywhere]" data-testid="approvers-key-id">{k.id}</p>
          <p className="text-xs text-muted-foreground [overflow-wrap:anywhere]" data-testid="approvers-key-type">{k.key_type}</p>
        </div>
        <Badge variant={k.presence === 'proved' ? 'secondary' : 'outline'} data-testid="approvers-key-presence">
          {presence.label}
        </Badge>
      </div>
      <p className="text-xs text-muted-foreground" data-testid="approvers-key-help">{presence.help}</p>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-sm">
        <dt className="text-xs text-muted-foreground">{t('approvers.col_via')}</dt>
        <dd className="[overflow-wrap:anywhere]" data-testid="approvers-key-via">{enrolledViaText(k.enrolled_via)}</dd>
        <dt className="text-xs text-muted-foreground">{t('approvers.col_active')}</dt>
        <dd data-testid="approvers-key-active">{cooling !== null ? t('approvers.cooling', { when: new Date(cooling).toLocaleString() }) : t('approvers.active_now')}</dd>
      </dl>
      {owner ? (
        <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" onClick={() => onRevoke(k)} data-testid="approvers-key-revoke">
          {t('approvers.revoke')}
        </Button>
      ) : null}
    </li>
  );
}

function LaptopKeysCard() {
  const { client } = useApp();
  const { role } = useCan();
  const keys = useAsync((s) => client.approvalRequests.keys(s), [client], 10_000);
  const [revoking, setRevoking] = useState<LaptopKey | null>(null);
  const now = Date.now();
  const owner = role === 'owner';
  return (
    <Card className="min-w-0 space-y-3 p-4" data-testid="approvers-keys">
      <h2 className="text-sm font-semibold">{t('approvers.keys')}</h2>
      {!keys.data ? (
        keys.error ? <p role="alert" className="text-sm text-destructive">{keys.error instanceof ApiError ? keys.error.message : t('approvers.keys_failed')}</p> : <Skeleton className="h-24 w-full" aria-label={t('approvers.loading')} />
      ) : !keys.data.available ? (
        <Alert data-testid="approvers-keys-unavailable">
          <AlertDescription>{t('approvers.keys_not_available')}</AlertDescription>
        </Alert>
      ) : (
        <>
          {keys.data.laptop_keys.length === 0 ? <p className="text-sm text-muted-foreground" data-testid="approvers-keys-none">{t('approvers.keys_none')}</p> : null}
          <ul className="divide-y">
            {keys.data.laptop_keys.map((k) => (
              <KeyRow key={k.id} k={k} now={now} owner={owner} onRevoke={setRevoking} />
            ))}
          </ul>
          {!owner && keys.data.laptop_keys.length > 0 ? <p className="text-xs text-muted-foreground">{t('approvers.owner_only')}</p> : null}
        </>
      )}
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title={t('approvers.revoke_title', { id: revoking?.id ?? '' })}
        description={t('approvers.revoke_body')}
        confirmLabel={t('approvers.revoke')}
        destructive
        onConfirm={async () => {
          if (!revoking) return;
          try {
            await withStepUp(() => client.approvalRequests.revokeKey(revoking.id));
            toast.success(t('approvers.revoked_toast'));
            setRevoking(null);
            keys.reload();
          } catch (e) {
            toast.error(e instanceof ApiError ? e.message : t('approvers.revoke_failed'));
            throw e;
          }
        }}
      />
    </Card>
  );
}

/** Settings, Approvers: who can approve a change on this box. Passkeys are managed on the account page; laptop keys here. */
export function ApproversSection() {
  return (
    <div className="space-y-4" data-testid="approvers-section">
      <Card className="space-y-2 p-4">
        <h2 className="text-sm font-semibold">{t('approvers.title')}</h2>
        <p className="text-sm text-muted-foreground">{t('approvers.intro')}</p>
        <p className="text-sm text-muted-foreground" data-testid="approvers-chat-note">{t('approvers.chat_note')}</p>
      </Card>
      <PasskeysCard />
      <LaptopKeysCard />
    </div>
  );
}
