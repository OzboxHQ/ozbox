import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';

import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../../api/error';
import type { ApiClient } from '../../api/client';
import type { RequestCard, RequestList } from '../../api/approval-requests';
import { requestFromSearch, sortRequests } from '../../lib/approval-requests';
import { t } from '../../lib/i18n';
import { hrefs } from '../../lib/router';
import type { AsyncState } from '../../lib/use-async';
import { AppLink } from '../page';
import { ApproveSheet } from './approve-sheet';
import { ChangeRequestCard } from './request-card';

/** A clock that ticks once a second, for the time left on each card. */
function useNow(everyMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(id);
  }, [everyMs]);
  return now;
}

/** True while there is something here a person may still decide: the page uses it to say "nothing waiting" truthfully. */
export function openRequests(list: RequestList | null): number {
  return list ? list.requests.filter((r) => r.state === 'pending' || r.state === 'approved').length : 0;
}

/**
 * The "Change requests" section of the Approvals page. The page owns the polling (every five seconds) and passes the state;
 * this draws it and runs the two decisions: approve (a passkey) and deny or revoke (a confirmation, no passkey).
 */
export function RequestInbox({ client, list }: { client: ApiClient; list: AsyncState<RequestList> }) {
  const now = useNow();
  const [approving, setApproving] = useState<RequestCard | null>(null);
  const [denying, setDenying] = useState<RequestCard | null>(null);
  const target = requestFromSearch(window.location.search);
  const scrolled = useRef<string | null>(null);
  const data = list.data;

  // A link from a chat message opens this page on one request: scroll to it once it is on the page, and keep it marked.
  useEffect(() => {
    if (!target || !data || scrolled.current === target) return;
    const el = document.getElementById(`request-${target}`);
    if (el) {
      scrolled.current = target;
      el.scrollIntoView({ block: 'center' });
    }
  }, [target, data]);

  if (!data) {
    if (list.error) {
      return (
        <p role="alert" className="text-sm text-destructive" data-testid="requests-error">
          {list.error instanceof ApiError ? list.error.message : t('areq.load_failed')}
        </p>
      );
    }
    return <Skeleton className="h-32 w-full" aria-label={t('areq.loading')} />;
  }

  if (!data.available) {
    return (
      <section aria-label={t('areq.title')} className="space-y-2" data-testid="requests-need-newer-box">
        <h2 className="text-sm font-semibold">{t('areq.title')}</h2>
        <p className="text-sm text-muted-foreground">{t('areq.need_newer_box')}</p>
        <AppLink href={hrefs.boxes} className="text-sm underline-offset-4 hover:underline">
          {t('areq.need_newer_box_link')}
        </AppLink>
      </section>
    );
  }

  const role = data.viewer.role;
  const cards = sortRequests(data.requests);

  return (
    <section aria-label={t('areq.title')} className="min-w-0 space-y-3" data-testid="requests-section">
      <div className="space-y-1">
        <h2 className="text-sm font-semibold">{t('areq.title')}</h2>
        <p className="text-sm text-muted-foreground">{t('areq.intro')}</p>
      </div>
      {role === null ? (
        <p role="status" className="rounded-md border bg-muted/50 px-3 py-2 text-sm text-muted-foreground" data-testid="requests-no-sign-in">
          {t('areq.no_sign_in')}
        </p>
      ) : role === 'viewer' ? (
        <p role="status" className="rounded-md border bg-muted/50 px-3 py-2 text-sm text-muted-foreground" data-testid="requests-viewer-note">
          {t('areq.viewer_note')}
        </p>
      ) : null}
      {cards.length === 0 ? (
        <p className="text-sm text-muted-foreground" data-testid="requests-empty">
          {t('areq.none')}
        </p>
      ) : (
        <ul className="space-y-3" aria-label={t('areq.title')}>
          {cards.map((c) => (
            <li key={c.id} className="min-w-0">
              <ChangeRequestCard card={c} role={role} now={now} highlighted={c.id === target} onApprove={setApproving} onDeny={setDenying} />
            </li>
          ))}
        </ul>
      )}

      {approving ? <ApproveSheet client={client} card={approving} onClose={() => setApproving(null)} onDecided={() => list.reload()} /> : null}

      <ConfirmDialog
        open={!!denying}
        onOpenChange={(o) => !o && setDenying(null)}
        title={denying?.state === 'approved' ? t('areq.revoke_title') : t('areq.deny_title')}
        description={denying?.state === 'approved' ? t('areq.revoke_body') : t('areq.deny_body')}
        confirmLabel={denying?.state === 'approved' ? t('areq.revoke') : t('areq.deny')}
        destructive
        onConfirm={async () => {
          if (!denying) return;
          const revoking = denying.state === 'approved';
          try {
            await client.approvalRequests.deny(denying.id);
            toast.success(revoking ? t('areq.revoked_toast') : t('areq.denied_toast'));
            setDenying(null);
            list.reload();
          } catch (e) {
            // the server's sentence as it is; a request someone else decided meanwhile is refreshed under the message
            toast.error(e instanceof ApiError ? e.message : t('areq.deny_failed'));
            if (e instanceof ApiError) {
              setDenying(null);
              list.reload();
              return;
            }
            throw e;
          }
        }}
      />
    </section>
  );
}
