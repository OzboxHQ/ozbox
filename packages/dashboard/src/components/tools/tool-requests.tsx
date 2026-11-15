import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ApiError, type ApiClient } from '../../api/client';
import type { Decision, ToolRequest } from '../../api/tools';
import { t } from '../../lib/i18n';
import { useAsync } from '../../lib/use-async';
import { useCan } from '../../lib/use-can';

/**
 * What agents on a box have asked for. An agent can only ask; the owner decides here: approve once, always allow that
 * tool, or deny. With nothing waiting it shows nothing unless `showEmpty` is set.
 */
export function ToolRequestList({ client, box, showEmpty, onChanged }: { client: ApiClient; box: string; showEmpty?: boolean; onChanged?: () => void }) {
  const { can } = useCan();
  const list = useAsync((s) => client.tools.requests(box, s), [client, box], 5000);
  const [busy, setBusy] = useState<string | null>(null);
  const pending = (list.data?.requests ?? []).filter((r: ToolRequest) => r.state === 'pending');

  async function decide(r: ToolRequest, d: Decision) {
    setBusy(r.id);
    try {
      await client.tools.decide(box, r.id, d);
      list.reload();
      onChanged?.();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('tools.decision_failed'));
    } finally {
      setBusy(null);
    }
  }

  if (list.error && !list.data) {
    // a 501 is the server saying it does not have these (a box's own dashboard): a statement, not a failure
    if (list.error instanceof ApiError && list.error.status === 501) {
      return (
        <p role="status" className="text-sm text-muted-foreground" data-testid="tool-requests-unavailable">
          {t('tools.requests_unavailable', { box, reason: list.error.message })}
        </p>
      );
    }
    return (
      <p role="alert" className="text-sm text-destructive" data-testid="tool-requests-error">
        {t('tools.requests_error', { box, reason: list.error.message })}
      </p>
    );
  }
  if (pending.length === 0) {
    return showEmpty ? <p className="text-sm text-muted-foreground">{t('tools.requests_none')}</p> : null;
  }
  return (
    <ul className="space-y-3" aria-label={t('tools.requests_title')} data-testid="tool-requests">
      {pending.map((r) => (
        <li key={r.id}>
          <Card className="flex flex-col gap-3 p-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="min-w-0 space-y-1">
              <p className="text-sm font-medium">{t('approvals.tool_request_line', { agent: r.requested_by, tool: r.tool, box })}</p>
              {r.reason && <p className="break-words text-sm text-muted-foreground">{t('tools.request_reason', { reason: r.reason })}</p>}
              <Badge variant="outline">{t('tools.requests_title')}</Badge>
            </div>
            {can('approve') ? (
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
              <Button className="max-lg:h-11" disabled={busy === r.id} onClick={() => decide(r, 'approve_once')}>
                {t('tools.approve_once')}
              </Button>
              <Button variant="outline" className="max-lg:h-11" disabled={busy === r.id} onClick={() => decide(r, 'approve_always')}>
                {t('tools.approve_always')}
              </Button>
              <Button variant="outline" className="max-lg:h-11" disabled={busy === r.id} onClick={() => decide(r, 'deny')}>
                {t('tools.deny')}
              </Button>
            </div>
            ) : (
              <p className="text-xs text-muted-foreground" data-testid="cannot-decide">{t('roles.cannot_approve_hint')}</p>
            )}
          </Card>
        </li>
      ))}
    </ul>
  );
}
