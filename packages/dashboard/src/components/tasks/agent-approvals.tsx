import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { ApiError, type ApiClient } from '../../api/client';
import type { ApprovalRequest } from '../../api/tasks';
import { fmtRelative } from '../../lib/format';
import { t } from '../../lib/i18n';
import { askStepUp, STEP_UP_CODE } from '../../lib/step-up';
import { useCan } from '../../lib/use-can';
import { parseBrowserApproval } from '../../lib/browser';
import { KIND_KEY, minutesLeft } from '../../lib/tasks';

/** A browser step as a person reads it: where, what it would do, and the fields with secrets shown as masked. */
function BrowserStep({ action }: { action: string }) {
  const b = parseBrowserApproval(action);
  if (!b) return null;
  return (
    <div className="space-y-2 rounded-md border p-3" data-testid="browser-approval" data-host={b.host}>
      <p className="text-sm font-medium">{t('browser.approval_title')}: {b.action}</p>
      <p className="break-words text-xs text-muted-foreground">{t('browser.approval_where', { host: b.host })} · {b.reason}</p>
      {b.dest ? <p className="break-all text-xs" data-testid="browser-approval-dest">{t('browser.approval_dest', { dest: b.dest })}</p> : null}
      {b.check ? <p className="text-xs text-muted-foreground">{t('browser.approval_check', { check: b.check })}</p> : null}
      <p className="text-xs text-muted-foreground">{t('browser.approval_fields')}</p>
      {b.fields.length === 0 ? (
        <p className="text-sm">{t('browser.approval_none')}</p>
      ) : (
        <dl className="grid gap-x-3 gap-y-1 sm:grid-cols-[max-content_1fr]">
          {b.fields.map((f) => (
            <div key={f.name} className="contents" data-testid="browser-approval-field" data-masked={f.masked ? 'true' : 'false'}>
              <dt className="break-all text-sm font-medium">{f.name}</dt>
              <dd className="break-all text-sm">{f.masked ? <Badge variant="secondary">{t('browser.approval_masked')}</Badge> : f.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

/** Approve, asking for a fresh second factor first when the server says it is needed (sign-in mode). */
export async function approveWithStepUp(client: ApiClient, id: string): Promise<void> {
  try {
    await client.tasks.approve(id);
  } catch (e) {
    if (e instanceof ApiError && e.code === STEP_UP_CODE && (await askStepUp())) {
      await client.tasks.approve(id);
      return;
    }
    throw e;
  }
}

/** The requests agents have raised: the exact action, who asked, when it lapses, and Approve or Deny. */
export function AgentApprovals({ client, pending, recent, reload }: { client: ApiClient; pending: ApprovalRequest[]; recent: ApprovalRequest[]; reload: () => void }) {
  const { can } = useCan();
  const [confirm, setConfirm] = useState<ApprovalRequest | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function decide(a: ApprovalRequest, approve: boolean) {
    setBusy(a.id);
    try {
      if (approve) await approveWithStepUp(client, a.id);
      else await client.tasks.deny(a.id);
      toast.success(t('approvals.decided_ok'));
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('approvals.decide_failed'));
      throw e;
    } finally {
      setBusy(null);
      reload();
    }
  }

  return (
    <section aria-label={t('approvals.agent_title')} className="space-y-3" data-testid="agent-approvals">
      <div>
        <h2 className="text-sm font-semibold">{t('approvals.agent_title')}</h2>
        <p className="text-xs text-muted-foreground">{t('approvals.agent_desc')}</p>
      </div>
      {pending.length === 0 ? <p className="text-sm text-muted-foreground">{t('approvals.agent_none')}</p> : null}
      <ul className="space-y-3" aria-label={t('approvals.agent_list')}>
        {pending.map((a) => (
          <li key={a.id}>
            <Card className="space-y-3 p-4" data-testid="agent-approval" data-kind={a.kind}>
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-medium">{t(KIND_KEY[a.kind])}</p>
                {a.production ? <Badge variant="destructive">{t('approvals.production')}</Badge> : null}
                {a.needs_step_up ? (
                  <Badge variant="secondary" title={t('approvals.step_up_hint')}>
                    {t('approvals.step_up')}
                  </Badge>
                ) : null}
              </div>
              <BrowserStep action={a.action} />
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">{t('approvals.exact')}</p>
                <code className="block whitespace-pre-wrap break-all rounded-md border bg-muted px-3 py-2 text-sm" data-testid="exact-action">
                  {a.action}
                </code>
              </div>
              <p className="break-words text-xs text-muted-foreground">
                {t('approvals.asked_by', { who: a.asked_by })} · {t('approvals.on_box', { box: a.box })} · {t('approvals.expires_in', { n: minutesLeft(a) })}
              </p>
              {a.can_decide && can('approve') ? (
                <div className="flex flex-col gap-2 sm:flex-row">
                  <Button className="max-lg:h-11" disabled={busy === a.id} onClick={() => setConfirm(a)}>
                    {busy === a.id ? t('approvals.approving') : t('approvals.approve')}
                  </Button>
                  <Button variant="outline" className="max-lg:h-11" disabled={busy === a.id} onClick={() => decide(a, false).catch(() => undefined)}>
                    {t('approvals.deny')}
                  </Button>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground" data-testid="cannot-decide">
                  <strong className="font-medium">{t('approvals.not_allowed')}</strong> {can('approve') ? t('approvals.not_allowed_hint') : t('roles.cannot_approve_hint')}
                </p>
              )}
            </Card>
          </li>
        ))}
      </ul>
      {recent.length > 0 ? (
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">{t('approvals.recent')}</h3>
          <ul className="space-y-1 text-xs text-muted-foreground">
            {recent.map((a) => (
              <li key={a.id} className="break-words">
                <span className="font-mono">{a.action}</span> · {t('approvals.recent_line', { state: t(`approvals.state_${a.state}`), who: a.decided_by ?? '-' })}
                {a.decided_ms ? ` · ${fmtRelative(new Date(a.decided_ms).toISOString())}` : ''}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={t('approvals.approve_title')}
        description={`${t('approvals.approve_body', { action: confirm?.action ?? '' })}${confirm?.production ? t('approvals.approve_prod') : ''}`}
        confirmLabel={t('approvals.approve')}
        onConfirm={() => (confirm ? decide(confirm, true) : undefined)}
      />
    </section>
  );
}
