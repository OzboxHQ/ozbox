import { useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useApp } from '../App';
import { PlanSheet } from '../components/box-action-sheets';
import { AppLink, AppPage, EmptyState, PageHeader } from '../components/page';
import { openRequests, RequestInbox } from '../components/approvals/request-inbox';
import { AgentApprovals } from '../components/tasks/agent-approvals';
import { ToolRequestList } from '../components/tools/tool-requests';
import { t } from '../lib/i18n';
import { ApiError } from '../api/client';
import type { Approval } from '../api/types';
import { fmtRelative, ABSENT } from '../lib/format';
import { riskLabel } from '../lib/plan-flow';
import { hrefs } from '../lib/router';
import { useAsync } from '../lib/use-async';
import { usePlanFlow } from '../lib/use-plan-flow';
import { toast } from 'sonner';

/** One inbox for plans that were proposed and are waiting for someone to apply them. */
export function ApprovalsPage() {
  const { client } = useApp();
  const list = useAsync((s) => client.approvals(s), [client], 5000);
  // Change requests filed on a box (ADR 0041), polled like the plans above.
  const requests = useAsync((s) => client.approvalRequests.list(s), [client], 5000);
  const boxes = useAsync((s) => client.listBoxes(s), [client], 15000);
  const flow = usePlanFlow(client, () => list.reload());
  // Tool requests from agents live in their own lists; the empty state has to know whether any are waiting.
  const running = (boxes.data ?? []).filter((b) => b.state === 'running').map((b) => b.spec.name);
  const toolRequests = useAsync(
    async (s) => {
      const all = await Promise.all(running.map((n) => client.tools.requests(n, s).then((r) => ({ r, bad: false })).catch((e: unknown) => ({ r: null, bad: !(e instanceof ApiError && e.status === 501) }))));
      return { pending: all.reduce((sum, x) => sum + (x.r ? x.r.requests.filter((q) => q.state === 'pending').length : 0), 0), failed: all.filter((x) => x.bad).length };
    },
    [client, running.join(',')],
    8000,
  );
  const toolPending = toolRequests.data?.pending ?? 0;
  // Requests that agents raised (a push to a protected branch, a risky command, ...). A server with no task store answers 501.
  const agent = useAsync((s) => client.tasks.approvals(true, s), [client], 3000);
  const agentAll = agent.data?.items ?? [];
  const agentUnavailable = agent.error instanceof ApiError && agent.error.status === 501;
  const agentPending = agentAll.filter((a) => a.state === 'pending');
  const agentRecent = agentAll.filter((a) => a.state !== 'pending').slice(0, 5);
  const [busy, setBusy] = useState<string | null>(null);

  async function review(a: Approval) {
    setBusy(a.plan_id);
    try {
      flow.open(await client.getPlan(a.plan_id));
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('approvals.open_failed'));
      list.reload();
    } finally {
      setBusy(null);
    }
  }

  const items = list.data?.items ?? [];
  // "Nothing waiting" is only said when every source answered: a source that failed may be holding something.
  const anyError = !!(list.error || requests.error || (agent.error && !agentUnavailable) || (toolRequests.data?.failed ?? 0) > 0);
  const ttlMin = Math.max(1, Math.round((list.data?.ttl_s ?? 600) / 60));
  return (
    <AppPage>
      <PageHeader title={t('approvals.title')} description={t('approvals.desc')} />
      <RequestInbox client={client} list={requests} />
      {agent.data ? <AgentApprovals client={client} pending={agentPending} recent={agentRecent} reload={agent.reload} /> : null}
      {!agent.data && agentUnavailable ? (
        <section aria-label={t('approvals.agent_title')} className="space-y-1" data-testid="agent-approvals-unavailable">
          <h2 className="text-sm font-semibold">{t('approvals.agent_title')}</h2>
          <p className="text-sm text-muted-foreground">{agent.error?.message ?? t('approvals.agent_unavailable')}</p>
        </section>
      ) : null}
      {!agent.data && agent.error && !agentUnavailable ? (
        <section aria-label={t('approvals.agent_title')} className="space-y-1" data-testid="agent-approvals-error">
          <h2 className="text-sm font-semibold">{t('approvals.agent_title')}</h2>
          <p role="alert" className="text-sm text-destructive">{t('approvals.agent_error', { reason: agent.error.message })}</p>
        </section>
      ) : null}
      {agent.data && agent.error ? <p role="status" className="text-xs text-destructive">{t('approvals.refresh_failed', { what: t('approvals.agent_title').toLowerCase(), reason: agent.error.message })}</p> : null}
      {(boxes.data ?? []).some((b) => b.state === 'running') && (
        <section aria-label={t('approvals.tool_requests')} className="space-y-3">
          {(boxes.data ?? [])
            .filter((b) => b.state === 'running')
            .map((b) => (
              <ToolRequestList key={b.spec.name} client={client} box={b.spec.name} />
            ))}
        </section>
      )}
      {!list.data && !list.error && <Skeleton className="h-32 w-full" />}
      {list.error && !list.data && (
        <section aria-label={t('approvals.plans_title')} className="space-y-1" data-testid="plans-error">
          <h2 className="text-sm font-semibold">{t('approvals.plans_title')}</h2>
          <p role="alert" className="text-sm text-destructive">{t('approvals.plans_error', { reason: list.error.message })}</p>
        </section>
      )}
      {list.data && list.error && <p role="status" className="text-xs text-destructive">{t('approvals.refresh_failed', { what: t('approvals.plans_title').toLowerCase(), reason: list.error.message })}</p>}
      {list.data && !anyError && items.length === 0 && agentPending.length === 0 && openRequests(requests.data) === 0 && <EmptyState title={t('approvals.none')}>{toolPending > 0 ? t('approvals.only_requests', { n: toolPending }) : requests.data?.available === false ? t('approvals.none_partial') : t('approvals.none_body')}</EmptyState>}
      {items.length > 0 && <h2 className="text-sm font-semibold">{t('approvals.plans_title')}</h2>}
      {items.length > 0 && (
        <ul className="space-y-3" aria-label={t('approvals.pending')}>
          {items.map((a) => (
            <li key={a.plan_id}>
              <Card className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0 space-y-1">
                  <p className="text-sm font-medium">
                    <span className="capitalize">{a.verb}</span>{' '}
                    <AppLink href={hrefs.box(a.box_name)} className="underline-offset-4 hover:underline">
                      {a.box_name}
                    </AppLink>
                  </p>
                  <p className="text-xs text-muted-foreground">{`${a.changes === 1 ? t('approvals.changes_one') : t('approvals.changes_many', { n: a.changes })} · ${t('approvals.proposed', { when: fmtRelative(new Date(a.proposed_ms).toISOString()) })} · ${t('approvals.expires', { n: Math.max(1, Math.round(a.expires_in_s / 60)) })}`}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {a.max_risk && <Badge variant={a.max_risk === 'high' ? 'destructive' : 'outline'}>{riskLabel(a.max_risk)}</Badge>}
                    {a.needs_passkey && (
                      <Badge variant="secondary" title={t('approvals.passkey_hint')}>
                        {t('approvals.passkey')}
                      </Badge>
                    )}
                  </div>
                </div>
                <Button className="w-full sm:w-auto max-lg:h-11" disabled={busy === a.plan_id} onClick={() => review(a)}>
                  {busy === a.plan_id ? t('approvals.opening') : t('approvals.review')}
                </Button>
              </Card>
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-muted-foreground" data-testid="plans-memory-note">{list.data ? t('approvals.footer', { n: ttlMin }) : ABSENT}</p>
      <PlanSheet state={flow.state} dispatch={flow.dispatch} onClose={() => flow.dispatch({ type: 'cancel' })} />
    </AppPage>
  );
}
