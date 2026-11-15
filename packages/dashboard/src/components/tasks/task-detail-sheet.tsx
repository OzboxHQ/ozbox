import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError, type ApiClient } from '../../api/client';
import type { Task } from '../../api/tasks';
import { t } from '../../lib/i18n';
import { navigate, hrefs } from '../../lib/router';
import { offeredActions, parseCount, parseDollars, safeHref } from '../../lib/tasks';
import { useAsync } from '../../lib/use-async';
import { useCan } from '../../lib/use-can';
import { CannotNote } from '../role-scope';
import { costSourceText, costText, fallbackText, modelText, originText, StateBadge, timeText, whyLine } from './task-bits';

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm">{children}</dd>
    </div>
  );
}

/** Add budget to a run paused at a limit; it continues from its saved work. */
function ResumeForm({ client, task, onDone }: { client: ApiClient; task: Task; onDone: () => void }) {
  const [usd, setUsd] = useState('');
  const [min, setMin] = useState('');
  const [tok, setTok] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const monthly = task.needs?.kind === 'monthly_cap';

  async function go() {
    const add: { add_cents?: number; add_minutes?: number; add_tokens?: number } = {};
    if (usd.trim()) {
      const c = parseDollars(usd);
      if (c === null) return setErr(t('tasks.new_err_dollars'));
      add.add_cents = c;
    }
    if (min.trim()) {
      const m = parseCount(min, 5);
      if (m === null) return setErr(t('tasks.new_err_number'));
      add.add_minutes = m;
    }
    if (tok.trim()) {
      const k = parseCount(tok);
      if (k === null) return setErr(t('tasks.new_err_number'));
      add.add_tokens = k;
    }
    if (Object.keys(add).length === 0 || Object.values(add).every((v) => v === 0)) return setErr(t('tasks.resume_need'));
    setErr(null);
    setBusy(true);
    try {
      await client.tasks.resume(task.id, add);
      toast.success(t('tasks.resume_done'));
      onDone();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('tasks.action_failed'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="space-y-3 rounded-md border p-3" aria-label={t('tasks.resume_title')} data-testid="resume-form">
      <h3 className="text-sm font-semibold">{t('tasks.resume_title')}</h3>
      <p className="text-xs text-muted-foreground">{monthly ? t('tasks.resume_monthly_hint') : t('tasks.resume_desc')}</p>
      {err ? (
        <p role="alert" className="text-sm text-destructive">
          {err}
        </p>
      ) : null}
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1">
          <Label htmlFor="rs-usd">{t('tasks.resume_spend')}</Label>
          <Input id="rs-usd" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={usd} onChange={(e) => setUsd(e.target.value)} />
        </div>
        <div className="space-y-1">
          <Label htmlFor="rs-min">{t('tasks.resume_minutes')}</Label>
          <Input id="rs-min" inputMode="numeric" autoComplete="off" className="max-lg:h-11" value={min} onChange={(e) => setMin(e.target.value)} />
        </div>
        <div className="space-y-1">
          <Label htmlFor="rs-tok">{t('tasks.resume_tokens')}</Label>
          <Input id="rs-tok" inputMode="numeric" autoComplete="off" className="max-lg:h-11" value={tok} onChange={(e) => setTok(e.target.value)} />
        </div>
      </div>
      <Button className="max-lg:h-11" disabled={busy} onClick={go}>
        {t('tasks.resume_go')}
      </Button>
    </section>
  );
}

/** One run in full: its log, its limits, its results, and what a person can do next. */
export function TaskDetailSheet({ client, id, onClose, onChanged }: { client: ApiClient; id: string; onClose: () => void; onChanged: () => void }) {
  const task = useAsync((s) => client.tasks.get(id, s), [client, id], 2500);
  const logs = useAsync((s) => client.tasks.logs(id, s), [client, id], 2500);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const tk = task.data;
  const { can } = useCan();
  const mayAct = can('start_runs');
  const actions = tk ? offeredActions(tk, mayAct) : [];

  async function act(f: () => Promise<unknown>, ok?: string) {
    setErr(null);
    try {
      await f();
      if (ok) toast.success(ok);
      task.reload();
      logs.reload();
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('tasks.action_failed'));
    }
  }

  const why = tk ? whyLine(tk) : null;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="task-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tasks.detail_title', { id })}</PanelSheetTitle>
          {tk ? (
            <PanelSheetDescription>
              {t('tasks.on_box', { box: tk.box })} · {tk.engine} · {t('tasks.by', { person: tk.person })}
            </PanelSheetDescription>
          ) : null}
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {!tk && !task.error ? <Skeleton className="h-40 w-full" /> : null}
          {task.error && !tk ? (
            <p role="alert" className="text-sm text-destructive">
              {task.error.message}
            </p>
          ) : null}
          {task.error && tk ? (
            <p role="status" className="text-xs text-destructive" data-testid="task-stale">
              {t('tasks.refresh_failed', { reason: task.error.message })}
            </p>
          ) : null}
          {err ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{err}</AlertDescription>
            </Alert>
          ) : null}
          {tk ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <StateBadge state={tk.state} />
                {why ? <span className="text-sm">{why}</span> : null}
                {tk.cancelling ? <span className="text-sm text-muted-foreground">{t('tasks.detail_cancelling')}</span> : null}
              </div>
              <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <Fact label={t('tasks.cost')}>
                  {costText(tk)}
                  {costSourceText(tk) ? <span className="block text-xs text-muted-foreground">{costSourceText(tk)}</span> : null}
                </Fact>
                {modelText(tk) ? (
                  <Fact label={t('tasks.model')}>
                    <span data-testid="task-detail-model">{modelText(tk)}</span>
                    {fallbackText(tk) ? (
                      <span className="block text-xs text-muted-foreground" data-testid="task-detail-fallback">
                        {fallbackText(tk)}
                      </span>
                    ) : null}
                  </Fact>
                ) : null}
                <Fact label={t('tasks.elapsed')}>{timeText(tk)}</Fact>
                <Fact label={t('tasks.detail_tokens')}>
                  {tk.caps.max_tokens === null ? t('tasks.tokens_n', { n: tk.tokens }) : `${t('tasks.tokens_n', { n: tk.tokens })} ${t('tasks.of_cap', { cap: tk.caps.max_tokens })}`}
                </Fact>
                {tk.repo ? <Fact label={t('tasks.new_repo')}>{tk.repo}</Fact> : null}
                {tk.branch ? <Fact label={t('tasks.new_branch')}>{tk.branch}</Fact> : null}
                {originText(tk) ? <Fact label={t('tasks.col_started')}>{originText(tk)}</Fact> : null}
                {tk.retry_of ? <Fact label={t('tasks.col_started')}>{t('tasks.retry_of', { id: tk.retry_of })}</Fact> : null}
              </dl>
              <section aria-label={t('tasks.detail_prompt')} className="space-y-1">
                <h3 className="text-sm font-semibold">{t('tasks.detail_prompt')}</h3>
                <p className="whitespace-pre-wrap break-words text-sm">{tk.prompt}</p>
              </section>
              {tk.wip_branch ? (
                <section aria-label={t('tasks.detail_saved')} className="space-y-1">
                  <h3 className="text-sm font-semibold">{t('tasks.detail_saved')}</h3>
                  <code className="block break-all rounded bg-muted px-2 py-1 text-xs">{tk.wip_branch}</code>
                  <p className="text-xs text-muted-foreground">{t('tasks.detail_saved_hint')}</p>
                </section>
              ) : null}
              {tk.links.length > 0 ? (
                <section aria-label={t('tasks.detail_links')} className="space-y-1">
                  <h3 className="text-sm font-semibold">{t('tasks.detail_links')}</h3>
                  <ul className="space-y-1 text-sm">
                    {tk.links.map((l) => {
                      const href = safeHref(l.url);
                      return (
                        <li key={`${l.kind}:${l.url}`}>
                          {href ? (
                            <a href={href} target="_blank" rel="noreferrer noopener" className="inline-flex min-h-11 items-center underline underline-offset-4 lg:min-h-0">
                              {l.label}
                            </a>
                          ) : (
                            <span>{l.label}</span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </section>
              ) : null}
              {tk.summary ? (
                <section aria-label={t('tasks.detail_summary')} className="space-y-1">
                  <h3 className="text-sm font-semibold">{t('tasks.detail_summary')}</h3>
                  <p className="whitespace-pre-wrap break-words text-sm">{tk.summary}</p>
                </section>
              ) : null}
              {tk.error ? (
                <section aria-label={t('tasks.detail_error')} className="space-y-1">
                  <h3 className="text-sm font-semibold">{t('tasks.detail_error')}</h3>
                  <p className="break-words text-sm text-destructive">{tk.error}</p>
                </section>
              ) : null}
              {actions.includes('resume') && tk ? <ResumeForm client={client} task={tk} onDone={() => { task.reload(); onChanged(); }} /> : null}
              {tk.needs?.kind === 'approval' ? (
                <Button
                  variant="outline"
                  className="max-lg:h-11"
                  onClick={() => {
                    onClose();
                    navigate(hrefs.approvals);
                  }}
                >
                  {t('tasks.detail_to_inbox')}
                </Button>
              ) : null}
              <section aria-label={t('tasks.detail_log')} className="space-y-1">
                <h3 className="text-sm font-semibold">{t('tasks.detail_log')}</h3>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted p-3 font-mono text-xs leading-5" data-testid="task-log">
                  {logs.data && logs.data.lines.length > 0 ? logs.data.lines.join('\n') : t('tasks.detail_log_empty')}
                </pre>
              </section>
            </>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" onClick={onClose}>
            {t('common.close')}
          </Button>
          {tk && !mayAct ? <CannotNote cap="start_runs" /> : null}
          {tk && actions.includes('cancel') ? (
            <Button variant="outline" className="max-lg:h-11" onClick={() => setConfirmCancel(true)}>
              {t('tasks.detail_cancel')}
            </Button>
          ) : null}
          {tk && actions.includes('retry') ? (
            <Button
              className="max-lg:h-11"
              onClick={() => act(async () => {
                const r = await client.tasks.retry(tk.id);
                toast.success(t('tasks.retried', { id: r.id }));
              })}
            >
              {t('tasks.detail_retry')}
            </Button>
          ) : null}
          {tk && actions.includes('review') ? (
            <Button variant="outline" className="max-lg:h-11" onClick={() => act(() => client.tasks.review(tk.id), t('tasks.acted'))}>
              {t('tasks.detail_review')}
            </Button>
          ) : null}
          {tk && actions.includes('accept') ? (
            <Button className="max-lg:h-11" onClick={() => act(() => client.tasks.accept(tk.id), t('tasks.acted'))}>
              {t('tasks.detail_accept')}
            </Button>
          ) : null}
        </PanelSheetFooter>
        <ConfirmDialog
          open={confirmCancel}
          onOpenChange={setConfirmCancel}
          title={t('tasks.cancel_title')}
          description={t('tasks.cancel_body')}
          confirmLabel={t('tasks.cancel_verb')}
          destructive
          onConfirm={() => act(() => client.tasks.cancel(id), t('tasks.acted'))}
        />
      </PanelSheetContent>
    </PanelSheet>
  );
}
