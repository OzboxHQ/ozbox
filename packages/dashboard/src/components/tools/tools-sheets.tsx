import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import type { ApiClient } from '../../api/client';
import type { ToolJob, ToolPlan } from '../../api/tools';
import { t } from '../../lib/i18n';
import { isFinished, jobProgress, sizeLabel, validBoxName, validProfileName } from '../../lib/tools';
import { useAsync } from '../../lib/use-async';

export type PlanPhase =
  | { phase: 'idle' }
  | { phase: 'planning' }
  | { phase: 'review'; plan: ToolPlan; install: string[]; remove: string[] }
  | { phase: 'starting'; plan: ToolPlan; install: string[]; remove: string[] }
  | { phase: 'error'; message: string };

/** The plan, shown before anything changes: tools with sizes, the steps in order, the total. Apply is in the footer. */
export function ToolPlanSheet({ state, onApply, onClose }: { state: PlanPhase; onApply: () => void; onClose: () => void }) {
  const open = state.phase !== 'idle';
  const plan = state.phase === 'review' || state.phase === 'starting' ? state.plan : null;
  const busy = state.phase === 'starting';
  const nothing = plan !== null && plan.steps.length === 0;
  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <PanelSheetContent size="compact" data-testid="tool-plan-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tools.plan_title')}</PanelSheetTitle>
          <PanelSheetDescription>{state.phase === 'planning' ? t('tools.plan_preparing') : t('tools.plan_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {state.phase === 'planning' && (
            <div role="status" aria-label={t('tools.plan_preparing')} className="space-y-2">
              <Skeleton className="h-5 w-3/4" />
              <Skeleton className="h-5 w-1/2" />
            </div>
          )}
          {state.phase === 'error' && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{state.message}</AlertDescription>
            </Alert>
          )}
          {plan && (
            <>
              {nothing ? (
                <p className="text-sm">{t('tools.plan_nothing')}</p>
              ) : (
                <>
                  <section aria-label={t('tools.plan_tools')}>
                    <ul className="divide-y rounded-md border text-sm">
                      {plan.tools.map((tool) => (
                        <li key={`${tool.op}-${tool.id}`} className="flex flex-wrap items-center justify-between gap-2 p-3">
                          <span className="flex min-w-0 flex-wrap items-center gap-2">
                            <Badge variant={tool.op === 'remove' ? 'destructive' : 'outline'}>{tool.op === 'remove' ? t('tools.plan_remove') : t('tools.plan_install')}</Badge>
                            <span className="font-medium">{tool.name}</span>
                            {tool.reason.startsWith('required_by:') && (
                              <span className="text-xs text-muted-foreground">{t('tools.plan_needed_by', { tool: tool.reason.slice('required_by:'.length) })}</span>
                            )}
                          </span>
                          {tool.op === 'install' && <span className="text-xs text-muted-foreground">{sizeLabel(tool.size_mb)}</span>}
                        </li>
                      ))}
                    </ul>
                  </section>
                  <p className="text-sm font-medium">{t('tools.plan_total', { size: sizeLabel(plan.total_size_mb) })}</p>
                  <section aria-label={t('tools.plan_steps')}>
                    <h3 className="mb-1 text-sm font-semibold">{t('tools.plan_steps')}</h3>
                    <ol className="list-decimal space-y-1 pl-5 text-sm">
                      {plan.steps.map((s) => (
                        <li key={s.index}>
                          {s.title}
                          {s.privilege === 'root' && <span className="text-xs text-muted-foreground"> ({t('tools.plan_pkg')})</span>}
                        </li>
                      ))}
                    </ol>
                  </section>
                  {plan.needs_root && <p className="text-sm text-muted-foreground">{t('tools.plan_root')}</p>}
                </>
              )}
              {plan.already_installed.length > 0 && <p className="text-sm text-muted-foreground">{t('tools.plan_already', { names: plan.already_installed.join(', ') })}</p>}
            </>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
            {t('common.close')}
          </Button>
          {plan && !nothing && (
            <Button type="button" disabled={busy} onClick={onApply}>
              {busy ? t('tools.applying') : t('tools.apply')}
            </Button>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

const STEP_KEY = {
  pending: 'tools.job_step_pending',
  running: 'tools.job_step_running',
  ok: 'tools.job_step_ok',
  failed: 'tools.job_step_failed',
  skipped: 'tools.job_step_skipped',
} as const;

const OUTCOME_KEY = {
  ok: 'tools.job_outcome_ok',
  failed: 'tools.job_outcome_failed',
  skipped: 'tools.job_outcome_skipped',
} as const;

/** A running or finished job: the steps with their state and the live log. Safe to close; the job runs on the box. */
export function ToolJobSheet({ client, box, jobId, onClose, onFinished }: { client: ApiClient; box: string; jobId: string | null; onClose: () => void; onFinished: () => void }) {
  const job = useAsync<ToolJob | null>((s) => (jobId ? client.tools.job(box, jobId, s) : Promise.resolve(null)), [client, box, jobId], 1000);
  const state = job.data?.job.state;
  const finished = state ? isFinished(state) : false;
  useEffect(() => {
    if (finished) onFinished();
    // Only the moment it finishes matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished]);
  const progress = job.data ? jobProgress(job.data.job.steps) : null;
  const notes = finished && state === 'succeeded' ? (job.data?.tools ?? []).filter((x) => x.op === 'install' && x.post_install) : [];
  return (
    <PanelSheet open={jobId !== null} onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="tool-job-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tools.job_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('tools.job_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {!job.data && <Skeleton className="h-20 w-full" />}
          {job.data && (
            <>
              <p role="status" className="text-sm font-medium" data-testid="tool-job-state">
                {state === 'succeeded' ? t('tools.job_succeeded') : state === 'failed' ? t('tools.job_failed', { error: job.data.job.error ?? '' }) : t('tools.job_running')}
              </p>
              {progress && <p className="text-xs text-muted-foreground">{t('tools.job_progress', { done: progress.done, total: progress.total })}</p>}
              <ol className="space-y-1 text-sm" aria-label={t('tools.plan_steps')}>
                {job.data.job.steps.map((s) => (
                  <li key={s.index} className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="min-w-0">{s.title}</span>
                    <Badge variant={s.state === 'failed' ? 'destructive' : s.state === 'ok' ? 'secondary' : 'outline'}>{t(STEP_KEY[s.state])}</Badge>
                  </li>
                ))}
              </ol>
              {finished && state === 'failed' && (job.data.job.outcomes ?? []).length > 0 && (
                <ul className="space-y-1 text-sm" aria-label={t('tools.job_outcomes')} data-testid="tool-job-outcomes">
                  {(job.data.job.outcomes ?? []).map((o) => (
                    <li key={o.id} className="break-words" data-state={o.state}>
                      {t(OUTCOME_KEY[o.state], { id: o.id, error: o.error ?? '' })}
                    </li>
                  ))}
                </ul>
              )}
              {notes.length > 0 && (
                <ul className="space-y-1 text-sm">
                  {notes.map((n) => (
                    <li key={n.id}>{t('tools.post_install', { name: n.name, note: n.post_install ?? '' })}</li>
                  ))}
                </ul>
              )}
              <section aria-label={t('tools.job_log')}>
                <h3 className="mb-1 text-sm font-semibold">{t('tools.job_log')}</h3>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3 text-xs" tabIndex={0}>
                  {job.data.log.length > 0 ? job.data.log.join('\n') : t('tools.job_log_empty')}
                </pre>
              </section>
            </>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t('common.close')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

const profileSchema = z.object({
  name: z.string().refine(validProfileName, { message: 'tools.profile_name_invalid' }),
  description: z.string().max(200),
});

/** Save the box's tools and settings as a named profile. */
export function SaveProfileSheet({ open, busy, error, onSubmit, onClose }: { open: boolean; busy: boolean; error: string | null; onSubmit: (name: string, description: string) => void; onClose: () => void }) {
  const form = useForm<z.infer<typeof profileSchema>>({ resolver: zodResolver(profileSchema), defaultValues: { name: '', description: '' } });
  useEffect(() => {
    if (open) form.reset({ name: '', description: '' });
  }, [open, form]);
  const nameError = form.formState.errors.name;
  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <PanelSheetContent size="compact" data-testid="save-profile-sheet">
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={form.handleSubmit((v) => onSubmit(v.name, v.description))}>
          <PanelSheetHeader>
            <PanelSheetTitle>{t('tools.profile_save_title')}</PanelSheetTitle>
            <PanelSheetDescription>{t('tools.profile_save_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="profile-name">{t('tools.profile_name')}</Label>
              <Input id="profile-name" autoComplete="off" autoCapitalize="none" spellCheck={false} className="max-lg:h-11" aria-describedby="profile-name-hint" aria-invalid={nameError ? true : undefined} {...form.register('name')} />
              <p id="profile-name-hint" className="text-xs text-muted-foreground">
                {t('tools.profile_name_hint')}
              </p>
              {nameError && (
                <p role="alert" className="text-sm text-destructive">
                  {t('tools.profile_name_invalid')}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="profile-desc">{t('tools.profile_desc')}</Label>
              <Input id="profile-desc" autoComplete="off" className="max-lg:h-11" {...form.register('description')} />
            </div>
            {error && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy}>
              {t('common.save')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

const createSchema = z.object({ name: z.string().refine(validBoxName, { message: 'x' }) });

/** Ask for a name, then hand over to the usual create plan. */
export function CreateFromProfileSheet({ profile, onSubmit, onClose }: { profile: string | null; onSubmit: (name: string) => void; onClose: () => void }) {
  const form = useForm<z.infer<typeof createSchema>>({ resolver: zodResolver(createSchema), defaultValues: { name: '' } });
  useEffect(() => {
    if (profile) form.reset({ name: '' });
  }, [profile, form]);
  return (
    <PanelSheet open={profile !== null} onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="create-from-profile-sheet">
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={form.handleSubmit((v) => onSubmit(v.name))}>
          <PanelSheetHeader>
            <PanelSheetTitle>{t('tools.create_title', { name: profile ?? '' })}</PanelSheetTitle>
            <PanelSheetDescription>{t('tools.create_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-2">
            <Label htmlFor="create-name">{t('tools.create_name')}</Label>
            <Input id="create-name" autoComplete="off" autoCapitalize="none" spellCheck={false} className="max-lg:h-11" aria-invalid={form.formState.errors.name ? true : undefined} {...form.register('name')} />
            {form.formState.errors.name && (
              <p role="alert" className="text-sm text-destructive">
                {t('tools.create_name_invalid')}
              </p>
            )}
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit">{t('tools.create_submit')}</Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}
