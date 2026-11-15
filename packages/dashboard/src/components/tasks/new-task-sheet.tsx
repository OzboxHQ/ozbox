import { useEffect, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../../api/client';
import type { NewTask, NewTaskPreview } from '../../api/tasks';
import type { EngineInfo, ModelKindInfo, ModelProvider } from '../../api/types';
import type { ApiClient } from '../../api/client';
import { t } from '../../lib/i18n';
import { draftToTask, providersForRun, type Draft, type Errors } from '../../lib/new-task';
import { fmtCents } from '../../lib/tasks';
import { FieldError } from '../sched-bits';

/**
 * The engines a server can actually run. A real server runs Claude Code only: Codex is listed as a tool a box can have, but no
 * supervisor drives it yet, so a Codex task would queue and then fail to start. The demo accepts its own `fake` engine, and
 * keeps the other two so its screens can be tried.
 */
const REAL_ENGINES = ['claude-code'] as const;
const DEMO_ENGINES = ['fake', 'claude-code', 'codex'] as const;

/** The select cannot hold an empty value, so "the engine's own choice" has a name of its own. */
const ENGINE_CHOICE = '__engine__';

function limitsText(c: NonNullable<NewTask['caps']> | undefined): string {
  if (!c) return t('tasks.new_plan_no_limits');
  const parts: string[] = [];
  if (c.max_runtime_s !== undefined) parts.push(t('tasks.minutes_n', { n: Math.round(c.max_runtime_s / 60) }));
  if (c.max_spend_cents !== undefined) parts.push(fmtCents(c.max_spend_cents));
  if (c.max_tokens !== undefined) parts.push(t('tasks.tokens_n', { n: c.max_tokens }));
  return parts.join(', ');
}

/** A new task: fill it in, review the plan, then queue it. Nothing is queued until the last step. */
export function NewTaskSheet({ client, boxes, simulated, defaultBox, onClose, onQueued }: { client: ApiClient; boxes: string[]; simulated: boolean; defaultBox?: string; onClose: () => void; onQueued: () => void }) {
  const engines: string[] = simulated ? [...DEMO_ENGINES] : [...REAL_ENGINES];
  const [d, setD] = useState<Draft>({ box: defaultBox ?? '', engine: engines[0] ?? 'claude-code', prompt: '', skill: '', repo: '', branch: '', minutes: '', dollars: '', tokens: '', pr: false, alert: false, provider: '', model: '' });
  const [errors, setErrors] = useState<Errors>({});
  const [plan, setPlan] = useState<{ task: NewTask; preview: NewTaskPreview } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));

  // The providers set up in Settings -> Models, and which of them each engine can speak to. Without them the choice of a
  // model for this run is simply not offered.
  const [models, setModels] = useState<{ providers: ModelProvider[]; engines: EngineInfo[]; kinds: ModelKindInfo[] } | null>(null);
  useEffect(() => {
    const ctl = new AbortController();
    Promise.all([client.getSettings(ctl.signal), client.modelsCatalog(ctl.signal)])
      .then(([s, c]) => setModels({ providers: s.settings.models.providers, engines: c.engines, kinds: c.kinds }))
      .catch(() => undefined);
    return () => ctl.abort();
  }, [client]);
  const choices = models ? providersForRun(models.engines, d.engine, models.providers) : [];
  const chosen = choices.find((p) => p.id === d.provider);
  const suggestions = chosen ? (models?.kinds.find((k) => k.id === chosen.kind)?.suggested_models ?? []) : [];

  async function review() {
    const r = draftToTask(d);
    if (!r.ok) {
      setErrors(r.errors);
      return;
    }
    setErrors({});
    setBusy(true);
    setErr(null);
    try {
      setPlan({ task: r.value, preview: await client.tasks.preview(r.value) });
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('tasks.new_failed'));
    } finally {
      setBusy(false);
    }
  }

  async function queue() {
    if (!plan) return;
    setBusy(true);
    setErr(null);
    try {
      await client.tasks.start(plan.task);
      toast.success(t('tasks.new_queued'));
      onQueued();
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('tasks.new_failed'));
    } finally {
      setBusy(false);
    }
  }

  const fieldErr = (k: keyof Draft) => {
    const key = errors[k];
    return key ? <FieldError msg={t(key as 'tasks.new_err_box')} /> : null;
  };

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="new-task-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('tasks.new_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('tasks.new_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{err}</AlertDescription>
            </Alert>
          ) : null}
          {plan ? (
            <section className="space-y-3" aria-label={t('tasks.new_plan_title')} data-testid="new-task-plan">
              <h3 className="text-sm font-semibold">{t('tasks.new_plan_title')}</h3>
              <p className="text-sm font-medium">{t('tasks.new_plan_line', { engine: plan.preview.would_queue.engine, box: plan.preview.would_queue.box, person: plan.preview.would_queue.person })}</p>
              <dl className="grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs text-muted-foreground">{t('tasks.new_plan_limits')}</dt>
                  <dd>{limitsText(plan.task.caps)}</dd>
                </div>
                {plan.task.model ? (
                  <div>
                    <dt className="text-xs text-muted-foreground">{t('tasks.new_plan_model')}</dt>
                    <dd className="break-words" data-testid="new-task-plan-model">
                      {plan.task.model.provider_id} / {plan.task.model.model}
                    </dd>
                  </div>
                ) : null}
                {plan.task.repo ? (
                  <div>
                    <dt className="text-xs text-muted-foreground">{t('tasks.new_repo')}</dt>
                    <dd className="break-words">{plan.task.repo}</dd>
                  </div>
                ) : null}
              </dl>
              <p className="text-sm">{plan.preview.queued_ahead > 0 ? t('tasks.new_plan_ahead', { n: plan.preview.queued_ahead }) : t('tasks.new_plan_none_ahead')}</p>
              <p className="text-xs text-muted-foreground">{t('tasks.new_plan_note')}</p>
            </section>
          ) : (
            <>
              {boxes.length === 0 ? (
                <Alert role="status" data-testid="new-task-no-box">
                  <AlertDescription>{t('tasks.new_no_boxes')}</AlertDescription>
                </Alert>
              ) : null}
              <div className="space-y-1">
                <Label htmlFor="nt-box">{t('tasks.new_box')}</Label>
                <Select value={d.box} onValueChange={(v) => set('box', v)}>
                  <SelectTrigger id="nt-box" aria-invalid={!!errors.box}>
                    <SelectValue placeholder={t('tasks.new_box_none')} />
                  </SelectTrigger>
                  <SelectContent>
                    {boxes.map((b) => (
                      <SelectItem key={b} value={b}>
                        {b}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {fieldErr('box')}
              </div>
              <div className="space-y-1">
                <Label htmlFor="nt-engine">{t('tasks.new_engine')}</Label>
                <Select value={d.engine} onValueChange={(v) => setD((x) => ({ ...x, engine: v, provider: '', model: '' }))}>
                  <SelectTrigger id="nt-engine">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {engines.map((e) => (
                      <SelectItem key={e} value={e}>
                        {e}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {choices.length > 0 ? (
                <fieldset className="space-y-2" data-testid="new-task-model">
                  <legend className="text-sm font-medium">{t('tasks.new_model_title')}</legend>
                  <div className="space-y-1">
                    <Label htmlFor="nt-provider">{t('tasks.new_model_provider')}</Label>
                    <Select value={d.provider === '' ? ENGINE_CHOICE : d.provider} onValueChange={(v) => setD((x) => ({ ...x, provider: v === ENGINE_CHOICE ? '' : v, model: '' }))}>
                      <SelectTrigger id="nt-provider">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={ENGINE_CHOICE}>{t('tasks.new_model_default')}</SelectItem>
                        {choices.map((p) => (
                          <SelectItem key={p.id} value={p.id}>
                            {p.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  {d.provider !== '' ? (
                    <div className="space-y-1">
                      <Label htmlFor="nt-model">{t('tasks.new_model_name')}</Label>
                      <Input id="nt-model" autoComplete="off" list="nt-model-suggestions" className="max-lg:h-11" value={d.model} aria-invalid={!!errors.model} onChange={(e) => set('model', e.target.value)} />
                      <datalist id="nt-model-suggestions">
                        {suggestions.map((m) => (
                          <option key={m} value={m} />
                        ))}
                      </datalist>
                      {fieldErr('model')}
                    </div>
                  ) : null}
                  <p className="text-xs text-muted-foreground">{t('tasks.new_model_hint')}</p>
                </fieldset>
              ) : null}
              <div className="space-y-1">
                <Label htmlFor="nt-prompt">{t('tasks.new_prompt')}</Label>
                <Textarea id="nt-prompt" rows={5} value={d.prompt} aria-invalid={!!errors.prompt} onChange={(e) => set('prompt', e.target.value)} />
                <p className="text-xs text-muted-foreground">{t('tasks.new_prompt_hint')}</p>
                {fieldErr('prompt')}
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label htmlFor="nt-repo">{t('tasks.new_repo')}</Label>
                  <Input id="nt-repo" autoComplete="off" className="max-lg:h-11" value={d.repo} onChange={(e) => set('repo', e.target.value)} />
                  <p className="text-xs text-muted-foreground">{t('tasks.new_repo_hint')}</p>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="nt-branch">{t('tasks.new_branch')}</Label>
                  <Input id="nt-branch" autoComplete="off" className="max-lg:h-11" value={d.branch} onChange={(e) => set('branch', e.target.value)} />
                </div>
              </div>
              <div className="space-y-1">
                <Label htmlFor="nt-skill">{t('tasks.new_skill')}</Label>
                <Input id="nt-skill" autoComplete="off" className="max-lg:h-11" value={d.skill} onChange={(e) => set('skill', e.target.value)} />
              </div>
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1">
                  <Label htmlFor="nt-min">{t('tasks.new_minutes')}</Label>
                  <Input id="nt-min" inputMode="numeric" autoComplete="off" className="max-lg:h-11" value={d.minutes} aria-invalid={!!errors.minutes} onChange={(e) => set('minutes', e.target.value)} />
                  {fieldErr('minutes')}
                </div>
                <div className="space-y-1">
                  <Label htmlFor="nt-usd">{t('tasks.new_spend')}</Label>
                  <Input id="nt-usd" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={d.dollars} aria-invalid={!!errors.dollars} onChange={(e) => set('dollars', e.target.value)} />
                  {fieldErr('dollars')}
                </div>
                <div className="space-y-1">
                  <Label htmlFor="nt-tok">{t('tasks.new_tokens')}</Label>
                  <Input id="nt-tok" inputMode="numeric" autoComplete="off" className="max-lg:h-11" value={d.tokens} aria-invalid={!!errors.tokens} onChange={(e) => set('tokens', e.target.value)} />
                  {fieldErr('tokens')}
                </div>
              </div>
              <p className="text-xs text-muted-foreground">{t('tasks.new_limits_hint')}</p>
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('tasks.new_deliver')}</legend>
                <div className="flex items-center gap-1">
                  <TouchCheckbox id="nt-pr" checked={d.pr} onCheckedChange={(c) => set('pr', c === true)} />
                  <Label htmlFor="nt-pr">{t('tasks.new_deliver_pr')}</Label>
                </div>
                <div className="flex items-center gap-1">
                  <TouchCheckbox id="nt-alert" checked={d.alert} onCheckedChange={(c) => set('alert', c === true)} />
                  <Label htmlFor="nt-alert">{t('tasks.new_deliver_alert')}</Label>
                </div>
              </fieldset>
            </>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          {plan ? (
            <>
              <Button variant="outline" className="max-lg:h-11" disabled={busy} onClick={() => setPlan(null)}>
                {t('tasks.new_back')}
              </Button>
              <Button className="max-lg:h-11" disabled={busy} onClick={queue}>
                {busy ? t('tasks.new_starting') : t('tasks.new_start')}
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" className="max-lg:h-11" onClick={onClose}>
                {t('common.cancel')}
              </Button>
              <Button className="max-lg:h-11" disabled={busy} onClick={review}>
                {t('tasks.new_review')}
              </Button>
            </>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
