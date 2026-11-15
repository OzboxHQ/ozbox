import { useEffect, useMemo, useReducer, useRef } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../../api/error';
import type { BoxRecord } from '../../api/types';
import { useApp } from '../../App';
import { CREATE_STEPS, canContinue, createReducer, diskProblem, initialCreate, nameProblem, needsNetwork, parseLabels, refusalFix, stageOf, toOperation, type CreateState, type CreateStep, type Stage, STAGE_ORDER } from '../../lib/create-box-flow';
import { fmtCost } from '../../lib/format';
import { openFlow } from '../../lib/flows';
import { t, type MessageKey } from '../../lib/i18n';
import { hrefs, navigate } from '../../lib/router';
import { bundleSelectable, toggle } from '../../lib/tools';
import { useAsync } from '../../lib/use-async';
import { useSettings } from '../../lib/use-settings';
import { ChangeList } from '../setup/plan-view';

const STEP_TITLE: Record<CreateStep, MessageKey> = {
  name: 'create.step_name',
  size: 'create.step_size',
  tools: 'create.step_tools',
  options: 'create.step_options',
  review: 'create.step_review',
  progress: 'create.step_progress',
};

const STAGE_TEXT: Record<Stage, MessageKey> = {
  creating: 'create.stage_creating',
  booting: 'create.stage_booting',
  self_test: 'create.stage_self_test',
  ready: 'create.stage_ready',
  failed: 'create.stage_failed',
};

function money(monthly: number | null | undefined, currency: string | null | undefined): string | null {
  return monthly === null || monthly === undefined || !currency ? null : fmtCost(monthly, currency);
}

/** "Create a box": name, size, tools, options, then the plan, then a progress view that follows the box to ready. */
export function CreateBoxSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { client, info } = useApp();
  const { settings } = useSettings();
  const boxes = useAsync<BoxRecord[]>((s) => client.listBoxes(s), [client, open]);
  const catalog = useAsync((s) => client.tools.catalog(s), [client]);
  const profiles = useAsync((s) => client.tools.profiles(s), [client, open]);
  const existing = useMemo(() => (boxes.data ?? []).map((b) => b.spec.name), [boxes.data]);
  const [s, dispatch] = useReducer(createReducer, undefined as unknown as CreateState, () => initialCreate({ size: 'M', diskGb: 200 }));
  const touchedTools = useRef(false);
  const started = useRef(false);

  // Start fresh each time the sheet opens, with the person's box defaults.
  useEffect(() => {
    if (!open) return;
    started.current = false;
    touchedTools.current = false;
    dispatch({ type: 'set', patch: { name: '', labels: '', profile: null, tools: [] } });
  }, [open]);
  useEffect(() => {
    if (!open || !settings || started.current) return;
    started.current = true;
    dispatch({ type: 'set', patch: { size: settings.defaults.size, diskGb: settings.defaults.work_disk_gb, alwaysOn: settings.defaults.always_on, autoPauseMinutes: settings.defaults.auto_pause_minutes } });
  }, [open, settings]);
  // The default tools are ticked until the person touches the list.
  useEffect(() => {
    if (!catalog.data || touchedTools.current || s.form.profile) return;
    dispatch({ type: 'set', patch: { tools: catalog.data.tools.filter((x) => x.default && x.verified).map((x) => x.id) } });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog.data, open]);

  const form = s.form;
  const nameMsg = nameProblem(form.name, existing);
  const sizeInfo = info?.sizes.find((x) => x.id === (typeof form.size === 'string' ? form.size : form.size.Gpu === 'Small' ? 'GPU-S' : 'GPU-L'));
  const quote = sizeInfo?.quote;
  const estimate = money(quote?.monthly, quote?.currency);

  async function goReview() {
    dispatch({ type: 'next' });
    dispatch({ type: 'planning' });
    try {
      const plan = await client.plan(toOperation(form));
      dispatch({ type: 'planned', plan });
    } catch (e) {
      if (e instanceof ApiError) dispatch({ type: 'refused', code: e.code, message: e.message, fix: e.fix });
      else dispatch({ type: 'failed', message: t('common.request_failed') });
    }
  }

  async function create() {
    if (s.review.phase !== 'review') return;
    const plan = s.review.plan;
    dispatch({ type: 'apply' });
    try {
      const response = await client.apply({ plan_id: plan.plan_id, plan: plan.plan });
      // The box is made either way; if its chosen tools could not be saved for later, say so instead of letting it look as if they were.
      if (form.tools.length > 0) await client.tools.setPending(form.name, form.tools).catch((e: unknown) => toast.error(t('tools.pending_error', { reason: e instanceof ApiError ? e.message : '' })));
      dispatch({ type: 'applied', response });
      window.dispatchEvent(new Event('ozbox:changed'));
    } catch (e) {
      dispatch({ type: 'failed', message: e instanceof ApiError ? e.message : t('create.failed') });
    }
  }

  const stepIndex = CREATE_STEPS.indexOf(s.step);
  const okToContinue = canContinue(s, existing);
  const applying = s.review.phase === 'applying';

  return (
    <PanelSheet open={open} onOpenChange={(o) => !o && !applying && onClose()}>
      <PanelSheetContent size="wide" data-testid="create-box-sheet" onInteractOutside={(e) => e.preventDefault()} onEscapeKeyDown={(e) => applying && e.preventDefault()}>
        <PanelSheetHeader>
          <PanelSheetTitle>{t('create.title')}</PanelSheetTitle>
          <PanelSheetDescription>{s.step === 'name' ? t('create.desc') : t('flow.step_of', { n: stepIndex + 1, of: CREATE_STEPS.length })}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          <h2 className="text-base font-semibold" data-testid="create-step-title">
            {t(STEP_TITLE[s.step])}
          </h2>

          {s.step === 'name' && (
            <div className="space-y-1">
              <Label htmlFor="create-name">{t('create.name')}</Label>
              <Input id="create-name" className="h-11 lg:h-10" autoComplete="off" autoCapitalize="none" spellCheck={false} value={form.name} onChange={(e) => dispatch({ type: 'set', patch: { name: e.target.value } })} aria-invalid={form.name !== '' && nameMsg !== null} aria-describedby="create-name-msg" />
              <p id="create-name-msg" className={`text-xs ${form.name !== '' && nameMsg ? 'text-destructive' : 'text-muted-foreground'}`} data-testid="name-message">
                {form.name === '' ? t('create.name_hint') : nameMsg ? t(nameMsg) : t('create.name_ok')}
              </p>
            </div>
          )}

          {s.step === 'size' && (
            <>
              {!info ? (
                <Skeleton className="h-32 w-full" />
              ) : (
                <div role="radiogroup" aria-label={t('create.size_group')} className="space-y-2">
                  {info.sizes.map((z) => {
                    const m = money(z.quote?.monthly, z.quote?.currency);
                    const selected = JSON.stringify(z.size) === JSON.stringify(form.size);
                    return (
                      <button key={z.id} type="button" role="radio" aria-checked={selected} data-testid={`size-${z.id}`} onClick={() => dispatch({ type: 'set', patch: { size: z.size } })} className={`flex min-h-11 w-full flex-col gap-0.5 rounded-md border p-3 text-left text-sm ${selected ? 'border-primary bg-accent' : 'hover:bg-accent/60'}`}>
                        <span className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-semibold">{z.id}</span>
                          <span className="text-muted-foreground">{t('create.size_row', { vcpus: z.vcpus, memory: z.memory_gb })}</span>
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {z.quote?.machine_type ? t('create.size_machine', { machine: z.quote.machine_type }) : t('create.size_machine_none')}
                          {' · '}
                          {m ? t('create.size_price', { amount: m }) : t('create.size_price_none')}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
              <div className="space-y-1">
                <Label htmlFor="create-disk">{t('create.disk')}</Label>
                <Input id="create-disk" type="number" inputMode="numeric" className="h-11 lg:h-10" value={Number.isNaN(form.diskGb) ? '' : form.diskGb} onChange={(e) => dispatch({ type: 'set', patch: { diskGb: e.target.value === '' ? Number.NaN : Number(e.target.value) } })} aria-invalid={diskProblem(form.diskGb)} aria-describedby="create-disk-msg" />
                <p id="create-disk-msg" className={`text-xs ${diskProblem(form.diskGb) ? 'text-destructive' : 'text-muted-foreground'}`}>
                  {diskProblem(form.diskGb) ? t('create.disk_invalid') : t('create.disk_hint')}
                </p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="create-region">{t('create.region')}</Label>
                <Input id="create-region" className="h-11 lg:h-10" autoComplete="off" value={form.region} onChange={(e) => dispatch({ type: 'set', patch: { region: e.target.value.trim() } })} aria-describedby="create-region-hint" />
                <p id="create-region-hint" className="text-xs text-muted-foreground">
                  {t('create.region_hint')}
                </p>
              </div>
            </>
          )}

          {s.step === 'tools' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <Label htmlFor="create-profile">{t('create.profile')}</Label>
                <select
                  id="create-profile"
                  className="flex h-11 w-full rounded-md border border-input bg-background px-3 text-sm lg:h-10"
                  value={form.profile ?? ''}
                  onChange={(e) => {
                    const p = profiles.data?.find((x) => x.name === e.target.value);
                    touchedTools.current = true;
                    dispatch(
                      p
                        ? { type: 'profile', name: p.name, tools: p.tools, ...(p.box?.size ? { size: sizeOf(p.box.size) } : {}), ...(p.box?.disk_gb ? { diskGb: p.box.disk_gb } : {}), ...(p.box?.always_on !== undefined ? { alwaysOn: p.box.always_on } : {}) }
                        : { type: 'profile', name: null, tools: [] },
                    );
                  }}
                >
                  <option value="">{t('create.profile_none')}</option>
                  {(profiles.data ?? [])
                    .filter((p) => !p.error)
                    .map((p) => (
                      <option key={p.name} value={p.name}>
                        {p.name}
                      </option>
                    ))}
                </select>
                <p className="text-xs text-muted-foreground">{t('create.profile_hint')}</p>
              </div>
              {!catalog.data ? (
                <Skeleton className="h-40 w-full" />
              ) : (
                <>
                  <p className="text-sm text-muted-foreground">{t('create.tools_hint')}</p>
                  <section aria-label={t('create.tools_bundles')} className="flex flex-wrap gap-2">
                    {catalog.data.bundles.map((b) => {
                      const ids = bundleSelectable(catalog.data!, [], b.id).filter((id) => catalog.data!.tools.find((x) => x.id === id)?.verified);
                      const on = ids.length > 0 && ids.every((id) => form.tools.includes(id));
                      return (
                        <button
                          key={b.id}
                          type="button"
                          aria-pressed={on}
                          data-testid={`create-bundle-${b.id}`}
                          onClick={() => {
                            touchedTools.current = true;
                            dispatch({ type: 'set', patch: { tools: on ? form.tools.filter((id) => !ids.includes(id)) : [...new Set([...form.tools, ...ids])] } });
                          }}
                          className={`min-h-11 rounded-md border px-3 text-sm ${on ? 'border-primary bg-accent' : 'hover:bg-accent/60'}`}
                        >
                          {b.name}
                        </button>
                      );
                    })}
                  </section>
                  {catalog.data.groups.map((g) => {
                    const rows = catalog.data!.tools.filter((x) => x.group === g.id);
                    if (rows.length === 0) return null;
                    return (
                      <section key={g.id} aria-label={g.name} className="space-y-1">
                        <h3 className="text-sm font-semibold">{g.name}</h3>
                        <ul className="divide-y rounded-md border">
                          {rows.map((x) => {
                            const blocked = !x.verified || x.verification === 'client_managed';
                            return (
                              <li key={x.id} className="flex items-start gap-2 p-2 text-sm" data-testid={`create-tool-${x.id}`}>
                                <TouchCheckbox id={`create-tool-${x.id}-box`} disabled={blocked} checked={form.tools.includes(x.id)} onCheckedChange={() => {
                                  touchedTools.current = true;
                                  dispatch({ type: 'set', patch: { tools: [...toggle(new Set(form.tools), x.id)] } });
                                }} />
                                <div className="min-w-0 flex-1">
                                  <Label htmlFor={`create-tool-${x.id}-box`} className="flex flex-wrap items-center gap-2 font-medium">
                                    {x.name}
                                    {x.default && <Badge variant="secondary">{t('create.tool_default')}</Badge>}
                                  </Label>
                                  <p className="text-xs text-muted-foreground">{!x.verified ? t('create.tool_unverified', { reason: x.unverified_reason ?? '—' }) : x.verification === 'client_managed' ? t('create.tool_client') : x.description}</p>
                                </div>
                              </li>
                            );
                          })}
                        </ul>
                      </section>
                    );
                  })}
                  <p className="text-sm font-medium" role="status">
                    {t('create.tools_selected', { n: form.tools.length })}
                  </p>
                </>
              )}
            </div>
          )}

          {s.step === 'options' && (
            <div className="space-y-4">
              <div className="flex min-h-11 items-center gap-3">
                <TouchCheckbox id="create-always" checked={form.alwaysOn} onCheckedChange={(c) => dispatch({ type: 'set', patch: { alwaysOn: c === true } })} />
                <Label htmlFor="create-always">{t('create.always_on')}</Label>
              </div>
              {!form.alwaysOn && settings && <p className="text-xs text-muted-foreground">{t('create.auto_pause_note', { minutes: settings.defaults.auto_pause_minutes })}</p>}
              <div className="space-y-1">
                <Label htmlFor="create-labels">{t('create.labels')}</Label>
                <textarea id="create-labels" rows={3} className="flex min-h-24 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm" value={form.labels} onChange={(e) => dispatch({ type: 'set', patch: { labels: e.target.value } })} aria-describedby="create-labels-hint" aria-invalid={parseLabels(form.labels).bad.length > 0} />
                <p id="create-labels-hint" className={`text-xs ${parseLabels(form.labels).bad.length > 0 ? 'text-destructive' : 'text-muted-foreground'}`}>
                  {parseLabels(form.labels).bad.length > 0 ? t('create.labels_invalid') : t('create.labels_hint')}
                </p>
              </div>
            </div>
          )}

          {s.step === 'review' && <ReviewView s={s} estimate={estimate} onSetup={() => { onClose(); openFlow('setup'); }} />}
          {s.step === 'progress' && <ProgressView name={form.name} s={s} dispatch={dispatch} />}

          {s.problem && s.step !== 'progress' && (
            <p role="alert" className="text-sm text-destructive">
              {s.problem}
            </p>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          {s.step === 'progress' ? (
            <>
              <Button type="button" variant="outline" onClick={onClose}>
                {t('create.close')}
              </Button>
              <Button type="button" disabled={s.stage !== 'ready'} onClick={() => { onClose(); navigate(hrefs.box(form.name)); }} data-testid="open-box">
                {t('create.open_box')}
              </Button>
            </>
          ) : (
            <>
              <Button type="button" variant="outline" disabled={s.step === 'name' || applying} onClick={() => dispatch({ type: 'back' })}>
                {t('flow.back')}
              </Button>
              {s.step === 'options' ? (
                <Button type="button" disabled={!okToContinue} onClick={goReview} data-testid="create-review">
                  {t('setup.review_plan')}
                </Button>
              ) : s.step === 'review' ? (
                <Button type="button" disabled={!okToContinue || applying} onClick={create} data-testid="create-apply">
                  {applying ? t('create.creating') : t('create.create')}
                </Button>
              ) : (
                <Button type="button" disabled={!okToContinue} onClick={() => dispatch({ type: 'next' })} data-testid="create-continue">
                  {t('flow.continue')}
                </Button>
              )}
            </>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function sizeOf(s: string): import('../../api/types').Size {
  if (s === 'GPU-S') return { Gpu: 'Small' };
  if (s === 'GPU-L') return { Gpu: 'Large' };
  if (s === 'XS' || s === 'S' || s === 'M' || s === 'L' || s === 'XL' || s === 'XXL') return s;
  return 'M';
}

/** The plan is the review: every change with its risk and the estimate. A refusal shows its reason and the fix. */
function ReviewView({ s, estimate, onSetup }: { s: CreateState; estimate: string | null; onSetup: () => void }) {
  const r = s.review;
  if (r.phase === 'planning' || r.phase === 'none') return <Skeleton className="h-24 w-full" aria-label={t('create.review_planning')} />;
  if (r.phase === 'refused') {
    const fixKey = needsNetwork(r.message) ? 'create.fix_subnet' : refusalFix(r.code);
    return (
      <div role="alert" className="space-y-2 rounded-md border border-destructive/50 p-3 text-sm" data-testid="refusal" data-code={r.code}>
        <p className="font-semibold">{t('create.refused')}</p>
        <p>{t('create.refused_reason', { message: r.message })}</p>
        <p className="font-medium">{r.fix ?? t(fixKey)}</p>
        {(fixKey === 'create.fix_subnet' || fixKey === 'create.fix_guardrails') && (
          <Button type="button" variant="outline" className="max-lg:h-11" onClick={onSetup}>
            {t('create.open_setup')}
          </Button>
        )}
        {fixKey === 'create.fix_budget' && (
          <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => navigate(hrefs.settings('budgets'))}>
            {t('create.open_budgets')}
          </Button>
        )}
      </div>
    );
  }
  const plan = r.plan;
  return (
    <div className="space-y-3">
      {plan.noop ? (
        <p className="text-sm">{t('create.review_nothing')}</p>
      ) : (
        <>
          <p className="text-sm">{t('create.review_changes', { provider: plan.plan.provider })}</p>
          <ChangeList changes={plan.plan.changes} label={t('create.step_review')} />
        </>
      )}
      {plan.plan.notes.map((n) => (
        <p key={n} className="text-xs text-muted-foreground">
          {n}
        </p>
      ))}
      <p className="text-sm font-medium" data-testid="estimate">
        {estimate ? t('create.review_estimate', { amount: estimate }) : t('create.review_estimate_none')}
      </p>
      {s.form.tools.length > 0 && <p className="text-xs text-muted-foreground">{t('create.review_tools', { tools: s.form.tools.join(', ') })}</p>}
    </div>
  );
}

/** Follows the new box: creating, booting, self-test, ready. Its chosen tools are installed once its daemon answers. */
function ProgressView({ name, s, dispatch }: { name: string; s: CreateState; dispatch: (a: import('../../lib/create-box-flow').CreateAction) => void }) {
  const { client } = useApp();
  const box = useAsync((sig) => client.getBox(name, sig), [client, name], 2000);
  const tools = useAsync((sig) => client.tools.box(name, sig), [client, name], 2000);
  const selftest = useAsync((sig) => client.selftest(name, sig), [client, name], 3000);
  const reachable = tools.data !== null;
  const test = selftest.data?.result ?? null;
  const stage = stageOf(box.data, reachable, test ? test.ok : null);

  useEffect(() => {
    if (stage !== s.stage) dispatch({ type: 'stage', stage });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage]);

  // Tools chosen at create time are installed by the server as soon as the box's daemon answers, whether or not this
  // sheet is open. All this view does is say where that stands.
  const waiting = (tools.data?.pending.length ?? 0) > 0;

  const idx = STAGE_ORDER.indexOf(stage === 'failed' ? 'self_test' : stage);
  return (
    <div className="space-y-4" data-testid="create-progress">
      <ol className="space-y-2" aria-label={t('create.step_progress')}>
        {STAGE_ORDER.map((st, i) => (
          <li key={st} className={`flex min-h-11 items-center gap-3 rounded-md border p-2 text-sm ${i === idx ? 'border-primary' : ''}`} aria-current={i === idx ? 'step' : undefined} data-testid={`stage-${st}`}>
            <Badge variant={i < idx || stage === 'ready' ? 'outline' : i === idx ? 'secondary' : 'outline'}>{i + 1}</Badge>
            <span className={i <= idx ? 'font-medium' : 'text-muted-foreground'}>{t(STAGE_TEXT[st])}</span>
          </li>
        ))}
      </ol>
      <p role="status" className="text-sm font-medium" data-testid="stage-now">
        {t('create.progress_now', { stage: t(STAGE_TEXT[stage]) })}
      </p>
      <p className="text-xs text-muted-foreground">{t('create.progress_hint')}</p>
      <section aria-label={t('create.self_test_title')} className="space-y-1">
        <h3 className="text-sm font-semibold">{t('create.self_test_title')}</h3>
        {test ? (
          <ul className="space-y-1 text-sm">
            {test.checks.map((c) => (
              <li key={c.name} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2">
                <span>{c.name}</span>
                <Badge variant={c.outcome === 'pass' ? 'outline' : c.outcome === 'fail' ? 'destructive' : 'secondary'}>{c.outcome === 'pass' ? t('setup.sec_pass') : c.outcome === 'fail' ? t('setup.sec_fail') : t('setup.perm_unknown')}</Badge>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">{t('create.self_test_none')}</p>
        )}
      </section>
      {s.form.tools.length > 0 && (
        <p className="text-sm text-muted-foreground" data-testid="tools-state">
          {reachable && !waiting ? t('create.tools_started') : reachable ? t('create.tools_installing') : t('create.tools_waiting')}
        </p>
      )}
    </div>
  );
}
