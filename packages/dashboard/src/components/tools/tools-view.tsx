import { useCallback, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { cn } from '@/lib/utils';
import { ApiError } from '../../api/client';
import type { BoxProfile, CatalogTool, ToolPlan } from '../../api/tools';
import type { BoxRecord, Size } from '../../api/types';
import { useApp } from '../../App';
import { t, type MessageKey } from '../../lib/i18n';
import { hrefs, navigate } from '../../lib/router';
import { bundleSelectable, bundleTicked, groupRows, selectable, sizeLabel, toggle, type ToolRow } from '../../lib/tools';
import { useAsync } from '../../lib/use-async';
import { usePlanFlow } from '../../lib/use-plan-flow';
import { PlanSheet } from '../box-action-sheets';
import { EmptyState } from '../page';
import { SourceNote } from '../source-badge';
import { ToolRequestList } from './tool-requests';
import { CreateFromProfileSheet, SaveProfileSheet, ToolJobSheet, ToolPlanSheet, type PlanPhase } from './tools-sheets';

const UPDATES: Record<CatalogTool['updates']['how'], MessageKey> = {
  self_update: 'tools.updates_self_update',
  apt: 'tools.updates_apt',
  manual: 'tools.updates_manual',
  client: 'tools.updates_client',
};

function sizeFromProfile(s: string | undefined): Size {
  if (s === 'GPU-S') return { Gpu: 'Small' };
  if (s === 'GPU-L') return { Gpu: 'Large' };
  if (s === 'XS' || s === 'S' || s === 'M' || s === 'L' || s === 'XL' || s === 'XXL') return s;
  return 'M';
}

function describeError(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

function ToolCard({ row, checked, onToggle, onRemove }: { row: ToolRow; checked: boolean; onToggle: () => void; onRemove: () => void }) {
  const { tool, state, status } = row;
  return (
    <Card className="flex h-full flex-col gap-2 p-4" data-testid={`tool-${tool.id}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="break-words text-sm font-semibold">{tool.name}</h3>
          <p className="mt-0.5 break-words text-sm text-muted-foreground">{tool.description}</p>
        </div>
        {selectable(row) && <TouchCheckbox checked={checked} onCheckedChange={onToggle} aria-label={t('tools.select_aria', { name: tool.name })} />}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {tool.default && <Badge variant="secondary">{t('tools.badge_default')}</Badge>}
        {status !== 'unavailable' && status !== 'client' && <Badge variant="outline">{t(UPDATES[tool.updates.how])}</Badge>}
        {status === 'available' && <Badge variant="outline">{t('tools.size', { size: sizeLabel(tool.size_mb) })}</Badge>}
      </div>
      <p className="text-sm" data-testid={`tool-status-${tool.id}`}>
        {status === 'installed' && (state?.version ? t('tools.installed_version', { version: state.version }) : t('tools.installed'))}
        {status === 'available' && t('tools.not_installed')}
        {status === 'unavailable' && t('tools.unavailable')}
        {status === 'client' && t('tools.client_managed')}
      </p>
      {status === 'unavailable' && tool.unverified_reason && <p className="text-xs text-muted-foreground">{t('tools.unavailable_why', { reason: tool.unverified_reason })}</p>}
      {status === 'installed' && (
        <div className="mt-auto pt-1">
          <Button variant="outline" className="h-11 lg:h-9" aria-label={t('tools.remove_aria', { name: tool.name })} onClick={onRemove}>
            {t('tools.remove')}
          </Button>
        </div>
      )}
    </Card>
  );
}

/** A box's tools: the catalog in groups with search and bundles, a plan before every change, jobs with a live log, agent requests and profiles. */
export function ToolsView({ box }: { box: BoxRecord }) {
  const { client } = useApp();
  const name = box.spec.name;
  const running = box.state === 'running';
  const catalog = useAsync((s) => client.tools.catalog(s), [client]);
  const [jobId, setJobId] = useState<string | null>(null);
  const state = useAsync((s) => (running ? client.tools.box(name, s) : Promise.resolve(null)), [client, name, running], jobId ? 2000 : 6000);
  const profiles = useAsync((s) => client.tools.profiles(s), [client]);

  const [query, setQuery] = useState('');
  const [bundle, setBundle] = useState<string | null>(null);
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [plan, setPlan] = useState<PlanPhase>({ phase: 'idle' });
  const [removing, setRemoving] = useState<{ tool: CatalogTool; plan: ToolPlan } | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [createFrom, setCreateFrom] = useState<BoxProfile | null>(null);
  const created = useRef<{ name: string; tools: string[] } | null>(null);

  const reloadAll = useCallback(() => {
    state.reload();
    profiles.reload();
  }, [state, profiles]);

  // Creating a box from a profile goes through the usual create plan; its tools wait for the new box.
  const flow = usePlanFlow(client, () => {
    const c = created.current;
    if (!c) return;
    created.current = null;
    // The new box is made either way. If its waiting tools could not be saved, say so: it is not left looking as if they were.
    void client.tools
      .setPending(c.name, c.tools)
      .catch((e: unknown) => toast.error(t('tools.pending_error', { reason: describeError(e, '') })))
      .finally(() => navigate(hrefs.tools(c.name)));
  });

  const states = useMemo(() => state.data?.tools ?? [], [state.data]);
  const groups = useMemo(() => (catalog.data ? groupRows(catalog.data, states, query, bundle) : []), [catalog.data, states, query, bundle]);
  const activeJob = state.data?.active_job ?? null;
  const pending = state.data?.pending ?? [];

  async function makePlan(install: string[], remove: string[]) {
    setPlan({ phase: 'planning' });
    try {
      const p = await client.tools.plan(name, { install, remove });
      setPlan({ phase: 'review', plan: p, install, remove });
    } catch (e) {
      setPlan({ phase: 'error', message: describeError(e, t('tools.plan_failed')) });
    }
  }

  async function apply(p: Extract<PlanPhase, { phase: 'review' }>) {
    setPlan({ ...p, phase: 'starting' });
    try {
      const r = await client.tools.apply(name, { install: p.install, remove: p.remove }, p.plan.hash);
      setPlan({ phase: 'idle' });
      setSelection(new Set());
      if (r.job_id) {
        setJobId(r.job_id);
        if (pending.length > 0) void client.tools.clearPending(name).catch((e: unknown) => toast.error(t('tools.pending_error', { reason: describeError(e, '') })));
      }
      state.reload();
    } catch (e) {
      setPlan({ phase: 'error', message: describeError(e, t('tools.apply_failed')) });
    }
  }

  async function dismissPending() {
    try {
      await client.tools.clearPending(name);
      state.reload();
    } catch (e) {
      toast.error(t('tools.pending_error', { reason: describeError(e, '') }));
    }
  }

  async function askRemove(tool: CatalogTool) {
    try {
      const p = await client.tools.plan(name, { remove: [tool.id] });
      setRemoving({ tool, plan: p });
    } catch (e) {
      toast.error(describeError(e, t('tools.plan_failed')));
    }
  }

  async function confirmRemove() {
    if (!removing) return;
    const r = await client.tools.apply(name, { remove: [removing.tool.id] }, removing.plan.hash);
    setRemoving(null);
    if (r.job_id) setJobId(r.job_id);
    state.reload();
  }

  async function saveProfile(profileName: string, description: string) {
    setSaveBusy(true);
    setSaveError(null);
    try {
      await client.tools.saveProfile({ name: profileName, from_box: name, ...(description ? { description } : {}) });
      toast.success(t('tools.profile_saved', { name: profileName }));
      setSaveOpen(false);
      profiles.reload();
    } catch (e) {
      setSaveError(describeError(e, t('tools.profile_save_failed')));
    } finally {
      setSaveBusy(false);
    }
  }

  function startCreate(profile: BoxProfile, newName: string) {
    const b = profile.box ?? {};
    created.current = { name: newName, tools: profile.tools };
    setCreateFrom(null);
    flow.begin({
      op: 'create',
      spec: { name: newName, size: sizeFromProfile(b.size), work_disk_gb: b.disk_gb ?? 200, image: null, region: null, from_snapshot: null, labels: { ...(b.labels ?? {}), ...(b.always_on ? { 'ozbox-always-on': 'true' } : {}) } },
    });
  }

  if (!running) return <EmptyState title={t('tools.title')}>{t('tools.not_running')}</EmptyState>;
  // A server that has no tools to show (a 501) says so as a statement; any other failure is an alert. Neither is a blank page.
  const firstError = (catalog.error && !catalog.data ? catalog.error : null) ?? (state.error && !state.data ? state.error : null);
  if (firstError) {
    if (firstError instanceof ApiError && firstError.status === 501) {
      return (
        <p role="status" className="rounded-lg border p-4 text-sm text-muted-foreground" data-testid="tools-unavailable">
          {t('tools.unavailable_here', { box: name, reason: firstError.message })}
        </p>
      );
    }
    return (
      <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm" data-testid="tools-error">
        {firstError.message}
      </div>
    );
  }
  if (!catalog.data || !state.data) return <Skeleton className="h-40 w-full" />;
  const cat = catalog.data;
  const nameOf = (id: string) => cat.tools.find((x) => x.id === id)?.name ?? id;

  return (
    <div className="space-y-6" data-testid="tools-view">
      <SourceNote source={state.data.source} what="tools" />
      {state.error || catalog.error ? (
        <p role="alert" className="text-sm text-destructive" data-testid="tools-refresh-error">
          {t('tools.refresh_error', { reason: (state.error ?? catalog.error)?.message ?? '' })}
        </p>
      ) : null}
      <p className="text-sm text-muted-foreground">{t('tools.intro')}</p>

      {activeJob && (
        <Card className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between" role="status">
          <p className="text-sm">{t('tools.job_banner')}</p>
          <Button variant="outline" className="h-11 lg:h-9" onClick={() => setJobId(activeJob)}>
            {t('tools.job_view')}
          </Button>
        </Card>
      )}

      {pending.length > 0 && (
        <Card className="flex flex-col gap-2 p-4 sm:flex-row sm:items-center sm:justify-between" data-testid="pending-banner">
          <p className="text-sm">{t('tools.pending_banner', { names: pending.map(nameOf).join(', ') })}</p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button className="h-11 lg:h-9" onClick={() => void makePlan(pending, [])}>
              {t('tools.pending_review')}
            </Button>
            <Button variant="outline" className="h-11 lg:h-9" onClick={() => void dismissPending()}>
              {t('tools.pending_dismiss')}
            </Button>
          </div>
        </Card>
      )}

      <ToolRequestList client={client} box={name} onChanged={state.reload} />

      <div className="space-y-3">
        <div className="max-w-md space-y-1">
          <Label htmlFor="tool-search">{t('tools.search_label')}</Label>
          <Input id="tool-search" type="search" className="max-lg:h-11" placeholder={t('tools.search_placeholder')} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
        </div>
        <section aria-label={t('tools.bundles')} className="space-y-1">
          <p className="text-xs text-muted-foreground">{t('tools.bundles_hint')}</p>
          <div className="flex flex-wrap gap-2">
            {cat.bundles.map((b) => {
              const left = bundleSelectable(cat, states, b.id);
              const ticked = left.length > 0 && bundleTicked(cat, states, selection, b.id);
              return (
                <Button
                  key={b.id}
                  variant={ticked ? 'default' : 'outline'}
                  className="h-11 lg:h-9"
                  aria-pressed={ticked}
                  aria-label={t('tools.bundle_aria', { name: b.name })}
                  title={b.description}
                  disabled={left.length === 0}
                  data-testid={`bundle-${b.id}`}
                  onClick={() => {
                    setSelection((cur) => {
                      const next = new Set(cur);
                      if (ticked) left.forEach((id) => next.delete(id));
                      else left.forEach((id) => next.add(id));
                      return next;
                    });
                    setBundle(null);
                  }}
                >
                  {b.name}
                </Button>
              );
            })}
          </div>
        </section>
      </div>

      {groups.length === 0 && <EmptyState title={t('tools.title')}>{t('tools.none_found')}</EmptyState>}
      {groups.map((g) => (
        <section key={g.id} aria-labelledby={`group-${g.id}`} className="space-y-2" data-testid={`group-${g.id}`}>
          <h2 id={`group-${g.id}`} className="text-sm font-semibold">
            {g.name}
          </h2>
          <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {g.rows.map((row) => (
              <li key={row.tool.id}>
                <ToolCard row={row} checked={selection.has(row.tool.id)} onToggle={() => setSelection((s) => toggle(s, row.tool.id))} onRemove={() => void askRemove(row.tool)} />
              </li>
            ))}
          </ul>
        </section>
      ))}

      <section aria-labelledby="profiles-h" className="space-y-3" data-testid="profiles">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <h2 id="profiles-h" className="text-sm font-semibold">
            {t('tools.profiles_title')}
          </h2>
          <Button variant="outline" className="h-11 lg:h-9" onClick={() => setSaveOpen(true)}>
            {t('tools.profile_save')}
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">{t('tools.profiles_intro')}</p>
        {profiles.error && !profiles.data && (
          <p role="alert" className="text-sm text-destructive" data-testid="profiles-error">
            {t('tools.profiles_error', { reason: profiles.error.message })}
          </p>
        )}
        {profiles.data && profiles.data.length === 0 && <p className="text-sm text-muted-foreground">{t('tools.profiles_none')}</p>}
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {(profiles.data ?? []).map((p) => (
            <li key={p.name}>
              <Card className="flex h-full flex-col gap-2 p-4" data-testid={`profile-${p.name}`}>
                <h3 className="break-words text-sm font-semibold">{p.name}</h3>
                {p.description && <p className="break-words text-sm text-muted-foreground">{p.description}</p>}
                {p.error ? (
                  <p className="text-sm text-destructive">{t('tools.profile_invalid', { error: p.error })}</p>
                ) : (
                  <>
                    <p className="text-xs text-muted-foreground">{t('tools.profile_tools_count', { n: p.tools.length })}</p>
                    <div className={cn('mt-auto flex flex-col gap-2 pt-1 sm:flex-row')}>
                      <Button className="h-11 lg:h-9" aria-label={t('tools.profile_apply_aria', { name: p.name })} onClick={() => void makePlan(p.tools, [])}>
                        {t('tools.profile_apply')}
                      </Button>
                      <Button variant="outline" className="h-11 lg:h-9" aria-label={t('tools.profile_create_aria', { name: p.name })} onClick={() => setCreateFrom(p)}>
                        {t('tools.profile_create')}
                      </Button>
                    </div>
                  </>
                )}
              </Card>
            </li>
          ))}
        </ul>
      </section>

      {selection.size > 0 && (
        <div className="sticky bottom-0 z-10 -mx-4 flex flex-col gap-2 border-t bg-background p-3 sm:mx-0 sm:flex-row sm:items-center sm:justify-between sm:rounded-lg sm:border" data-testid="selection-bar" role="region" aria-label={t('tools.plan_button')}>
          <p className="text-sm font-medium">{t('tools.selected_count', { n: selection.size })}</p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button variant="outline" className="h-11 lg:h-9" onClick={() => setSelection(new Set())}>
              {t('tools.clear')}
            </Button>
            <Button className="h-11 lg:h-9" onClick={() => void makePlan([...selection], [])}>
              {t('tools.plan_button')}
            </Button>
          </div>
        </div>
      )}

      <ToolPlanSheet state={plan} onClose={() => setPlan({ phase: 'idle' })} onApply={() => plan.phase === 'review' && void apply(plan)} />
      <ToolJobSheet client={client} box={name} jobId={jobId} onClose={() => setJobId(null)} onFinished={reloadAll} />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('tools.remove_title', { name: removing?.tool.name ?? '' })}
        description={t('tools.remove_confirm', { names: removing ? removing.plan.tools.map((x) => x.name).join(', ') : '' })}
        confirmLabel={t('tools.remove')}
        destructive
        onConfirm={confirmRemove}
      />
      <SaveProfileSheet open={saveOpen} busy={saveBusy} error={saveError} onSubmit={(n, d) => void saveProfile(n, d)} onClose={() => setSaveOpen(false)} />
      <CreateFromProfileSheet profile={createFrom?.name ?? null} onSubmit={(n) => createFrom && startCreate(createFrom, n)} onClose={() => setCreateFrom(null)} />
      <PlanSheet state={flow.state} dispatch={flow.dispatch} onClose={() => flow.dispatch({ type: 'cancel' })} />
    </div>
  );
}
