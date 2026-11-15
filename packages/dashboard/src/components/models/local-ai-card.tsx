import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../../api/client';
import type { LocalAiPlan } from '../../api/types';
import { useApp } from '../../App';
import { SourceNote } from '../source-badge';
import { t } from '../../lib/i18n';
import { gpuBoxes } from '../../lib/models';
import { useAsync } from '../../lib/use-async';

const errorText = (e: unknown) => (e instanceof ApiError ? e.message : t('common.request_failed'));

/** Ollama or vLLM on a GPU box: pick a model, see the download and the disk it takes, then apply. */
export function LocalAiCard({ reload }: { reload: () => void }) {
  const { client, info } = useApp();
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const catalog = useAsync((s) => client.localCatalog(s), [client]);
  const [box, setBox] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<'ollama' | 'vllm'>('vllm');
  const [model, setModel] = useState<string | null>(null);
  const [plan, setPlan] = useState<LocalAiPlan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const gpu = gpuBoxes(boxes.data ?? []);
  const chosen = box ?? gpu[0]?.spec.name ?? null;
  const status = useAsync((s) => (chosen ? client.localAiStatus(chosen, s) : Promise.resolve(null)), [client, chosen]);
  const loadError = (boxes.data ? null : boxes.error) ?? (catalog.data ? null : catalog.error);
  if (loadError) return <Alert variant="destructive" role="alert" data-testid="local-ai-error"><AlertDescription>{loadError.message}</AlertDescription></Alert>;
  if (!boxes.data || !catalog.data) return <Skeleton className="h-40 w-full" />;
  const models = catalog.data.models.filter((m) => m.runtime === runtime);
  const rt = status.data?.runtimes.find((r) => r.id === runtime);
  const running = gpu.find((b) => b.spec.name === chosen)?.state === 'running';

  const review = async () => {
    if (!chosen || !model) return;
    setErr(null);
    setBusy(true);
    try {
      setPlan(await client.localAiPlan(chosen, runtime, model));
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!plan) return;
    setBusy(true);
    try {
      await client.localAiApply(plan.box_name, plan, undefined, plan.install_only);
      toast.success(t('models.local_done', { model: plan.model }));
      setPlan(null);
      status.reload();
      reload();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="space-y-3 p-4" data-testid="model-local-ai">
      <h2 className="text-sm font-semibold">{t('models.local_title')}</h2>
      <SourceNote source={status.data?.source ?? info?.metrics} what="local-ai" />
      <p className="text-xs text-muted-foreground">{t('models.local_help')}</p>
      {gpu.length === 0 ? (
        <p className="text-sm" data-testid="local-no-gpu">{t('models.local_no_gpu')}</p>
      ) : (
        <>
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1">
              <Label htmlFor="la-box">{t('models.local_box')}</Label>
              <Select value={chosen ?? ''} onValueChange={(v) => { setBox(v); setModel(null); }}>
                <SelectTrigger id="la-box"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {gpu.map((b) => (
                    <SelectItem key={b.spec.name} value={b.spec.name}>{b.spec.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="la-runtime">{t('models.local_runtime')}</Label>
              <Select value={runtime} onValueChange={(v) => { setRuntime(v as 'ollama' | 'vllm'); setModel(null); }}>
                <SelectTrigger id="la-runtime"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="vllm">{t('models.runtime_vllm')}</SelectItem>
                  <SelectItem value="ollama">{t('models.runtime_ollama')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="la-model">{t('models.local_model')}</Label>
              <Select value={model ?? ''} onValueChange={setModel}>
                <SelectTrigger id="la-model"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {models.map((m) => (
                    <SelectItem key={m.id} value={m.id}>{`${m.label} (${m.id})`}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {status.error && !status.data ? <Alert variant="destructive" role="alert" data-testid="local-ai-status-error"><AlertDescription>{t('models.local_status_failed', { why: status.error.message })}</AlertDescription></Alert> : null}
          {!running ? <p className="text-sm" role="status">{t('models.local_not_running')}</p> : null}
          {rt ? (
            <div className="space-y-1" data-testid="local-status">
              <Badge variant={rt.installed ? 'default' : 'outline'}>{rt.installed ? t('models.local_installed') : t('models.local_not_installed')}</Badge>
              {!rt.installed ? <p className="text-xs text-muted-foreground">{t('models.local_install_first', { runtime: rt.id })}</p> : null}
              <p className="text-xs text-muted-foreground">{rt.models.length > 0 ? t('models.local_models_held', { models: rt.models.join(', ') }) : t('models.local_none_held')}</p>
              {rt.registered ? <p className="text-xs text-muted-foreground">{t('models.local_registered')}</p> : null}
            </div>
          ) : null}
          <Button className="max-lg:h-11" disabled={!model || !running || busy} onClick={() => void review()}>{t('models.local_review')}</Button>
        </>
      )}
      <OneClick running={(boxes.data ?? []).filter((b) => b.state === 'running').map((b) => b.spec.name)} onPlan={setPlan} onError={setErr} />
      <PanelSheet open={plan !== null} onOpenChange={(o) => !o && setPlan(null)}>
        <PanelSheetContent size="compact" data-testid="local-plan-sheet">
          {plan ? (
            <>
              <PanelSheetHeader>
                <PanelSheetTitle>{t('models.local_plan_title', { model: plan.model, box: plan.box_name })}</PanelSheetTitle>
                <PanelSheetDescription>{t('models.local_plan_endpoint', { endpoint: plan.endpoint })}</PanelSheetDescription>
              </PanelSheetHeader>
              <PanelSheetBody className="space-y-3 text-sm">
                {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
                <p data-testid="local-plan-size">{t('models.local_plan_size', { gb: plan.download_gb })}</p>
                <p>{plan.disk_free_gb !== null ? t('models.local_plan_disk', { free: plan.disk_free_gb.toFixed(0), total: plan.work_disk_gb }) : t('models.local_plan_disk_unknown', { total: plan.work_disk_gb })}</p>
                <p>{plan.compute === 'cpu' ? t('models.local_plan_ram', { need: plan.memory_gb_needed, have: plan.memory_gb_available }) : t('models.local_plan_gpu', { need: plan.gpu_gb_needed, have: plan.gpu_gb_available })}</p>
                {plan.install_only ? <p data-testid="local-plan-install">{t('models.local_plan_install')}</p> : null}
                {plan.blocked && !plan.install_only ? <Alert variant="destructive" role="alert"><AlertDescription>{t('models.local_plan_blocked', { why: plan.blocked })}</AlertDescription></Alert> : null}
              </PanelSheetBody>
              <PanelSheetFooter>
                <Button type="button" variant="outline" onClick={() => setPlan(null)}>{t('common.cancel')}</Button>
                <Button type="button" disabled={!(plan.can_apply || plan.install_only) || busy} onClick={() => void apply()}>{plan.install_only ? t('models.local_apply_install') : t('models.local_apply')}</Button>
              </PanelSheetFooter>
            </>
          ) : null}
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}

/** Ollama on any running box, GPU or not: Oz Box picks the model, the person reviews the plan, one click installs and adds it. */
function OneClick({ running, onPlan, onError }: { running: string[]; onPlan: (p: LocalAiPlan) => void; onError: (m: string | null) => void }) {
  const { client } = useApp();
  const [box, setBox] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const chosen = box ?? running[0] ?? null;
  return (
    <div className="space-y-2 border-t pt-3" data-testid="local-oneclick">
      <h3 className="text-sm font-semibold">{t('models.oneclick_title')}</h3>
      <p className="text-xs text-muted-foreground">{t('models.oneclick_help')}</p>
      {running.length === 0 ? (
        <p className="text-sm">{t('models.oneclick_none')}</p>
      ) : (
        <div className="grid items-end gap-3 sm:grid-cols-[1fr_auto]">
          <div className="space-y-1">
            <Label htmlFor="la-oneclick-box">{t('models.oneclick_box')}</Label>
            <Select value={chosen ?? ''} onValueChange={setBox}>
              <SelectTrigger id="la-oneclick-box" className="max-lg:h-11"><SelectValue /></SelectTrigger>
              <SelectContent>
                {running.map((b) => (
                  <SelectItem key={b} value={b}>{b}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button
            className="max-lg:h-11"
            disabled={!chosen || busy}
            onClick={async () => {
              if (!chosen) return;
              onError(null);
              setBusy(true);
              try {
                onPlan(await client.localAiPlan(chosen, 'ollama', 'auto'));
              } catch (e) {
                onError(errorText(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            {t('models.oneclick_go')}
          </Button>
        </div>
      )}
    </div>
  );
}
