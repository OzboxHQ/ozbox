import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import type { EngineModel, ModelChoice, Settings } from '../../api/types';
import { useApp } from '../../App';
import { t } from '../../lib/i18n';
import { MODEL_RE, providersFor } from '../../lib/models';
import { useAsync } from '../../lib/use-async';

const NONE = '__none__';
const FLEET = '__fleet__';

interface Props {
  settings: Settings;
  save: (s: Settings) => Promise<string | null>;
  reload: () => void;
}

/** Which provider and model each agent engine uses, with a fallback, for the fleet or for one box. */
export function EnginesCard({ settings, save, reload }: Props) {
  const { client } = useApp();
  const catalog = useAsync((s) => client.modelsCatalog(s), [client]);
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const [engine, setEngine] = useState<string | null>(null);
  const [scope, setScope] = useState(FLEET);
  const [provider, setProvider] = useState(NONE);
  const [model, setModel] = useState('');
  const [fbProvider, setFbProvider] = useState(NONE);
  const [fbModel, setFbModel] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const providers = settings.models.providers;

  if (!catalog.data) return <Skeleton className="h-40 w-full" />;
  const engines = catalog.data.engines;
  const current = (id: string, sc: string): EngineModel | undefined => (sc === FLEET ? settings.models.engines[id] : settings.models.box_overrides[sc]?.[id]);
  const label = (id: string) => providers.find((p) => p.id === id)?.label ?? id;
  const describe = (e: { provider_id: string; model: string } | undefined) => (e ? `${label(e.provider_id)} · ${e.model}` : t('models.engine_unset'));

  const open = (id: string, sc: string) => {
    const e = current(id, sc);
    setEngine(id);
    setScope(sc);
    setProvider(e?.provider_id ?? NONE);
    setModel(e?.model ?? '');
    setFbProvider(e?.fallback?.provider_id ?? NONE);
    setFbModel(e?.fallback?.model ?? '');
    setErr(null);
  };

  const info = engines.find((e) => e.id === engine);
  const usable = providersFor(info, providers);

  const commit = async (clear: boolean) => {
    if (!engine) return;
    const m = settings.models;
    let entry: EngineModel | null = null;
    if (!clear) {
      if (provider === NONE || !MODEL_RE.test(model)) return setErr(t('models.model_invalid'));
      let fallback: ModelChoice | null = null;
      if (fbProvider !== NONE) {
        if (!MODEL_RE.test(fbModel)) return setErr(t('models.model_invalid'));
        fallback = { provider_id: fbProvider, model: fbModel };
      }
      entry = { provider_id: provider, model, fallback };
    }
    const engines2 = { ...m.engines };
    const overrides = { ...m.box_overrides };
    if (scope === FLEET) {
      if (entry) engines2[engine] = entry;
      else delete engines2[engine];
    } else {
      const per = { ...(overrides[scope] ?? {}) };
      if (entry) per[engine] = entry;
      else delete per[engine];
      if (Object.keys(per).length > 0) overrides[scope] = per;
      else delete overrides[scope];
    }
    const msg = await save({ ...settings, models: { ...m, engines: engines2, box_overrides: overrides } });
    if (msg) return setErr(msg);
    toast.success(t('models.saved'));
    setEngine(null);
    reload();
  };

  const overrideBoxes = (id: string) => Object.entries(settings.models.box_overrides).filter(([, per]) => per[id]);

  return (
    <Card className="space-y-3 p-4" data-testid="model-engines">
      <h2 className="text-sm font-semibold">{t('models.engines_title')}</h2>
      <p className="text-xs text-muted-foreground">{t('models.engines_help')}</p>
      <ul className="divide-y" aria-label={t('models.engines_title')}>
        {engines.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center justify-between gap-2 py-2" data-testid={`engine-${e.id}`}>
            <div className="min-w-0">
              <p className="text-sm font-medium">{e.label}</p>
              {e.runs === undefined ? null : <p className="text-xs text-muted-foreground" data-testid={`engine-runs-${e.id}`}>{t(e.runs ? 'models.engine_runs_preview' : 'models.engine_runs_planned')}</p>}
              <p className="text-xs text-muted-foreground">{describe(settings.models.engines[e.id])}</p>
              {settings.models.engines[e.id]?.fallback ? <p className="text-xs text-muted-foreground">{t('models.engine_fallback')}: {describe(settings.models.engines[e.id]?.fallback ?? undefined)}</p> : null}
              {overrideBoxes(e.id).map(([b, per]) => (
                <p key={b} className="text-xs text-muted-foreground">{t('models.engine_override_note', { box: b, provider: label(per[e.id]?.provider_id ?? ''), model: per[e.id]?.model ?? '' })}</p>
              ))}
            </div>
            <Button variant="outline" size="sm" className="max-lg:h-11" disabled={providers.length === 0} aria-label={t('models.engine_edit', { engine: e.label })} onClick={() => open(e.id, FLEET)}>{t('common.edit')}</Button>
          </li>
        ))}
      </ul>
      <PanelSheet open={engine !== null} onOpenChange={(o) => !o && setEngine(null)}>
        <PanelSheetContent size="compact" data-testid="engine-sheet">
          <form noValidate className="flex min-h-0 flex-1 flex-col" onSubmit={(e) => { e.preventDefault(); void commit(false); }}>
            <PanelSheetHeader>
              <PanelSheetTitle>{t('models.engine_title', { engine: info?.label ?? '' })}</PanelSheetTitle>
              <PanelSheetDescription>{t('models.engine_provider_only')}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
              {usable.length === 0 ? <p className="text-sm" role="status">{t('models.engine_no_providers')}</p> : null}
              <div className="space-y-1">
                <Label htmlFor="eng-scope">{t('models.engine_scope')}</Label>
                <Select value={scope} onValueChange={(v) => { if (engine) open(engine, v); }}>
                  <SelectTrigger id="eng-scope"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FLEET}>{t('models.engine_scope_fleet')}</SelectItem>
                    {(boxes.data ?? []).map((b) => (
                      <SelectItem key={b.spec.name} value={b.spec.name}>{b.spec.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="eng-provider">{t('models.provider')}</Label>
                <Select value={provider} onValueChange={setProvider}>
                  <SelectTrigger id="eng-provider"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>{t('models.none')}</SelectItem>
                    {usable.map((p) => (
                      <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="eng-model">{t('models.model')}</Label>
                <Input id="eng-model" autoComplete="off" className="max-lg:h-11" disabled={provider === NONE} value={model} onChange={(e) => setModel(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="eng-fb-provider">{t('models.engine_fallback_label')}</Label>
                <Select value={fbProvider} onValueChange={setFbProvider}>
                  <SelectTrigger id="eng-fb-provider"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>{t('models.none')}</SelectItem>
                    {usable.map((p) => (
                      <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="eng-fb-model">{t('models.engine_fallback_model')}</Label>
                <Input id="eng-fb-model" autoComplete="off" className="max-lg:h-11" disabled={fbProvider === NONE} value={fbModel} onChange={(e) => setFbModel(e.target.value)} />
              </div>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => void commit(true)} disabled={!current(engine ?? '', scope)}>{t('models.engine_clear')}</Button>
              <Button type="button" variant="outline" onClick={() => setEngine(null)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={usable.length === 0}>{t('common.save')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}
