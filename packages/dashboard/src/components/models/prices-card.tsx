import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { Settings } from '../../api/types';
import { t } from '../../lib/i18n';
import { MODEL_RE } from '../../lib/models';

const MAX_PRICE = 1_000_000;

/** A price per million tokens: a plain non-negative number with at most four decimals. */
export function parsePrice(raw: string): number | null {
  const v = raw.trim();
  if (!/^\d{1,7}(\.\d{1,4})?$/.test(v)) return null;
  const n = Number(v);
  return n >= 0 && n <= MAX_PRICE ? n : null;
}

/** Your own price for a model. It wins over the built-in estimate; clearing it goes back to the estimate. */
export function PricesCard({ settings, save, reload }: { settings: Settings; save: (s: Settings) => Promise<string | null>; reload: () => void }) {
  const providers = settings.models.providers;
  const [open, setOpen] = useState(false);
  const [provider, setProvider] = useState('');
  const [model, setModel] = useState('');
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const rows = Object.entries(settings.models.prices).sort(([a], [b]) => a.localeCompare(b));

  const start = (key?: string) => {
    const [p, ...rest] = (key ?? '').split('/');
    const m = rest.join('/');
    const cur = key ? settings.models.prices[key] : undefined;
    setProvider(p || (providers[0]?.id ?? ''));
    setModel(m);
    setInput(cur ? String(cur.input_per_mtok_usd) : '');
    setOutput(cur ? String(cur.output_per_mtok_usd) : '');
    setErr(null);
    setOpen(true);
  };

  const write = async (prices: Settings['models']['prices']) => {
    const msg = await save({ ...settings, models: { ...settings.models, prices } });
    if (msg) {
      setErr(msg);
      return false;
    }
    toast.success(t('models.saved'));
    reload();
    return true;
  };

  return (
    <Card className="space-y-3 p-4" data-testid="model-prices">
      <div className="flex items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('models.prices_title')}</h2>
        <Button variant="outline" size="sm" className="max-lg:h-11" disabled={providers.length === 0} onClick={() => start()}>
          {t('models.prices_add')}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('models.prices_help')}</p>
      {rows.length === 0 ? (
        <p className="text-sm" data-testid="prices-empty">{t('models.prices_none')}</p>
      ) : (
        <ul className="space-y-2" aria-label={t('models.prices_title')}>
          {rows.map(([key, p]) => (
            <li key={key} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2 text-sm" data-testid="price-row">
              <span className="min-w-0 break-all font-mono text-xs">{key}</span>
              <span>{t('models.prices_row', { input: p.input_per_mtok_usd, output: p.output_per_mtok_usd })}</span>
              <span className="flex gap-2">
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => start(key)}>{t('common.edit')}</Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="max-lg:h-11"
                  onClick={async () => {
                    const next = { ...settings.models.prices };
                    delete next[key];
                    await write(next);
                  }}
                >
                  {t('models.prices_clear')}
                </Button>
              </span>
            </li>
          ))}
        </ul>
      )}
      <PanelSheet open={open} onOpenChange={setOpen}>
        <PanelSheetContent size="compact" data-testid="price-sheet">
          <form
            noValidate
            className="flex min-h-0 flex-1 flex-col"
            onSubmit={async (e) => {
              e.preventDefault();
              const i = parsePrice(input);
              const o = parsePrice(output);
              if (!provider || !MODEL_RE.test(model.trim()) || i === null || o === null) return setErr(t('models.prices_invalid'));
              if (await write({ ...settings.models.prices, [`${provider}/${model.trim()}`]: { input_per_mtok_usd: i, output_per_mtok_usd: o } })) setOpen(false);
            }}
          >
            <PanelSheetHeader>
              <PanelSheetTitle>{t('models.prices_title')}</PanelSheetTitle>
              <PanelSheetDescription>{t('models.prices_help')}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody className="space-y-4">
              {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
              <div className="space-y-1">
                <Label htmlFor="pr-provider">{t('models.provider')}</Label>
                <Select value={provider} onValueChange={setProvider}>
                  <SelectTrigger id="pr-provider" className="max-lg:h-11"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {providers.map((p) => <SelectItem key={p.id} value={p.id}>{p.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pr-model">{t('models.model')}</Label>
                <Input id="pr-model" autoComplete="off" className="max-lg:h-11" value={model} onChange={(e) => setModel(e.target.value)} />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label htmlFor="pr-in">{t('models.prices_input')}</Label>
                  <Input id="pr-in" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={input} onChange={(e) => setInput(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="pr-out">{t('models.prices_output')}</Label>
                  <Input id="pr-out" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={output} onChange={(e) => setOutput(e.target.value)} />
                </div>
              </div>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
              <Button type="submit">{t('common.save')}</Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}
