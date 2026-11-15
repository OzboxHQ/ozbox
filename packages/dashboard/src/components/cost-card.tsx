import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ApiError } from '../api/client';
import type { CostResponse } from '../api/types';
import { useApp } from '../App';
import { fmtEstimate, priceSourceLine } from '../lib/cost';
import { t } from '../lib/i18n';

/**
 * The cost estimate and where it comes from: the price list, how old it is, and (loudly) when it is stale. It never
 * shows a number the server did not give, and a figure is always marked as an estimate.
 */
export function CostCard({ cost, onRefreshed, unreachable }: { cost: CostResponse | null; onRefreshed: () => void; unreachable?: { name: string; reason: string }[] }) {
  const { client } = useApp();
  if (!cost) return null;
  const f = cost.fleet;
  async function refresh() {
    try {
      await client.refreshPrices();
      toast.success(t('cost.refreshed'));
      onRefreshed();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('common.request_failed'));
    }
  }
  return (
    <Card className="space-y-3 p-4" data-testid="cost-card">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline">{t('cost.est')}</Badge>
          {cost.prices?.stale ? <Badge variant="destructive">{t('cost.stale')}</Badge> : null}
        </div>
        {cost.prices ? (
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={refresh}>
            {t('cost.refresh')}
          </Button>
        ) : null}
      </div>
      <dl className="grid grid-cols-2 gap-3">
        <div>
          <dt className="text-xs text-muted-foreground">{t('cost.run_rate')}</dt>
          <dd className="text-lg font-semibold tabular-nums" data-testid="cost-run-rate">{fmtEstimate(f.run_rate_month, cost.currency)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">{t('cost.month_to_date')}</dt>
          <dd className="text-lg font-semibold tabular-nums" data-testid="cost-mtd">{fmtEstimate(f.month_to_date, f.month_to_date_currency)}</dd>
        </div>
      </dl>
      <p className="text-xs text-muted-foreground" data-testid="cost-source">{priceSourceLine(cost.prices, cost.entered_prices_used)}</p>
      {f.observed_since_ms ? <p className="text-xs text-muted-foreground">{t('cost.observed_since', { when: new Date(f.observed_since_ms).toLocaleString() })}</p> : null}
      <p className="text-xs text-muted-foreground">{t('cost.basis')}</p>
      {f.unpriced.length > 0 ? <p className="text-xs">{t('cost.unpriced', { names: f.unpriced.join(', ') })}</p> : null}
      {cost.price_error ? (
        <p role="status" className="text-xs text-destructive">{t('cost.price_error', { reason: cost.price_error })}</p>
      ) : null}
      {unreachable && unreachable.length > 0 ? <p role="status" className="text-xs">{t('cost.unreachable', { names: unreachable.map((u) => u.name).join(', ') })}</p> : null}
    </Card>
  );
}
