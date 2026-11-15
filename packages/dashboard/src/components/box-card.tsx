import { Card } from '@/components/ui/card';
import type { BoxRecord, CostBox, MetricsNow } from '../api/types';
import { fmtEstimate } from '../lib/cost';
import { t } from '../lib/i18n';
import { ABSENT, fmtCost, fmtRelative, isMachineMissing, memUsedPct, sizeLabel } from '../lib/format';
import { hrefs } from '../lib/router';
import { SourceBadge } from './source-badge';
import { ConnectButtons } from './connect-buttons';
import { OpenInMenu } from './open-in';
import { AppLink, StatusDot } from './page';
import { UsageBar } from './usage-bar';

/** One box in the fleet: state, size, live bars (labelled when simulated), cost and last activity. */
export function BoxCard({ box, now, domain, cost = null }: { box: BoxRecord; now: MetricsNow | undefined; domain: string | null; cost?: CostBox | null }) {
  const name = box.spec.name;
  const sample = now?.sample;
  return (
    <Card className="relative h-full p-4 transition-colors focus-within:ring-2 focus-within:ring-ring hover:bg-accent/50">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="truncate text-sm font-semibold">
            <AppLink href={hrefs.box(name)} className="flex min-h-11 items-center outline-none after:absolute after:inset-0 after:rounded-lg lg:min-h-0">
              {name}
            </AppLink>
          </h2>
          <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">{`${sizeLabel(box.spec.size)} · ${box.machine_type ?? ABSENT}`}</p>
        </div>
        <StatusDot state={box.state} className="shrink-0" />
      </div>
      <div className="mt-3 space-y-2">
        {box.state === 'running' && sample ? (
          <>
            <UsageBar label={t('card.cpu')} pct={sample.cpu_pct} />
            <UsageBar label={t('card.memory')} pct={memUsedPct(sample)} />
            {now && <SourceBadge source={now.source} />}
          </>
        ) : (
          <p className="text-xs text-muted-foreground">{isMachineMissing(box.state) ? t('card.missing') : box.state === 'running' ? t('card.usage_pending') : t('card.usage_off')}</p>
        )}
      </div>
      <dl className="mt-3 grid grid-cols-3 gap-x-3 text-xs">
        <div>
          <dt className="text-muted-foreground">{t('card.runs')}</dt>
          <dd className="font-medium">{sample ? sample.runs.length : ABSENT}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{t('card.cost_month')}</dt>
          <dd className="font-medium" data-testid="box-cost">{cost ? fmtEstimate(cost.month_to_date, cost.currency) : fmtCost(null)}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{t('card.last_active')}</dt>
          <dd className="font-medium">{fmtRelative(box.last_activity_at)}</dd>
        </div>
      </dl>
      {!isMachineMissing(box.state) && (
        <>
          <ConnectButtons box={box} domain={domain} className="mt-3" />
          <OpenInMenu box={box} domain={domain} className="mt-2" />
        </>
      )}
    </Card>
  );
}
