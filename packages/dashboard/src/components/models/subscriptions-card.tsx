import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useApp } from '../../App';
import { en } from '../../i18n/en';
import { t } from '../../lib/i18n';
import { SUB_SIGNIN_LABEL, SUB_STATUS_LABEL, subscriptionRows } from '../../lib/models';
import { useAsync } from '../../lib/use-async';

const has = (k: string) => k in en;

/**
 * Whether each engine can run on a person's own subscription instead of an API key, and why not (ADR 0054). Read only:
 * no sign-in adapter is built, so there is nothing to connect, and the card never offers a button that implies there is.
 */
export function SubscriptionsCard() {
  const { client } = useApp();
  const catalog = useAsync((s) => client.modelsCatalog(s), [client]);
  if (catalog.error && !catalog.data) return <p role="alert" className="text-sm text-destructive">{catalog.error.message}</p>;
  if (!catalog.data) return <Skeleton className="h-40 w-full" />;
  const rows = subscriptionRows(catalog.data.subscriptions, has);
  if (rows.length === 0) return null;
  const checked = rows[0]?.sub.checked_on ?? '';
  return (
    <Card className="space-y-3 p-4" data-testid="model-subscriptions">
      <h2 className="text-sm font-semibold">{t('models.sub_title')}</h2>
      <p className="text-xs text-muted-foreground">{t('models.sub_intro')}</p>
      <p className="text-xs text-muted-foreground">{t('models.sub_own_login')}</p>
      <ul className="grid gap-3 lg:grid-cols-2" aria-label={t('models.sub_title')}>
        {rows.map(({ sub, plan, reason, links }) => (
          <li key={sub.id} className="min-w-0 space-y-2 rounded-md border p-3" data-testid={`subscription-${sub.id}`}>
            <div className="flex items-start justify-between gap-2">
              <h3 className="min-w-0 break-words text-sm font-medium">{t(plan)}</h3>
              <Badge variant="outline" className="shrink-0">{t(SUB_STATUS_LABEL[sub.status])}</Badge>
            </div>
            <p className="text-xs text-muted-foreground">{t(SUB_SIGNIN_LABEL[sub.sign_in])}</p>
            <p className="break-words text-xs">{t(reason)}</p>
            {links.length > 0 ? (
              <ul className="flex flex-wrap gap-x-4 gap-y-1">
                {links.map((u, i) => (
                  <li key={u}>
                    <a
                      href={u}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex min-h-11 items-center text-xs font-medium underline underline-offset-2 lg:min-h-0"
                      aria-label={t('models.sub_source', { n: i + 1, plan: t(plan) })}
                    >
                      {t('models.sub_source_short', { n: i + 1 })}
                    </a>
                  </li>
                ))}
              </ul>
            ) : null}
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">{t('models.sub_checked', { date: checked })}</p>
    </Card>
  );
}
