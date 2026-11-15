import type { ModelListResult, ModelPrice } from '../../api/types';
import { t } from '../../lib/i18n';
import { perMtok, priceIsStale } from '../../lib/models';

/** One line about a model's price: what it is, where it comes from, how old it is. Always an estimate. */
export function PriceNote({ price }: { price: ModelPrice | null }) {
  if (!price) return <span className="text-muted-foreground">{t('models.price_none')}</span>;
  if (price.origin === 'local') return <span>{t('models.price_local')}</span>;
  return (
    <span>
      {t('models.price_line', { input: perMtok(price.input_per_mtok_usd), output: perMtok(price.output_per_mtok_usd) })}
      {price.origin === 'entered' ? ` · ${t('models.price_entered')}` : ` · ${t('models.price_source', { source: price.source })}`}
      {price.as_of !== null && price.age_months !== null ? ` · ${t('models.price_as_of', { asOf: price.as_of, months: price.age_months })}` : ''}
      {price.note ? ` · ${price.note}` : ''}
      {priceIsStale(price) ? <span className="block text-amber-700 dark:text-amber-400">{t('models.price_stale')}</span> : null}
    </span>
  );
}

/** The models a provider offers, each with its estimated price when one is known. */
export function ModelList({ result }: { result: ModelListResult }) {
  if (result.priced.length === 0) return <p className="text-xs text-muted-foreground">{t('models.list_empty')}</p>;
  return (
    <div>
      <h4 className="text-xs font-medium text-muted-foreground">{t('models.list_title')}</h4>
      {/* a keyboard user can scroll the list: it is a focusable region */}
      <ul tabIndex={0} aria-label={t('models.list_title')} className="mt-1 max-h-56 space-y-2 overflow-y-auto rounded-md border p-2 text-xs">
        {result.priced.map((m) => (
          <li key={m.id}>
            <span className="break-all font-mono">{m.id}</span>
            <span className="block text-muted-foreground">
              <PriceNote price={m.price} />
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
