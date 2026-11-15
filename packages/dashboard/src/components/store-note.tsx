import type { StoreInfo } from '../api/memory';
import { t } from '../lib/i18n';

/**
 * Where notes or skills are kept, in one plain sentence: on this box, or on the computer that runs the dashboard; and, when
 * the server has no settings file to sit beside, that they last only until it stops. Nothing until the server has answered.
 */
export function StoreNote({ what, store }: { what: 'memory' | 'skills'; store: StoreInfo | undefined }) {
  if (!store) return null;
  const where = store.on_a_box ? t('store.on_box', { box: store.host ?? '' }) : t('store.on_computer');
  return (
    <div className="space-y-1 rounded-md border bg-muted/40 px-3 py-2 text-sm" data-testid={`${what}-where`} data-persisted={store.persisted ? 'true' : 'false'}>
      <p>{t(what === 'memory' ? 'store.mem_kept' : 'store.skills_kept', { where })}</p>
      {store.persisted ? null : <p className="font-medium" data-testid={`${what}-forgotten`}>{t('store.not_persisted')}</p>}
    </div>
  );
}
