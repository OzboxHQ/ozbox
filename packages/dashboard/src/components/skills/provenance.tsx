import type { Provenance } from '../../api/memory';
import { t } from '../../lib/i18n';
import { VIA_KEY } from '../../lib/skills';

/** Where a skill came from, in one sentence. */
export function ProvenanceLine({ p }: { p: Provenance }) {
  if (p.origin === 'bundled') return <>{t('skills.provenance_bundled')}</>;
  if (p.origin === 'removed') return <>{t('skills.provenance_removed')}</>;
  if (!p.by || !p.via || !p.ms) return <>{t('skills.provenance_library_unknown')}</>;
  const when = new Date(p.ms).toLocaleString();
  return <>{t('skills.provenance_library_who', { by: p.by, how: t(VIA_KEY[p.via] ?? 'skills.via_folder'), when })}</>;
}
