import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/client';
import { useApp } from '../App';
import { AuditCard } from '../components/perm/audit-card';
import { ReadOnlyScope } from '../components/role-scope';
import { GrantsCard } from '../components/perm/grants-card';
import { ModeCard, RulesCard } from '../components/perm/mode-rules-cards';
import { ToolsCard } from '../components/perm/tools-card';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { t } from '../lib/i18n';
import { useAsync } from '../lib/use-async';

/** Modes, rules and time-boxed Production grants, with the tamper-evident audit log and its check. */
export function PermissionsPage() {
  const { client, info } = useApp();
  const view = useAsync((s) => client.perm.view(s), [client], 5000);
  const unavailable = view.error instanceof ApiError && view.error.status === 501;
  return (
    <AppPage>
      <PageHeader title={t('perm.title')} description={t('perm.desc')} />
      {!view.data && !view.error ? <Skeleton className="h-40 w-full" /> : null}
      {unavailable ? <EmptyState title={t('perm.title')}>{t('perm.unavailable')}</EmptyState> : null}
      {view.error && !unavailable && !view.data ? <p role="alert" className="text-sm text-destructive">{t('perm.load_failed')}</p> : null}
      {view.data ? (
        <>
          <ReadOnlyScope cap="change_settings">
            <div className="space-y-4">
              <ModeCard key={view.data.settings.default_mode} client={client} settings={view.data.settings} reload={view.reload} />
              <RulesCard client={client} settings={view.data.settings} reload={view.reload} />
              <GrantsCard client={client} view={view.data} reload={view.reload} />
              <ToolsCard client={client} settings={view.data.settings} reload={view.reload} />
            </div>
          </ReadOnlyScope>
          <AuditCard client={client} zone={info?.clock?.time_zone} />
        </>
      ) : null}
    </AppPage>
  );
}
