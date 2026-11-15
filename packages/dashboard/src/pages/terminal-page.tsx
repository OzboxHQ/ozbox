import type { BoxRecord } from '../api/types';
import { AppLink, AppPage, EmptyState, PageHeader } from '../components/page';
import { TerminalView } from '../components/terminal/terminal-view';
import { useApp } from '../App';
import { CannotNote } from '../components/role-scope';
import { t } from '../lib/i18n';
import { useCan } from '../lib/use-can';
import { hrefs } from '../lib/router';
import { useAsync } from '../lib/use-async';

export function TerminalPage({ name }: { name: string }) {
  const { client } = useApp();
  const box = useAsync<BoxRecord>((s) => client.getBox(name, s), [client, name], 5000);
  const { can } = useCan();
  if (!can('use_boxes')) {
    return (
      <AppPage>
        <PageHeader title={t('terminal.title')} />
        <CannotNote cap="use_boxes" />
      </AppPage>
    );
  }
  return (
    <AppPage className="flex h-[calc(100dvh-4rem)] flex-col">
      <PageHeader
        title={t('terminal.title')}
        description={
          <AppLink href={hrefs.box(name)} className="inline-flex min-h-11 items-center text-primary underline-offset-4 hover:underline">
            {t('terminal.back', { name })}
          </AppLink>
        }
      />
      {box.data && box.data.state !== 'running' ? <EmptyState title={name}>{t('terminal.not_running')}</EmptyState> : <TerminalView box={name} className="flex-1" />}
    </AppPage>
  );
}
