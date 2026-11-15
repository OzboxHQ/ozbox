import { Skeleton } from '@/components/ui/skeleton';
import type { BoxRecord } from '../api/types';
import { useApp } from '../App';
import { FilesView } from '../components/files/files-view';
import { AppLink, AppPage, PageHeader, StatusDot } from '../components/page';
import { hrefs } from '../lib/router';
import { CannotNote } from '../components/role-scope';
import { t } from '../lib/i18n';
import { useCan } from '../lib/use-can';
import { useAsync } from '../lib/use-async';

/** `/boxes/<name>/files`: the file browser on its own page, for a link or a bookmark. */
export function FilesPage({ name }: { name: string }) {
  const { client } = useApp();
  const box = useAsync<BoxRecord>((s) => client.getBox(name, s), [client, name], 10000);
  const { can } = useCan();
  if (!can('use_boxes')) {
    return (
      <AppPage>
        <PageHeader title={t('files.title')} />
        <CannotNote cap="use_boxes" />
      </AppPage>
    );
  }
  return (
    <AppPage>
      <PageHeader
        title={t('files.title')}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <AppLink href={hrefs.box(name)} className="inline-flex min-h-11 min-w-11 items-center justify-center text-primary underline-offset-4 hover:underline lg:min-h-0 lg:min-w-0">
              {name}
            </AppLink>
            {box.data && <StatusDot state={box.data.state} />}
          </span>
        }
      />
      {box.error && !box.data ? (
        <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm">
          {box.error.message}
        </div>
      ) : box.data ? (
        <FilesView box={box.data} />
      ) : (
        <Skeleton className="h-40 w-full" />
      )}
    </AppPage>
  );
}
