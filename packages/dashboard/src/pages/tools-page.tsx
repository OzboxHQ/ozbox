import { Skeleton } from '@/components/ui/skeleton';
import type { BoxRecord } from '../api/types';
import { useApp } from '../App';
import { AppLink, AppPage, PageHeader, StatusDot } from '../components/page';
import { ToolsView } from '../components/tools/tools-view';
import { t } from '../lib/i18n';
import { hrefs } from '../lib/router';
import { useAsync } from '../lib/use-async';

/** `/boxes/<name>/tools`: the box's tools on their own page, for a link or a bookmark. */
export function ToolsPage({ name }: { name: string }) {
  const { client } = useApp();
  const box = useAsync<BoxRecord>((s) => client.getBox(name, s), [client, name], 10000);
  return (
    <AppPage>
      <PageHeader
        title={t('tools.title')}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <AppLink href={hrefs.box(name)} className="inline-flex min-h-11 items-center text-primary underline-offset-4 hover:underline lg:min-h-0">
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
        <ToolsView box={box.data} />
      ) : (
        <Skeleton className="h-40 w-full" />
      )}
    </AppPage>
  );
}
