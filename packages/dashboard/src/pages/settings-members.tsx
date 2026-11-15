import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useApp } from '../App';
import { PeopleCard } from '../components/auth/people-card';
import { t } from '../lib/i18n';
import { useAsync } from '../lib/use-async';

/** Who may sign in and what each person may do. Roles belong to a dashboard with a sign-in; a local one has one operator. */
export function MembersSection() {
  const { client } = useApp();
  const view = useAsync((s) => client.people.list(s), [client]);
  if (view.error && !view.data) return <p role="alert" className="text-sm text-destructive">{view.error.message}</p>;
  if (!view.data) return <Skeleton className="h-40 w-full" />;
  if (view.data.mode === 'token') {
    return (
      <Card className="space-y-2 p-4" data-testid="members-local">
        <h2 className="text-sm font-semibold">{t('people.title')}</h2>
        <p className="text-sm text-muted-foreground">{t('people.local_only')}</p>
      </Card>
    );
  }
  return <PeopleCard people={view.data.people} meId={view.data.me.id} onChanged={view.reload} />;
}
