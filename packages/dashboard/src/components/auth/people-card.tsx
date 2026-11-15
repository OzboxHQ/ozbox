import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useApp } from '../../App';
import { ApiError } from '../../api/error';
import { withStepUp } from '../perm/with-step-up';
import { ROLES, type Role } from '../../api/people';
import { t } from '../../lib/i18n';
import { isRole } from '../../lib/roles';
import { useCan } from '../../lib/use-can';
import { ROLE_HELP, ROLE_LABEL } from '../role-scope';

interface Row {
  id: string;
  label: string;
  role: Role;
}

/** Everyone who may sign in, with their role. An owner changes a role here; it takes a passkey and is audited. */
export function PeopleCard({ people, meId, onChanged }: { people: Row[]; meId: string; onChanged: () => void }) {
  const { client } = useApp();
  const { can, role: myRole } = useCan();
  const [busy, setBusy] = useState<string | null>(null);
  const manage = can('manage_people');

  const change = async (id: string, role: Role) => {
    setBusy(id);
    try {
      await withStepUp(() => client.people.setRole(id, role));
      toast(t('people.changed'));
      onChanged();
    } catch (e) {
      toast.error(e instanceof ApiError && e.code === 'last_owner' ? t('people.last_owner') : e instanceof ApiError ? e.message : t('people.failed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card className="space-y-3 p-4" aria-labelledby="acct-people" data-testid="people-card">
      <h2 id="acct-people" className="text-base font-semibold">
        {t('people.title')}
      </h2>
      <p className="text-sm text-muted-foreground">{t('people.body')}</p>
      <p className="text-sm" data-testid="my-role">
        {t('roles.your_role', { role: t(ROLE_LABEL[myRole]) })}
      </p>
      {!manage && <p className="text-xs text-muted-foreground">{t('people.owner_only')}</p>}
      <ul className="divide-y text-sm">
        {people.map((p) => (
          <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 py-2" data-testid={`person-${p.id}`}>
            <span className="min-w-0 break-words">
              {p.label}
              {p.id === meId && <Badge variant="secondary" className="ml-2">{t('people.you')}</Badge>}
            </span>
            {manage ? (
              <Select value={p.role} disabled={busy !== null} onValueChange={(v) => isRole(v) && v !== p.role && void change(p.id, v)}>
                <SelectTrigger className="h-11 w-40 lg:h-9" aria-label={t('people.role_label', { name: p.label })} data-testid={`role-${p.id}`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {t(ROLE_LABEL[r])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Badge variant="outline" data-testid={`role-${p.id}`}>{t(ROLE_LABEL[p.role])}</Badge>
            )}
          </li>
        ))}
      </ul>
      <dl className="space-y-1 text-xs text-muted-foreground">
        {ROLES.map((r) => (
          <div key={r}>
            <dt className="inline font-medium">{t(ROLE_LABEL[r])}: </dt>
            <dd className="inline">{t(ROLE_HELP[r])}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
