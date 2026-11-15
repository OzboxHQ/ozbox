import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError, type ApiClient } from '../../api/client';
import { t, type MessageKey } from '../../lib/i18n';
import { formatWithUtc } from '../../lib/locale';
import { AUDIT_FILTERS, problems, shortHash } from '../../lib/perm';
import { useAsync } from '../../lib/use-async';

const ALL = '__all__';

export function AuditCard({ client, zone }: { client: ApiClient; zone: string | undefined }) {
  const [filter, setFilter] = useState<string>('');
  const list = useAsync((s) => client.perm.audit(60, filter, s), [client, filter], 8000);
  const check = useAsync((s) => client.perm.verify(s), [client]);
  const [busy, setBusy] = useState(false);
  const report = check.data?.report;
  const found = report && !report.ok ? problems(report) : [];

  return (
    <Card className="space-y-3 p-4" data-testid="perm-audit">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold">{t('perm.audit_title')}</h2>
          <p className="text-xs text-muted-foreground">{t('perm.audit_desc')}</p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
          <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" disabled={busy} onClick={() => check.reload()} data-testid="perm-audit-check">
            {t('perm.audit_check')}
          </Button>
          <Button
            variant="outline"
            className="w-full max-lg:h-11 sm:w-auto"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await client.perm.seal();
                toast.success(t(r.sealed ? 'perm.audit_sealed' : 'perm.audit_nothing'));
              } catch (e) {
                toast.error(e instanceof ApiError ? e.message : t('perm.save_failed'));
              } finally {
                setBusy(false);
                check.reload();
              }
            }}
          >
            {t('perm.audit_seal')}
          </Button>
        </div>
      </div>

      {!report && !check.error ? (
        <p className="text-sm text-muted-foreground" data-testid="perm-audit-status" data-ok="checking">
          {t('perm.audit_checking')}
        </p>
      ) : null}
      {report ? (
        <div role="status" className="space-y-1" data-testid="perm-audit-status" data-ok={report.ok ? 'yes' : 'no'}>
          <p className={report.ok ? 'text-sm font-medium' : 'text-sm font-medium text-destructive'}>{report.ok ? t('perm.audit_ok', { entries: report.entries }) : t('perm.audit_broken')}</p>
          {found.map(([kind, where]) => (
            <p key={kind + where} className="text-sm text-destructive">
              {t(`perm.problem_${kind}` as MessageKey, { where })}
            </p>
          ))}
          {report.ok && report.unsealed_tail > 0 ? <p className="text-xs text-muted-foreground">{t('perm.audit_unsealed', { n: report.unsealed_tail })}</p> : null}
          {!report.seals_checked ? <p className="text-xs text-muted-foreground">{t('perm.audit_seals_unchecked')}</p> : null}
          {report.head_hash ? (
            <p className="break-all text-xs text-muted-foreground" title={t('perm.audit_head_hint')}>
              {t('perm.audit_head', { hash: shortHash(report.head_hash) })}
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="max-w-xs space-y-1.5">
        <Label htmlFor="audit-filter">{t('perm.audit_filter')}</Label>
        <Select value={filter === '' ? ALL : filter} onValueChange={(v) => setFilter(v === ALL ? '' : v)}>
          <SelectTrigger id="audit-filter">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {AUDIT_FILTERS.map((f) => (
              <SelectItem key={f || ALL} value={f === '' ? ALL : f}>
                {f === '' ? t('perm.audit_filter_all') : t(`perm.audit_filter_${f.replace('.', '')}` as MessageKey)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {!list.data && !list.error ? <Skeleton className="h-24 w-full" /> : null}
      {list.data && list.data.entries.length === 0 ? <p className="text-sm text-muted-foreground">{t('perm.audit_none')}</p> : null}
      {list.data && list.data.entries.length > 0 ? (
        <ul className="divide-y rounded-md border" aria-label={t('perm.audit_list')} data-testid="perm-audit-list">
          {list.data.entries.map((e) => (
            <li key={e.seq} className="space-y-1 p-3" data-testid="perm-audit-entry" data-action={e.action}>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{`#${e.seq}`}</Badge>
                <span className="break-all text-sm font-medium">{e.action}</span>
                <span className="text-xs text-muted-foreground">{formatWithUtc(e.ts_ms, zone)}</span>
              </div>
              <p className="break-words text-xs text-muted-foreground">{[e.actor, e.subject, e.detail].filter(Boolean).join(' · ')}</p>
            </li>
          ))}
        </ul>
      ) : null}
    </Card>
  );
}
