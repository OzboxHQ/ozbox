import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError, type ApiClient } from '../../api/client';
import { ENVIRONMENTS, type Environment, type PermSettings } from '../../api/perm';
import { t, type MessageKey } from '../../lib/i18n';
import { hostList, hostProblem, withHosts } from '../../lib/perm';
import { useAsync } from '../../lib/use-async';
import { FieldError } from '../sched-bits';
import { withStepUp } from './with-step-up';

const EFFECT_VARIANT = { allow: 'secondary', ask: 'outline', deny: 'destructive' } as const;

/** The tools an agent has on a box, what a new call to each would be decided as, and the hosts the browser may open. */
export function ToolsCard({ client, settings, reload }: { client: ApiClient; settings: PermSettings; reload: () => void }) {
  const [env, setEnv] = useState<Environment>('sandbox');
  const view = useAsync((s) => client.perm.hostTools(env, s), [client, env, settings.default_mode, settings.rules.length, settings.browser_hosts.join(',')], 8000);
  const [hosts, setHosts] = useState(settings.browser_hosts.join(' '));
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const parsed = hostList(hosts);
  const invalid = tried && hostProblem(parsed);

  async function saveHosts() {
    setTried(true);
    if (hostProblem(parsed)) return;
    setBusy(true);
    try {
      await withStepUp(() => client.perm.save(withHosts(settings, parsed)));
      toast.success(t('perm.hosts_saved'));
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('perm.save_failed'));
    } finally {
      setBusy(false);
      reload();
    }
  }

  return (
    <Card className="space-y-4 p-4" data-testid="perm-tools">
      <div>
        <h2 className="text-sm font-semibold">{t('perm.tools_title')}</h2>
        <p className="text-xs text-muted-foreground">{t('perm.tools_desc')}</p>
      </div>
      <div className="max-w-xs space-y-1.5">
        <Label htmlFor="tools-env">{t('perm.tools_env')}</Label>
        <Select value={env} onValueChange={(v) => setEnv(v as Environment)}>
          <SelectTrigger id="tools-env" data-testid="perm-tools-env">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ENVIRONMENTS.map((x) => (
              <SelectItem key={x} value={x}>
                {t(`perm.env_${x}` as MessageKey)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {!view.data && !view.error ? <Skeleton className="h-24 w-full" /> : null}
      {view.error && !view.data ? <p role="alert" className="text-sm text-destructive">{t('perm.tools_failed')}</p> : null}
      {view.data ? (
        <ul className="divide-y rounded-md border" aria-label={t('perm.tools_list')} data-testid="perm-tools-list" data-env={view.data.env}>
          {view.data.tools.map((x) => (
            <li key={x.name} className="space-y-1 p-3" data-testid="host-tool" data-tool={x.name} data-effect={x.effect} data-reason={x.reason}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="break-all text-sm font-medium">{x.name}</span>
                <Badge variant="outline">{x.server}</Badge>
                <Badge variant="outline">{t(`perm.tools_${x.writes}` as MessageKey)}</Badge>
                <Badge variant={EFFECT_VARIANT[x.effect]}>{t(`perm.tools_${x.effect}` as MessageKey)}</Badge>
              </div>
              <p className="break-words text-xs text-muted-foreground">{x.summary}</p>
              <p className="break-words text-xs text-muted-foreground">
                {t(`perm.reason_${x.reason}` as MessageKey)}
                {x.rule ? t('perm.reason_rule_note', { id: x.rule }) : ''}
              </p>
            </li>
          ))}
        </ul>
      ) : null}

      <div className="space-y-1.5 border-t pt-4" data-testid="perm-hosts">
        <h3 className="text-sm font-semibold">{t('perm.hosts_title')}</h3>
        <p className="text-xs text-muted-foreground">{t('perm.hosts_desc')}</p>
        <Label htmlFor="browser-hosts">{t('perm.hosts_label')}</Label>
        <Input id="browser-hosts" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={hosts} aria-invalid={invalid} onChange={(e) => setHosts(e.target.value.replace(/\n/g, ' '))} />
        <FieldError msg={invalid ? t('perm.hosts_invalid') : undefined} />
        <Button className="w-full max-lg:h-11 sm:w-auto" disabled={busy} onClick={() => void saveHosts()}>
          {t('perm.hosts_save')}
        </Button>
      </div>
    </Card>
  );
}
