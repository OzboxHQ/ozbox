import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import type { BoxRecord } from '../api/types';
import { useApp } from '../App';
import { openInReason } from '../lib/connect';
import { fillSteps, WORK_PATH, type OpenInApp, OPEN_IN_APPS } from '../lib/open-in-apps';
import { t } from '../lib/i18n';
import { copyAndSay } from '../lib/copy-and-say';
import { useAsync } from '../lib/use-async';

function copy(text: string, what: string) {
  return copyAndSay(text, { done: t('openin.copied', { what }), failed: t('openin.copy_failed', { what: what.toLowerCase() }) });
}

function OpenInSheet({ box, app, onClose }: { box: BoxRecord; app: OpenInApp; onClose: () => void }) {
  const { client } = useApp();
  const ssh = useAsync((s) => client.sshEntry(box.spec.name, s), [client, box.spec.name]);
  const [makingKey, setMakingKey] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const makeKey = async () => {
    setMakingKey(true);
    setKeyError(null);
    try {
      await client.createSshKey(box.spec.name);
      ssh.reload();
    } catch (e) {
      setKeyError(`${t('openin.key_failed')}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setMakingKey(false);
    }
  };
  const alias = ssh.data?.host ?? `ozbox-${box.spec.name}`;
  const steps = fillSteps(app, alias);
  const uri = app.uri ? app.uri(alias, WORK_PATH) : null;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="open-in-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('openin.title', { box: box.spec.name, app: app.name })}</PanelSheetTitle>
          <PanelSheetDescription>{t('openin.description')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {!ssh.data && !ssh.error && <Skeleton className="h-24 w-full" />}
          {ssh.error && <p role="alert" className="text-sm text-destructive">{ssh.error.message}</p>}
          {ssh.data && (
            <>
              {ssh.data.key_exists === false && (
                <div role="status" className="space-y-2 rounded-md border p-3 text-sm" data-testid="ssh-key-missing">
                  <p>{t('openin.key_missing')}</p>
                  {keyError && <p role="alert" className="text-destructive">{keyError}</p>}
                  <Button size="sm" className="max-lg:h-11" disabled={makingKey} onClick={makeKey}>
                    {t('openin.key_create')}
                  </Button>
                </div>
              )}
              <ol className="list-decimal space-y-2 pl-5 text-sm">
                {steps.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ol>
              {ssh.data.routes.map((r) => (
                <div key={r.id} className="space-y-2 rounded-md border p-3" data-testid={`route-${r.id}`}>
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold">{r.label}</h3>
                    <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => copy(r.config, t('openin.what_entry'))}>
                      {t('openin.copy_entry')}
                    </Button>
                  </div>
                  <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-5">{r.config}</pre>
                  <p className="text-xs text-muted-foreground">{r.requirements}</p>
                </div>
              ))}
              <div className="flex flex-wrap items-center gap-2">
                <code className="rounded border bg-muted px-2 py-1 font-mono text-xs">{ssh.data.command}</code>
                <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => copy(ssh.data?.command ?? '', t('openin.what_command'))}>
                  {t('openin.copy_command')}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                {t('openin.write_hint_before')}<code>ozbox connect {box.spec.name} --ssh --write</code>{t('openin.write_hint_after')}
              </p>
              {app.unverified && <p className="text-xs text-muted-foreground">{t('openin.unverified')}</p>}
              <p className="text-xs text-muted-foreground">
                {app.source}{' '}
                <a href={app.doc} target="_blank" rel="noopener noreferrer" className="underline underline-offset-4">
                  {t('openin.documentation')}
                </a>
              </p>
            </>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.close')}
          </Button>
          {uri && (
            <Button asChild>
              <a href={uri}>{t('openin.open_in_app', { app: app.name })}</a>
            </Button>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

/** "Open in…": pick a desktop app and get the way to connect it. Off, with its reason, until the box has a tunnel. */
export function OpenInMenu({ box, domain, className }: { box: BoxRecord; domain: string | null | undefined; className?: string }) {
  const [app, setApp] = useState<OpenInApp | null>(null);
  const reason = openInReason(box, domain);
  const reasonId = `openin-reason-${box.spec.name}`;
  return (
    <div className={className}>
      {reason ? (
        <>
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled aria-describedby={reasonId}>
            {t('openin.open_in')}
          </Button>
          <p id={reasonId} className="mt-1 text-xs text-muted-foreground">
            {reason}
          </p>
        </>
      ) : (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="relative z-10 max-lg:h-11">
              {t('openin.open_in')}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-56">
            {OPEN_IN_APPS.map((a) => (
              <DropdownMenuItem key={a.id} onSelect={() => setApp(a)}>
                {a.name}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {app && <OpenInSheet box={box} app={app} onClose={() => setApp(null)} />}
    </div>
  );
}
