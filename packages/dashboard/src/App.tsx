import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import type { ApiClient } from './api/client';
import type { BoxRecord, Info } from './api/types';
import { BoxActionSheets, type ActionKind } from './components/box-action-sheets';
import { CommandPalette, type PaletteRun } from './components/command-palette';
import { FlowsHost } from './components/flows-host';
import { startEvents } from './lib/events';
import { openFlow } from './lib/flows';
import { AppLink, AppPage, EmptyState, PageHeader } from './components/page';
import { Shell } from './components/shell';
import { hrefs, navigate, useRoute } from './lib/router';
import { t } from './lib/i18n';
import { LoadError } from './components/load-error';
import { REQUIRED_LOAD_RETRY } from './lib/retry';
import { useAsync } from './lib/use-async';
import { ActivityPage } from './pages/activity-page';
import { ApprovalsPage } from './pages/approvals-page';
import { PermissionsPage } from './pages/permissions-page';
import { BillPage } from './pages/bill-page';
import { ChatPage } from './pages/chat-page';
import { BoxPage } from './pages/box-page';
import { FilesPage } from './pages/files-page';
import { ToolsPage } from './pages/tools-page';
import { MemoryPage } from './pages/memory-page';
import { OrchestrationsPage } from './pages/orchestrations-page';
import { BrowserPage } from './pages/browser-page';
import { SkillsPage } from './pages/skills-page';
import { TasksPage } from './pages/tasks-page';
import { SchedulesPage } from './pages/schedules-page';
import { TriggersPage } from './pages/triggers-page';
import { BoxesPage } from './pages/boxes-page';
import { FleetPage } from './pages/fleet-page';
import { AccountPage } from './pages/account-page';
import { GoPage } from './pages/go-page';
import { SettingsPage } from './pages/settings-page';
import { TerminalPage } from './pages/terminal-page';
import { UsagePage } from './pages/usage-page';

const Ctx = createContext<{ client: ApiClient; info: Info | null } | null>(null);

export function useApp() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useApp outside <App>');
  return v;
}

const TOKEN_KEY = 'ozbox.token';
/** How often a page that could not ask the server what it is asks again, in ms. */
const INFO_RECOVER_MS = 5000;

export function App({ client, onSignOut }: { client: ApiClient | null; onSignOut?: () => void }) {
  const route = useRoute();
  const [ended, setEnded] = useState(false);
  const info = useAsync((s) => (client ? client.info(s) : Promise.reject(new Error('no client'))), [client], undefined, REQUIRED_LOAD_RETRY);
  const value = useMemo(() => (client ? { client, info: info.data } : null), [client, info.data]);

  // With no answer after the tries, the page says so and keeps asking, so a server that was only busy brings the page back
  // by itself instead of leaving it on the error until someone presses Try again.
  const infoFailed = info.data === null && info.error !== null;
  const reloadInfo = info.reload;
  useEffect(() => {
    if (!infoFailed) return;
    const id = setInterval(reloadInfo, INFO_RECOVER_MS);
    return () => clearInterval(id);
  }, [infoFailed, reloadInfo]);

  const [paletteOpen, setPaletteOpen] = useState(false);
  const [pending, setPending] = useState<{ box: BoxRecord; kind: ActionKind } | null>(null);
  const boxes = useAsync<BoxRecord[]>((sig) => (client ? client.listBoxes(sig) : Promise.resolve([])), [client, paletteOpen]);

  // Live updates: the server tells every open tab when a change was applied, and every view refreshes.
  useEffect(() => {
    if (!client) return;
    const ctl = new AbortController();
    startEvents(client.eventsRequest(), (e) => {
      if (e.event === 'changed') window.dispatchEvent(new Event('ozbox:changed'));
    }, ctl.signal);
    return () => ctl.abort();
  }, [client]);

  // Command palette on Cmd+K / Ctrl+K.
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, []);

  const runPalette = useCallback(
    (r: PaletteRun) => {
      if (r.kind === 'go') return navigate(r.href);
      if (r.kind === 'flow') return openFlow(r.flow);
      const box = boxes.data?.find((b) => b.spec.name === r.box);
      if (box) setPending({ box, kind: r.action });
    },
    [boxes.data],
  );

  const endSession = useCallback(() => {
    // Behind a sign-in, ending the session signs out on the server; there is no token to forget.
    if (onSignOut) return onSignOut();
    try {
      window.sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      // nothing kept
    }
    setEnded(true);
  }, [onSignOut]);

  useEffect(() => {
    document.title = t('app.title');
  }, []);

  if (value === null || ended) {
    return (
      <main id="main" className="mx-auto max-w-xl p-6">
        <PageHeader title={t('app.no_link_heading')} />
        <div className="mt-4">
          <EmptyState title={ended ? t('app.session_ended') : t('app.no_access_link')}>
            {t('app.access_link_help_before')}<code>{'ozbox serve'}</code>{t('app.access_link_help_after')}
          </EmptyState>
        </div>
      </main>
    );
  }

  return (
    <Ctx.Provider value={value}>
      <Shell route={route} info={info.data} onEndSession={endSession} onSearch={() => setPaletteOpen(true)}>
        {/* What this server is (a fleet, one box, a demo) decides what every page offers, so with no answer after the tries a page says so and
            offers to ask again, instead of showing its parts as if they were allowed or denied. */}
        {info.data === null && info.error ? (
          <AppPage width="narrow">
            <PageHeader title={t('app.info_failed_title')} />
            <LoadError title={t('app.info_failed_title')} error={info.error} onRetry={info.reload} />
          </AppPage>
        ) : (
          <>
            {route.page === 'fleet' && <FleetPage />}
            {route.page === 'boxes' && <BoxesPage />}
            {route.page === 'box' && <BoxPage key={route.name} name={route.name} />}
            {route.page === 'files' && <FilesPage key={route.name} name={route.name} />}
            {route.page === 'tools' && <ToolsPage key={route.name} name={route.name} />}
            {route.page === 'terminal' && <TerminalPage key={route.name} name={route.name} />}
            {route.page === 'account' && <AccountPage />}
            {route.page === 'go' && <GoPage />}
            {route.page === 'tasks' && <TasksPage />}
            {route.page === 'orchestrations' && <OrchestrationsPage />}
            {route.page === 'memory' && <MemoryPage />}
            {route.page === 'skills' && <SkillsPage />}
            {route.page === 'browser' && <BrowserPage />}
            {route.page === 'schedules' && <SchedulesPage />}
            {route.page === 'triggers' && <TriggersPage />}
            {route.page === 'approvals' && <ApprovalsPage />}
            {route.page === 'permissions' && <PermissionsPage />}
            {route.page === 'chat' && <ChatPage />}
            {route.page === 'usage' && <UsagePage />}
            {route.page === 'bill' && <BillPage />}
            {route.page === 'activity' && <ActivityPage />}
            {route.page === 'settings' && <SettingsPage section={route.section} />}
            {route.page === 'missing' && (
              <AppPage width="narrow">
                <PageHeader title={t('app.not_found')} />
                <AppLink href={hrefs.fleet} className="inline-flex min-h-11 items-center text-sm text-primary underline-offset-4 hover:underline">
                  {t('app.back_to_fleet')}
                </AppLink>
              </AppPage>
            )}
          </>
        )}
      </Shell>
      <FlowsHost />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} boxes={boxes.data ?? []} onRun={runPalette} />
      {pending && (
        <BoxActionSheets
          key={`${pending.box.spec.name}:${pending.kind}`}
          box={pending.box}
          kind={pending.kind}
          client={value.client}
          info={info.data}
          onClose={() => setPending(null)}
          onApplied={() => window.dispatchEvent(new Event('ozbox:changed'))}
        />
      )}
    </Ctx.Provider>
  );
}
