import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from 'next-themes';
import { toast } from 'sonner';

import { App } from './App';
import { createApiClient } from './api/client';
import { createSessionApi, type SessionApi, type SessionStatus } from './api/session';
import { registerServiceWorker } from './lib/pwa';
import { SessionApp } from './session-app';
import { takeToken } from './lib/token';
import { Toaster } from '@/components/ui/sonner';
import './index.css';

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

const token = takeToken({
  hash: window.location.hash,
  pathname: window.location.pathname,
  search: window.location.search,
  replaceUrl: (url) => window.history.replaceState(null, '', url),
  storage: storage(),
});

const root = document.getElementById('root');

function render(tree: React.ReactNode): void {
  if (!root) return;
  createRoot(root).render(
    <StrictMode>
      <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
        {tree}
        <Toaster />
      </ThemeProvider>
    </StrictMode>,
  );
}

/**
 * Two ways in. With the access link `ozbox serve` prints, the token opens everything. On a shared machine there is no
 * token: the server says it wants a sign-in, and the pages for that come first.
 */
async function start(): Promise<void> {
  if (token) return render(<App client={createApiClient({ token })} />);
  const api: SessionApi = createSessionApi();
  const status = await api.status().catch(() => null);
  if (status && status.mode === 'session') return render(<SessionApp api={api} initial={status as SessionStatus} />);
  render(<App client={null} />);
}
void start();

// Installable app. A new version waits; the person chooses when to refresh (never an automatic reload).
registerServiceWorker((apply) => {
  toast('A new version of the dashboard is ready', { duration: Infinity, action: { label: 'Refresh', onClick: apply } });
});
