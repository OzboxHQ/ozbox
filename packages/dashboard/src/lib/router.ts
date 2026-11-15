import { useEffect, useState } from 'react';

export type Route =
  | { page: 'fleet' }
  | { page: 'boxes' }
  | { page: 'box'; name: string }
  | { page: 'files'; name: string }
  | { page: 'tools'; name: string }
  | { page: 'terminal'; name: string }
  | { page: 'account' }
  | { page: 'tasks' }
  | { page: 'orchestrations' }
  | { page: 'memory' }
  | { page: 'skills' }
  | { page: 'browser' }
  | { page: 'schedules' }
  | { page: 'triggers' }
  | { page: 'approvals' }
  | { page: 'permissions' }
  | { page: 'chat' }
  | { page: 'usage' }
  | { page: 'bill' }
  | { page: 'activity' }
  | { page: 'settings'; section: SettingsSection }
  | { page: 'missing' };

export const SETTINGS_SECTIONS = ['general', 'providers', 'budgets', 'backups', 'apps', 'access', 'models', 'approvals', 'secret-approvals', 'approvers', 'defaults', 'members'] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number];

/**
 * Addresses the dashboard used to have, and the page that took their place. Runs became part of Tasks (one place for a person's
 * work), so a bookmark or a link to `/runs` lands on `/tasks`.
 */
export const MOVED: Readonly<Record<string, string>> = { '/runs': '/tasks' };

/** Where an old address now lives, or `null` when the address is current. A trailing slash is ignored. */
export function movedTo(pathname: string): string | null {
  return MOVED[pathname.replace(/\/+$/, '')] ?? null;
}

export function parseRoute(pathname: string): Route {
  const parts = (movedTo(pathname) ?? pathname).split('/').filter(Boolean);
  const [a, b] = parts;
  if (parts.length === 0) return { page: 'fleet' };
  if (a === 'boxes' && parts.length === 1) return { page: 'boxes' };
  if (a === 'boxes' && b && parts.length === 2) {
    try {
      return { page: 'box', name: decodeURIComponent(b) };
    } catch {
      return { page: 'missing' };
    }
  }
  if (a === 'boxes' && b && parts.length === 3 && parts[2] === 'files') {
    try {
      return { page: 'files', name: decodeURIComponent(b) };
    } catch {
      return { page: 'missing' };
    }
  }
  if (a === 'boxes' && b && parts.length === 3 && parts[2] === 'terminal') {
    try {
      return { page: 'terminal', name: decodeURIComponent(b) };
    } catch {
      return { page: 'missing' };
    }
  }
  if (a === 'account' && parts.length === 1) return { page: 'account' };
  if (a === 'costs' && b === 'bill' && parts.length === 2) return { page: 'bill' };
  if (a === 'boxes' && b && parts.length === 3 && parts[2] === 'tools') {
    try {
      return { page: 'tools', name: decodeURIComponent(b) };
    } catch {
      return { page: 'missing' };
    }
  }
  if (parts.length === 1 && (a === 'tasks' || a === 'orchestrations' || a === 'memory' || a === 'skills' || a === 'browser' || a === 'schedules' || a === 'triggers' || a === 'approvals' || a === 'permissions' || a === 'chat' || a === 'usage' || a === 'activity')) return { page: a };
  if (a === 'settings' && parts.length === 1) return { page: 'settings', section: 'general' };
  if (a === 'settings' && parts.length === 2) {
    const sec = SETTINGS_SECTIONS.find((x) => x === b);
    if (sec && sec !== 'general') return { page: 'settings', section: sec };
  }
  return { page: 'missing' };
}

export const hrefs = {
  fleet: '/',
  boxes: '/boxes',
  box: (name: string) => `/boxes/${encodeURIComponent(name)}`,
  files: (name: string) => `/boxes/${encodeURIComponent(name)}/files`,
  tools: (name: string) => `/boxes/${encodeURIComponent(name)}/tools`,
  terminal: (name: string) => `/boxes/${encodeURIComponent(name)}/terminal`,
  account: '/account',
  tasks: '/tasks',
  orchestrations: '/orchestrations',
  memory: '/memory',
  skills: '/skills',
  browser: '/browser',
  schedules: '/schedules',
  triggers: '/triggers',
  approvals: '/approvals',
  permissions: '/permissions',
  chat: '/chat',
  usage: '/usage',
  bill: '/costs/bill',
  activity: '/activity',
  settings: (section: SettingsSection = 'general') => (section === 'general' ? '/settings' : `/settings/${section}`),
};

export function navigate(path: string): void {
  window.history.pushState(null, '', path);
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo(0, 0);
}

/** Replace an old address in the address bar with its new one, keeping the query and the fragment, without adding a history entry. */
function followMoved(): void {
  const to = movedTo(window.location.pathname);
  if (to) window.history.replaceState(null, '', `${to}${window.location.search}${window.location.hash}`);
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => {
    followMoved();
    return parseRoute(window.location.pathname);
  });
  useEffect(() => {
    const on = () => {
      followMoved();
      setRoute(parseRoute(window.location.pathname));
    };
    window.addEventListener('popstate', on);
    return () => window.removeEventListener('popstate', on);
  }, []);
  return route;
}
