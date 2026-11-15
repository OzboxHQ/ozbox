import { SETTINGS_SECTIONS, hrefs, type Route } from './router';

/**
 * One address for every page the dashboard has, so a guard can visit them all. Add a page to `Route` and the test beside this
 * file fails until it has a sample here, which is how "every route says plainly what it is" stays true for a page added later.
 */
export interface RouteSample {
  page: Route['page'];
  /** The address, for the box named `box` on pages that are about one box. */
  path: (box: string) => string;
  /** Settings pages only. */
  section?: string;
}

const fixed: Exclude<Route['page'], 'box' | 'files' | 'tools' | 'terminal' | 'settings' | 'missing'>[] = [
  'fleet',
  'boxes',
  'account',
  'tasks',
  'orchestrations',
  'memory',
  'skills',
  'browser',
  'schedules',
  'triggers',
  'approvals',
  'permissions',
  'chat',
  'usage',
  'bill',
  'activity',
];

export const ROUTE_SAMPLES: RouteSample[] = [
  ...fixed.map((page): RouteSample => ({ page, path: () => hrefs[page] })),
  { page: 'box', path: (b) => hrefs.box(b) },
  { page: 'files', path: (b) => hrefs.files(b) },
  { page: 'tools', path: (b) => hrefs.tools(b) },
  { page: 'terminal', path: (b) => hrefs.terminal(b) },
  ...SETTINGS_SECTIONS.map((section): RouteSample => ({ page: 'settings', section, path: () => hrefs.settings(section) })),
  { page: 'missing', path: () => '/no-such-page' },
];
