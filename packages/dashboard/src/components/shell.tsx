import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useTheme } from 'next-themes';
import {
  Activity01Icon,
  Calendar03Icon,
  FlashIcon,
  ArrowDown01Icon,
  ChartLineData01Icon,
  Invoice01Icon,
  CheckmarkCircle02Icon,
  GitBranchIcon,
  Folder01Icon,
  File01Icon,
  Message01Icon,
  KanbanIcon,
  Search01Icon,
  ComputerIcon,
  GridViewIcon,
  Logout01Icon,
  Menu01Icon,
  Moon02Icon,
  PinIcon,
  PinOffIcon,
  ServerStack01Icon,
  Settings01Icon,
  Sun01Icon,
  SecurityCheckIcon,
  Tick02Icon,
  UserCircleIcon,
} from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';

import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { Info } from '../api/types';
import { t, type MessageKey } from '../lib/i18n';
import { hrefs, navigate, type Route } from '../lib/router';
import { useSession } from '../lib/session-context';
import { FleetBanners } from './fleet-notice';
import { AppLink } from './page';

const PIN_KEY = 'ozbox.rail.pinned';

/** The shared look of a header control: 44px on touch widths, compact from lg. */
export const HEADER_BUTTON =
  'inline-flex h-11 min-w-11 shrink-0 items-center justify-center gap-1.5 rounded-md px-2 text-sm text-foreground outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring lg:h-8 lg:min-w-8 lg:text-[13px]';

interface NavEntry {
  key: string;
  label: MessageKey;
  icon: typeof GridViewIcon;
  href: string;
}

const NAV: NavEntry[] = [
  { key: 'fleet', label: 'nav.fleet', icon: GridViewIcon, href: hrefs.fleet },
  { key: 'boxes', label: 'nav.boxes', icon: ServerStack01Icon, href: hrefs.boxes },
  { key: 'tasks', label: 'nav.tasks', icon: KanbanIcon, href: hrefs.tasks },
  { key: 'orchestrations', label: 'nav.orchestrations', icon: GitBranchIcon, href: hrefs.orchestrations },
  { key: 'memory', label: 'nav.memory', icon: Folder01Icon, href: hrefs.memory },
  { key: 'skills', label: 'nav.skills', icon: File01Icon, href: hrefs.skills },
  { key: 'browser', label: 'nav.browser', icon: ComputerIcon, href: hrefs.browser },
  { key: 'schedules', label: 'nav.schedules', icon: Calendar03Icon, href: hrefs.schedules },
  { key: 'triggers', label: 'nav.triggers', icon: FlashIcon, href: hrefs.triggers },
  { key: 'chat', label: 'nav.chat', icon: Message01Icon, href: hrefs.chat },
  { key: 'approvals', label: 'nav.approvals', icon: CheckmarkCircle02Icon, href: hrefs.approvals },
  { key: 'permissions', label: 'nav.permissions', icon: SecurityCheckIcon, href: hrefs.permissions },
  { key: 'usage', label: 'nav.usage', icon: ChartLineData01Icon, href: hrefs.usage },
  { key: 'bill', label: 'nav.bill', icon: Invoice01Icon, href: hrefs.bill },
  { key: 'activity', label: 'nav.activity', icon: Activity01Icon, href: hrefs.activity },
  { key: 'settings', label: 'nav.settings', icon: Settings01Icon, href: hrefs.settings() },
];

function isActive(route: Route, entry: NavEntry): boolean {
  switch (entry.key) {
    case 'fleet':
      return route.page === 'fleet';
    case 'boxes':
      return route.page === 'boxes' || route.page === 'box' || route.page === 'files' || route.page === 'tools';
    default:
      return route.page === entry.key;
  }
}

function leafLabel(route: Route): string | null {
  switch (route.page) {
    case 'fleet':
      return t('nav.fleet');
    case 'boxes':
      return t('nav.boxes');
    case 'box':
    case 'files':
    case 'tools':
      return route.name;
    case 'tasks':
      return t('nav.tasks');
    case 'orchestrations':
      return t('nav.orchestrations');
    case 'memory':
      return t('nav.memory');
    case 'skills':
      return t('nav.skills');
    case 'browser':
      return t('nav.browser');
    case 'schedules':
      return t('nav.schedules');
    case 'triggers':
      return t('nav.triggers');
    case 'chat':
      return t('nav.chat');
    case 'approvals':
      return t('nav.approvals');
    case 'permissions':
      return t('nav.permissions');
    case 'usage':
      return t('nav.usage');
    case 'bill':
      return t('nav.bill');
    case 'activity':
      return t('nav.activity');
    case 'settings':
      return t('nav.settings');
    default:
      return null;
  }
}

function Rail({ route, pinned, onTogglePin }: { route: Route; pinned: boolean; onTogglePin: () => void }) {
  // Hover and keyboard focus expand the rail separately, so neither can leave it stuck open.
  const [hover, setHover] = useState(false);
  const [focusWithin, setFocusWithin] = useState(false);
  const expanded = pinned || hover || focusWithin;
  const key = route.page;
  const last = useRef(key);
  useEffect(() => {
    if (last.current === key) return;
    last.current = key;
    setHover(false);
    setFocusWithin(false);
  }, [key]);

  return (
    <aside
      aria-label={t('shell.primary')}
      onPointerEnter={(e) => {
        if (e.pointerType === 'mouse') setHover(true);
      }}
      onPointerLeave={() => setHover(false)}
      onFocus={(e) => {
        if (e.target.matches(':focus-visible')) setFocusWithin(true);
      }}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocusWithin(false);
      }}
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          setHover(false);
          setFocusWithin(false);
        }
      }}
      className={cn(
        'fixed bottom-0 left-0 top-14 z-30 hidden flex-col overflow-hidden border-r bg-sidebar text-sidebar-foreground transition-[width] duration-150 md:flex lg:top-12',
        expanded ? 'w-52' : 'w-14 lg:w-12',
        expanded && !pinned && 'shadow-lg',
      )}
    >
      <nav aria-label={t('shell.main')} className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto overflow-x-hidden p-1">
        {NAV.map((item) => {
          const active = isActive(route, item);
          const link = (
            <AppLink
              href={item.href}
              aria-label={t(item.label)}
              aria-current={active ? 'page' : undefined}
              className={cn(
                'flex h-11 items-center gap-3 rounded-md px-[9px] text-[13px] outline-none transition-colors focus-visible:ring-2 focus-visible:ring-sidebar-ring lg:h-8',
                active ? 'bg-sidebar-accent font-medium text-sidebar-accent-foreground' : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
              )}
            >
              <HugeiconsIcon icon={item.icon} className="h-[15px] w-[15px] shrink-0" />
              <span aria-hidden className={cn('truncate transition-opacity', expanded ? 'opacity-100' : 'opacity-0')}>
                {t(item.label)}
              </span>
            </AppLink>
          );
          return (
            <Tooltip key={item.key}>
              <TooltipTrigger asChild>{link}</TooltipTrigger>
              {!expanded && <TooltipContent side="right">{t(item.label)}</TooltipContent>}
            </Tooltip>
          );
        })}
      </nav>
      <div className="border-t border-sidebar-border p-1">
        <button
          type="button"
          onClick={onTogglePin}
          aria-pressed={pinned}
          aria-label={pinned ? t('shell.unpin_sidebar') : t('shell.pin_sidebar')}
          className="flex h-11 w-full items-center gap-3 rounded-md px-[9px] text-[13px] text-sidebar-foreground outline-none hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-sidebar-ring lg:h-8"
        >
          <HugeiconsIcon icon={pinned ? PinOffIcon : PinIcon} className="h-[15px] w-[15px] shrink-0" />
          <span aria-hidden className={cn('truncate transition-opacity', expanded ? 'opacity-100' : 'opacity-0')}>
            {pinned ? t('shell.unpin') : t('shell.pin_open')}
          </span>
        </button>
      </div>
    </aside>
  );
}

function MobileMenu({ route, open, onOpenChange }: { route: Route; open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent size="compact">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('shell.menu')}</PanelSheetTitle>
          <PanelSheetDescription className="sr-only">{t('shell.go_to_page')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody>
          <nav aria-label={t('shell.menu')}>
            <ul className="space-y-1">
              {NAV.map((item) => {
                const active = isActive(route, item);
                return (
                  <li key={item.key}>
                    <AppLink
                      href={item.href}
                      aria-current={active ? 'page' : undefined}
                      onClick={() => onOpenChange(false)}
                      className={cn('flex min-h-11 items-center gap-3 rounded-md px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring', active ? 'bg-accent font-medium' : 'hover:bg-accent')}
                    >
                      <HugeiconsIcon icon={item.icon} className="h-4 w-4 shrink-0" />
                      {t(item.label)}
                    </AppLink>
                  </li>
                );
              })}
            </ul>
          </nav>
        </PanelSheetBody>
      </PanelSheetContent>
    </PanelSheet>
  );
}

/** Where the organisation switcher sits in a multi-tenant console. One fleet today, so it lists just that one. */
function FleetSwitcher({ info }: { info: Info | null }) {
  const name = t('shell.my_fleet');
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className={cn(HEADER_BUTTON, 'min-w-0 max-w-[9.5rem] shrink justify-between font-medium sm:max-w-[14rem]')} aria-label={t('shell.fleet_switch', { name })}>
        <span className="truncate">{name}</span>
        <HugeiconsIcon icon={ArrowDown01Icon} className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel>{t('shell.fleets')}</DropdownMenuLabel>
        <DropdownMenuItem onSelect={() => navigate(hrefs.fleet)} className="justify-between gap-2">
          <span className="truncate">{name}</span>
          <span className="flex shrink-0 items-center gap-1.5">
            {info && <span className="rounded border px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">{info.provider}</span>}
            <HugeiconsIcon icon={Tick02Icon} className="h-4 w-4" />
          </span>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled>{t('shell.new_fleet')}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const icon = !mounted ? ComputerIcon : resolvedTheme === 'dark' ? Moon02Icon : Sun01Icon;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className={HEADER_BUTTON} aria-label={t('shell.theme')}>
        <HugeiconsIcon icon={icon} className="h-4 w-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuRadioGroup value={mounted ? (theme ?? 'system') : 'system'} onValueChange={setTheme}>
          <DropdownMenuRadioItem value="light">{t('shell.theme_light')}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">{t('shell.theme_dark')}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system">{t('shell.theme_system')}</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function SessionMenu({ onEnd }: { onEnd: () => void }) {
  const session = useSession();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className={cn(HEADER_BUTTON, 'px-1')} aria-label={t('shell.session_menu')}>
        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-secondary-foreground lg:h-6 lg:w-6">
          <HugeiconsIcon icon={UserCircleIcon} className="h-4 w-4" />
        </span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel className="font-normal">
          <span className="block truncate text-sm font-medium">{session ? (session.status.user?.label ?? t('shell.signed_in')) : t('shell.this_computer')}</span>
          <span className="block truncate text-xs text-muted-foreground">{session ? t('shell.signed_in') : t('shell.local_session')}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {session && (
          <DropdownMenuItem onSelect={() => navigate(hrefs.account)}>
            <HugeiconsIcon icon={UserCircleIcon} className="mr-2 h-4 w-4" />
            {t('shell.account')}
          </DropdownMenuItem>
        )}
        <DropdownMenuItem onSelect={onEnd}>
          <HugeiconsIcon icon={Logout01Icon} className="mr-2 h-4 w-4" />
          {session ? t('shell.sign_out') : t('shell.end_session')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** The app frame: fixed header (breadcrumbs, switcher, controls), a hover-expanding rail, and the page. */
export function Shell({ route, info, onEndSession, onSearch, children, extra }: { route: Route; info: Info | null; onEndSession: () => void; onSearch: () => void; children: ReactNode; extra?: ReactNode }) {
  const [pinned, setPinned] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const closeMenu = useCallback((o: boolean) => setMenuOpen(o), []);

  useEffect(() => {
    try {
      setPinned(localStorage.getItem(PIN_KEY) === '1');
    } catch {
      // Pinning is a per-viewer convenience; the rail works without it.
    }
  }, []);
  const togglePin = useCallback(() => {
    setPinned((p) => {
      try {
        localStorage.setItem(PIN_KEY, p ? '0' : '1');
      } catch {
        // see above
      }
      return !p;
    });
  }, []);

  const leaf = leafLabel(route);
  return (
    <TooltipProvider delayDuration={150}>
      <a href="#main" className="sr-only z-[60] rounded-md bg-background px-3 py-2 text-sm focus:not-sr-only focus:fixed focus:left-2 focus:top-2">
        {t('shell.skip')}
      </a>
      <header className="fixed inset-x-0 top-0 z-40 flex h-14 items-center gap-1 border-b bg-background px-2 sm:px-3 lg:h-12">
        <button type="button" onClick={() => setMenuOpen(true)} aria-label={t('shell.open_menu')} className={cn(HEADER_BUTTON, 'md:hidden')}>
          <HugeiconsIcon icon={Menu01Icon} className="h-5 w-5" />
        </button>
        <AppLink href={hrefs.fleet} aria-label={t('shell.home')} className="flex h-11 shrink-0 items-center justify-center rounded-md px-2 text-sm font-bold outline-none focus-visible:ring-2 focus-visible:ring-ring lg:h-8">
          {t('app.title')}
        </AppLink>
        <div className="mx-1 hidden h-5 w-px bg-border sm:block" aria-hidden />
        <nav aria-label={t('shell.breadcrumb')} className="min-w-0 flex-1 overflow-hidden">
          <ol className="flex min-w-0 items-center gap-0.5 text-sm lg:text-[13px]">
            <li className="flex min-w-0 shrink">
              <FleetSwitcher info={info} />
            </li>
            {leaf && (
              <>
                <li aria-hidden className="select-none text-muted-foreground">/</li>
                <li className="hidden min-w-0 truncate px-2 text-muted-foreground sm:block" aria-current="page">
                  {leaf}
                </li>
              </>
            )}
          </ol>
        </nav>
        <div className="ml-auto flex shrink-0 items-center gap-0.5">
          <button
            type="button"
            onClick={onSearch}
            className="hidden h-8 w-56 items-center gap-2 rounded-md border bg-background px-2.5 text-[13px] text-muted-foreground outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring xl:flex"
          >
            <HugeiconsIcon icon={Search01Icon} className="h-3.5 w-3.5" />
            <span className="flex-1 text-left">{t('shell.search_or_run')}</span>
            <kbd className="rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-foreground">⌘K</kbd>
          </button>
          <button type="button" onClick={onSearch} aria-label={t('shell.search_actions')} className={cn(HEADER_BUTTON, 'xl:hidden')}>
            <HugeiconsIcon icon={Search01Icon} className="h-4 w-4" />
          </button>
          {extra}
          <ThemeToggle />
          <SessionMenu onEnd={onEndSession} />
        </div>
      </header>
      <Rail route={route} pinned={pinned} onTogglePin={togglePin} />
      <main id="main" tabIndex={-1} className={cn('min-h-screen min-w-0 pt-14 outline-none lg:pt-12', pinned ? 'md:pl-52' : 'md:pl-14 lg:pl-12')}>
        <FleetBanners route={route} info={info} />
        {children}
      </main>
      <MobileMenu route={route} open={menuOpen} onOpenChange={closeMenu} />
    </TooltipProvider>
  );
}
