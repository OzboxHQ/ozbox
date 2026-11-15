import type { ReactNode } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { BoxState } from '../api/types';
import { stateLabel } from '../lib/format';
import { navigate } from '../lib/router';

/** Anchor that navigates inside the app without a page load. */
export function AppLink({ href, className, children, ...rest }: { href: string; className?: string; children: ReactNode } & Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  return (
    <a
      href={href}
      className={className}
      onClick={(e) => {
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        navigate(href);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}

/** The one page container for every screen: comfortable gutters on a phone and tablet, tighter from lg. */
export function AppPage({ children, width = 'full', className }: { children: ReactNode; width?: 'full' | 'form' | 'narrow'; className?: string }) {
  return (
    <div
      className={cn(
        'w-full min-w-0 space-y-4 p-4 sm:space-y-6 sm:p-6 lg:space-y-5 lg:p-6 xl:px-8',
        width === 'form' && 'max-w-3xl',
        width === 'narrow' && 'max-w-5xl',
        className,
      )}
    >
      {children}
    </div>
  );
}

export function PageHeader({ title, description, actions, className }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6', className)}>
      <div className="min-w-0">
        <h1 className="break-words text-2xl font-semibold tracking-tight lg:text-xl">{title}</h1>
        {description ? <div className="mt-1 text-sm text-muted-foreground">{description}</div> : null}
      </div>
      {actions ? <div className="flex w-full shrink-0 flex-wrap items-center gap-2 sm:w-auto">{actions}</div> : null}
    </div>
  );
}

const DOT: Record<BoxState, string> = {
  running: 'bg-emerald-500',
  paused: 'bg-zinc-400',
  creating: 'bg-amber-500 animate-pulse',
  pausing: 'bg-amber-500 animate-pulse',
  resuming: 'bg-amber-500 animate-pulse',
  resizing: 'bg-sky-500 animate-pulse',
  destroying: 'bg-amber-500 animate-pulse',
  instance_missing: 'bg-red-500',
  unknown: 'bg-red-500',
};

/** A coloured dot AND the word: colour is never the only signal. */
export function StatusDot({ state, className }: { state: BoxState; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-xs text-muted-foreground', className)}>
      <span aria-hidden className={cn('h-2 w-2 rounded-full', DOT[state])} />
      {stateLabel(state)}
    </span>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-10 text-center">
      <p className="text-sm font-medium">{title}</p>
      {children ? <div className="max-w-md text-sm text-muted-foreground">{children}</div> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function StatCard({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <Card className="p-4">
      <h3 className="text-xs font-medium text-muted-foreground">{label}</h3>
      <p className="mt-1 text-xl font-semibold tabular-nums lg:text-lg">{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
    </Card>
  );
}

export function SubNav({ items, label, current }: { items: { href: string; label: string }[]; label: string; current: string }) {
  return (
    <nav aria-label={label} className="no-scrollbar flex gap-1 overflow-x-auto">
      {items.map((i) => {
        const active = current === i.href;
        return (
          <AppLink
            key={i.href}
            href={i.href}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'inline-flex min-h-11 shrink-0 items-center rounded-md px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring lg:min-h-8 lg:text-[13px]',
              active ? 'bg-accent font-medium' : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground',
            )}
          >
            {i.label}
          </AppLink>
        );
      })}
    </nav>
  );
}

export function pagerPages(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

/** The table footer: "N boxes · page X of Y" with Previous / Next. */
export function TablePager({ page, pageSize, total, noun = ['box', 'boxes'], onPageChange }: { page: number; pageSize: number; total: number; noun?: [string, string]; onPageChange: (p: number) => void }) {
  const pages = pagerPages(total, pageSize);
  const shown = Math.min(page, pages);
  return (
    <div className="flex items-center justify-between gap-2 border-t p-3 text-sm">
      <span className="text-muted-foreground" data-testid="table-pager-summary">{`${total.toLocaleString('en-US')} ${total === 1 ? noun[0] : noun[1]} · page ${shown} of ${pages}`}</span>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" className="max-lg:h-11" disabled={shown <= 1} onClick={() => onPageChange(shown - 1)}>
          Previous
        </Button>
        <Button variant="outline" size="sm" className="max-lg:h-11" disabled={shown >= pages} onClick={() => onPageChange(shown + 1)}>
          Next
        </Button>
      </div>
    </div>
  );
}
