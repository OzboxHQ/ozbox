import { MoreHorizontalIcon } from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';

import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { TAP_ACTION_ICON } from '@/components/ui/tap-target';
import { cn } from '@/lib/utils';
import type { BoxRecord } from '../api/types';
import { useApp } from '../App';
import { fleetNotConnected } from '../lib/fleet';
import { isMachineMissing } from '../lib/format';
import { t } from '../lib/i18n';
import type { ActionKind } from './box-action-sheets';

/** The row menu: every item asks for a plan first; none changes anything by itself. */
export function BoxMenu({ box, onAction, onOpen }: { box: BoxRecord; onAction: (kind: ActionKind) => void; onOpen?: () => void }) {
  const { info } = useApp();
  // On a box's own dashboard nothing can change a fleet: open is all there is, and the rest says why it is missing.
  if (fleetNotConnected(info)) {
    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className={cn(TAP_ACTION_ICON)} aria-label={t('menu.actions_for', { name: box.spec.name })}>
            <HugeiconsIcon icon={MoreHorizontalIcon} className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          {onOpen && <DropdownMenuItem onSelect={onOpen}>{t('menu.open')}</DropdownMenuItem>}
          <DropdownMenuItem disabled data-testid="menu-fleet-not-connected">
            {t('fleetnote.unavailable')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className={cn(TAP_ACTION_ICON)} aria-label={t('menu.actions_for', { name: box.spec.name })}>
          <HugeiconsIcon icon={MoreHorizontalIcon} className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        {onOpen && <DropdownMenuItem onSelect={onOpen}>{t('menu.open')}</DropdownMenuItem>}
        {box.state === 'running' && <DropdownMenuItem onSelect={() => onAction('pause')}>{t('menu.pause')}</DropdownMenuItem>}
        {box.state === 'paused' && <DropdownMenuItem onSelect={() => onAction('resume')}>{t('menu.resume')}</DropdownMenuItem>}
        {/* With no machine, only finishing the upgrade and destroying act on the box; the server refuses the rest. */}
        {!isMachineMissing(box.state) && <DropdownMenuItem onSelect={() => onAction('snapshot')}>{t('menu.snapshot')}</DropdownMenuItem>}
        {!isMachineMissing(box.state) && <DropdownMenuItem onSelect={() => onAction('resize')}>{t('menu.resize')}</DropdownMenuItem>}
        <DropdownMenuItem onSelect={() => onAction('upgrade')}>{isMachineMissing(box.state) ? t('menu.finish_upgrade') : t('menu.upgrade')}</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => onAction('destroy')} className="text-destructive">
          {t('menu.destroy')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
