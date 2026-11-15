import { useState, type ReactNode } from 'react';
import {
  File01Icon,
  Folder01Icon,
  Image01Icon,
  LockIcon,
  MoreHorizontalIcon,
  Pdf01Icon,
} from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';

import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { cn } from '@/lib/utils';
import type { FileEntry, SortKey } from '../../api/files';
import { ABSENT, fmtBytes, fmtRelative } from '../../lib/format';
import { entryIcon } from '../../lib/files';
import { t } from '../../lib/i18n';
import { useMedia } from '../../lib/use-media';
import { blockedText } from './messages';

export type RowAction = 'open' | 'download' | 'rename' | 'share' | 'delete';

const ICONS = { folder: Folder01Icon, image: Image01Icon, pdf: Pdf01Icon, text: File01Icon, file: File01Icon, lock: LockIcon };

export function EntryIcon({ entry, className }: { entry: FileEntry; className?: string }) {
  return <HugeiconsIcon icon={ICONS[entryIcon(entry)]} className={cn('h-5 w-5 shrink-0', className)} aria-hidden="true" />;
}

const kindText = (e: FileEntry) => (e.kind === 'dir' ? t('files.kind_dir') : e.kind === 'file' ? t('files.kind_file') : t('files.kind_other'));
const modifiedText = (ms: number) => (ms > 0 ? fmtRelative(new Date(ms).toISOString()) : ABSENT);

/** What can be done with one entry. A blocked one can only be deleted. */
export function actionsFor(e: FileEntry): RowAction[] {
  if (e.blocked) return e.kind === 'other' ? [] : ['delete'];
  return e.kind === 'dir' ? ['open', 'rename', 'share', 'delete'] : ['open', 'download', 'rename', 'share', 'delete'];
}

const ACTION_LABEL: Record<RowAction, () => string> = {
  open: () => t('files.open'),
  download: () => t('files.download'),
  rename: () => t('files.rename'),
  share: () => t('files.share'),
  delete: () => t('files.delete'),
};

function NameButton({ entry, onOpen, children }: { entry: FileEntry; onOpen: (e: FileEntry) => void; children?: ReactNode }) {
  if (entry.blocked) {
    return (
      <div className="flex min-w-0 items-center gap-2 text-muted-foreground">
        <EntryIcon entry={entry} />
        <div className="min-w-0">
          <div className="truncate" title={entry.name}>{entry.name}</div>
          <div className="text-xs">{blockedText(entry.blocked)}</div>
        </div>
      </div>
    );
  }
  return (
    <button
      type="button"
      onClick={() => onOpen(entry)}
      className="-mx-1 flex min-h-11 min-w-11 items-center gap-2 rounded px-1 text-left outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring lg:min-h-8"
    >
      <EntryIcon entry={entry} className={entry.kind === 'dir' ? 'text-primary' : undefined} />
      <span className="truncate" title={entry.name}>{entry.name}</span>
      {entry.symlink && <span className="shrink-0 text-xs text-muted-foreground">({t('files.link_suffix')})</span>}
      {children}
    </button>
  );
}

/** The actions for one entry: a menu from md, a bottom sheet on a phone. */
function RowMenu({ entry, onAction }: { entry: FileEntry; onAction: (a: RowAction, e: FileEntry) => void }) {
  const phone = useMedia('(max-width: 767px)');
  const [open, setOpen] = useState(false);
  const actions = actionsFor(entry);
  if (actions.length === 0) return null;
  const label = t('files.actions', { name: entry.name });
  const trigger = (
    <Button variant="ghost" size="icon" className="h-11 w-11 shrink-0 lg:h-8 lg:w-8" aria-label={label} onClick={phone ? () => setOpen(true) : undefined}>
      <HugeiconsIcon icon={MoreHorizontalIcon} className="h-4 w-4" />
    </Button>
  );
  if (phone) {
    return (
      <>
        {trigger}
        <PanelSheet open={open} onOpenChange={setOpen}>
          <PanelSheetContent size="compact">
            <PanelSheetHeader>
              <PanelSheetTitle>{t('files.actions_title')}</PanelSheetTitle>
              <PanelSheetDescription className="truncate">{entry.name}</PanelSheetDescription>
            </PanelSheetHeader>
            <PanelSheetBody>
              <ul className="space-y-1">
                {actions.map((a) => (
                  <li key={a}>
                    <Button
                      variant="ghost"
                      className={cn('h-11 w-full justify-start', a === 'delete' && 'text-destructive')}
                      onClick={() => {
                        setOpen(false);
                        onAction(a, entry);
                      }}
                    >
                      {ACTION_LABEL[a]()}
                    </Button>
                  </li>
                ))}
              </ul>
            </PanelSheetBody>
          </PanelSheetContent>
        </PanelSheet>
      </>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        {actions.map((a) => (
          <div key={a}>
            {a === 'delete' && actions.length > 1 && <DropdownMenuSeparator />}
            <DropdownMenuItem onSelect={() => onAction(a, entry)} className={a === 'delete' ? 'text-destructive' : undefined}>
              {ACTION_LABEL[a]()}
            </DropdownMenuItem>
          </div>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export interface FilesListProps {
  entries: FileEntry[];
  view: 'list' | 'grid';
  selected: ReadonlySet<string>;
  sort: SortKey;
  order: 'asc' | 'desc';
  onSort: (k: SortKey) => void;
  onToggle: (path: string) => void;
  onToggleAll: (all: boolean) => void;
  onOpen: (e: FileEntry) => void;
  onAction: (a: RowAction, e: FileEntry) => void;
}

function SortHead({ k, label, sort, order, onSort, className }: { k: SortKey; label: string; sort: SortKey; order: 'asc' | 'desc'; onSort: (k: SortKey) => void; className?: string }) {
  const active = sort === k;
  return (
    <TableHead className={className} aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="inline-flex min-h-11 min-w-11 items-center gap-1 rounded px-1 text-left font-medium lg:min-h-8 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring" onClick={() => onSort(k)}>
        {label}
        <span aria-hidden="true" className="text-xs">{active ? (order === 'asc' ? '↑' : '↓') : ''}</span>
      </button>
    </TableHead>
  );
}

export function FilesList(p: FilesListProps) {
  const wide = useMedia('(min-width: 768px)');
  const selectable = p.entries.filter((e) => !e.blocked || e.kind !== 'other');
  const allSelected = selectable.length > 0 && selectable.every((e) => p.selected.has(e.path));
  const box = (e: FileEntry) => (
    <TouchCheckbox
      checked={p.selected.has(e.path)}
      onCheckedChange={() => p.onToggle(e.path)}
      aria-label={t('files.select_one', { name: e.name })}
      disabled={e.kind === 'other'}
    />
  );

  if (p.view === 'grid') {
    return (
      <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6" aria-label={t('files.title')}>
        {p.entries.map((e) => (
          <li key={e.path} className={cn('relative flex min-w-0 flex-col rounded-lg border p-2', p.selected.has(e.path) && 'border-primary bg-accent/40')}>
            <div className="flex items-center justify-between">
              {box(e)}
              <RowMenu entry={e} onAction={p.onAction} />
            </div>
            <div className="flex flex-col items-center gap-1 px-1 pb-2 text-center text-sm">
              <EntryIcon entry={e} className="h-10 w-10 text-muted-foreground" />
              <NameButton entry={e} onOpen={p.onOpen} />
              <span className="text-xs text-muted-foreground">{e.kind === 'file' ? fmtBytes(e.size) : kindText(e)}</span>
            </div>
          </li>
        ))}
      </ul>
    );
  }

  if (!wide) {
    return (
      <ul className="divide-y rounded-lg border" aria-label={t('files.title')}>
        {p.entries.map((e) => (
          <li key={e.path} className={cn('flex items-center gap-1 px-2 py-1', p.selected.has(e.path) && 'bg-accent/40')}>
            {box(e)}
            <div className="min-w-0 flex-1">
              <NameButton entry={e} onOpen={p.onOpen} />
              <div className="pl-7 text-xs text-muted-foreground">
                {e.kind === 'file' ? `${fmtBytes(e.size)} · ` : ''}
                {modifiedText(e.modified_ms)}
              </div>
            </div>
            <RowMenu entry={e} onAction={p.onAction} />
          </li>
        ))}
      </ul>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border">
      <Table aria-label={t('files.title')}>
        <TableHeader>
          <TableRow>
            <TableHead className="w-10">
              <TouchCheckbox checked={allSelected} onCheckedChange={(v) => p.onToggleAll(v === true)} aria-label={t('files.select_all')} />
            </TableHead>
            <SortHead k="name" label={t('files.col_name')} sort={p.sort} order={p.order} onSort={p.onSort} />
            <SortHead k="size" label={t('files.col_size')} sort={p.sort} order={p.order} onSort={p.onSort} className="w-28" />
            <SortHead k="modified" label={t('files.col_modified')} sort={p.sort} order={p.order} onSort={p.onSort} className="w-40" />
            <SortHead k="kind" label={t('files.col_kind')} sort={p.sort} order={p.order} onSort={p.onSort} className="w-28" />
            <TableHead className="w-12"><span className="sr-only">{t('files.actions_title')}</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {p.entries.map((e) => (
            <TableRow key={e.path} data-state={p.selected.has(e.path) ? 'selected' : undefined}>
              <TableCell>{box(e)}</TableCell>
              <TableCell className="max-w-0 min-w-48"><NameButton entry={e} onOpen={p.onOpen} /></TableCell>
              <TableCell className="tabular-nums text-muted-foreground">{e.kind === 'file' ? fmtBytes(e.size) : ABSENT}</TableCell>
              <TableCell className="text-muted-foreground">{modifiedText(e.modified_ms)}</TableCell>
              <TableCell className="text-muted-foreground">{kindText(e)}</TableCell>
              <TableCell><RowMenu entry={e} onAction={p.onAction} /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
