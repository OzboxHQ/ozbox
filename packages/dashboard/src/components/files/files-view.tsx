import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from 'react';
import {
  ArrowUp01Icon,
  Delete02Icon,
  Download01Icon,
  FolderAddIcon,
  GridViewIcon,
  ListViewIcon,
  PencilEdit01Icon,
  Search01Icon,
  Share01Icon,
  Upload01Icon,
} from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { cn } from '@/lib/utils';
import { ApiError } from '../../api/error';
import type { FileEntry, FilePreview, FilesApi, SortKey, TrashItem } from '../../api/files';
import type { BoxRecord } from '../../api/types';
import { useApp } from '../../App';
import { EmptyState } from '../page';
import { SourceNote } from '../source-badge';
import { breadcrumbs, checkUploads, parentOf, restoredName, within } from '../../lib/files';
import { fmtBytes, fmtRelative } from '../../lib/format';
import { t, type MessageKey } from '../../lib/i18n';
import { connectInfo } from '../../lib/connect';
import { useAsync } from '../../lib/use-async';
import { FilesList, type RowAction } from './files-list';
import { EditSheet, downloadPaths, PreviewSheet } from './files-preview';
import { MoveSheet, NewFolderSheet, SearchSheet, ShareSheet } from './files-sheets';
import { fileErrorText } from './messages';
import { useUploads } from './use-uploads';

const VIEW_KEY = 'ozbox.files.view';
const SORTS: SortKey[] = ['name', 'size', 'modified', 'kind'];
const SORT_LABEL: Record<SortKey, MessageKey> = { name: 'files.sort_name', size: 'files.sort_size', modified: 'files.sort_modified', kind: 'files.sort_kind' };

function readView(): 'list' | 'grid' {
  try {
    return window.localStorage.getItem(VIEW_KEY) === 'grid' ? 'grid' : 'list';
  } catch {
    return 'list';
  }
}

type Sheet =
  | { kind: 'folder' }
  | { kind: 'move'; entries: FileEntry[] }
  | { kind: 'share'; entries: FileEntry[] }
  | { kind: 'search' }
  | { kind: 'preview'; path: string }
  | { kind: 'edit'; file: FilePreview }
  | null;

function Breadcrumbs({ root, path, onGo }: { root: string; path: string; onGo: (p: string) => void }) {
  const crumbs = breadcrumbs(root, path);
  return (
    <nav aria-label={t('files.path_bar')} className="min-w-0 flex-1">
      <ol className="flex flex-wrap items-center gap-x-1 text-sm">
        {crumbs.map((c, i) => {
          const last = i === crumbs.length - 1;
          return (
            <li key={c.path} className="flex items-center gap-1">
              {i > 0 && <span aria-hidden="true" className="text-muted-foreground">/</span>}
              {last ? (
                <span aria-current="page" className="px-1 font-medium">{c.label}</span>
              ) : (
                <button type="button" onClick={() => onGo(c.path)} className="min-h-11 min-w-11 rounded px-1 text-primary outline-none lg:min-w-0 hover:underline focus-visible:ring-2 focus-visible:ring-ring lg:min-h-8">
                  {c.label}
                </button>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function UploadsPanel({ uploads, api }: { uploads: ReturnType<typeof useUploads>; api: FilesApi }) {
  void api;
  if (uploads.items.length === 0) return null;
  const stateText = (s: string) => t(`files.upload_state_${s}` as MessageKey);
  return (
    <section aria-label={t('files.uploads')} className="space-y-2 rounded-lg border p-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">{t('files.uploads')}</h2>
        <Button type="button" variant="ghost" className="h-11 lg:h-8" onClick={uploads.clearFinished}>
          {t('files.upload_clear')}
        </Button>
      </div>
      <ul className="space-y-2">
        {uploads.items.map((u) => {
          const pct = u.file.size > 0 ? Math.min(100, Math.round((u.loaded / u.file.size) * 100)) : u.state === 'done' ? 100 : 0;
          return (
            <li key={u.id} className="space-y-1 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="min-w-0 truncate">{u.file.name}</span>
                <span className="shrink-0 text-xs text-muted-foreground">{stateText(u.state)}</span>
              </div>
              <div
                role="progressbar"
                aria-label={t('files.upload_progress', { name: u.file.name })}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={pct}
                className="h-1.5 w-full overflow-hidden rounded bg-muted"
              >
                <div className={cn('h-full', u.state === 'error' ? 'bg-destructive' : 'bg-primary')} style={{ width: `${pct}%` }} />
              </div>
              {u.state === 'error' && (
                <p role="alert" className="text-xs text-destructive">
                  {fileErrorText(new ApiError(0, u.code ?? 'error', u.message ?? ''))}
                </p>
              )}
              <div className="flex flex-wrap gap-2">
                {(u.state === 'queued' || u.state === 'uploading') && (
                  <Button type="button" variant="outline" className="h-11 lg:h-8" aria-label={t('files.upload_cancel', { name: u.file.name })} onClick={() => uploads.cancel(u.id)}>
                    {t('common.cancel')}
                  </Button>
                )}
                {u.state === 'error' && u.code === 'exists' && (
                  <Button type="button" variant="outline" className="h-11 lg:h-8" onClick={() => uploads.retry(u.id, true)}>
                    {t('files.upload_replace')}
                  </Button>
                )}
                {(u.state === 'error' && u.code !== 'exists') || u.state === 'cancelled' ? (
                  <Button type="button" variant="outline" className="h-11 lg:h-8" onClick={() => uploads.retry(u.id, false)}>
                    {t('files.upload_retry')}
                  </Button>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function TrashView({ api, box, onBack, onRestored }: { api: FilesApi; box: string; onBack: () => void; onRestored: () => void }) {
  const trash = useAsync((s) => api.trash(box, s), [api, box]);
  const [conflict, setConflict] = useState<TrashItem | null>(null);
  const [emptying, setEmptying] = useState(false);
  async function restore(item: TrashItem, to?: string) {
    try {
      await api.restore(box, item.id, to);
      toast.success(t('files.trash_restored'));
      trash.reload();
      onRestored();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'exists' && !to) setConflict(item);
      else toast.error(fileErrorText(e));
    }
  }
  const items = trash.data?.items ?? [];
  return (
    <section aria-label={t('files.trash_title')} className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold">{t('files.trash_title')}</h2>
          <p className="text-sm text-muted-foreground">{t('files.trash_intro', { days: trash.data?.retention_days ?? 30 })}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" className="h-11 lg:h-9" onClick={onBack}>
            {t('files.back_to_files')}
          </Button>
          <Button type="button" variant="outline" className="h-11 text-destructive lg:h-9" disabled={items.length === 0} onClick={() => setEmptying(true)}>
            {t('files.trash_empty_action')}
          </Button>
        </div>
      </div>
      {trash.loading && !trash.data ? (
        <Skeleton className="h-24 w-full" />
      ) : trash.error && !trash.data ? (
        <p role="alert" className="text-sm text-destructive">{fileErrorText(trash.error)}</p>
      ) : items.length === 0 ? (
        <EmptyState title={t('files.trash_empty')} />
      ) : (
        <ul className="divide-y rounded-lg border">
          {items.map((i) => (
            <li key={i.id} className="flex items-center gap-2 px-3 py-1">
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium" title={i.original}>{i.name}</div>
                <div className="truncate text-xs text-muted-foreground">
                  {i.original} · {fmtBytes(i.size)} · {t('files.trash_expires', { when: fmtRelative(new Date(i.expires_ms).toISOString()) })}
                </div>
              </div>
              <Button type="button" variant="outline" className="h-11 shrink-0 lg:h-9" aria-label={t('files.trash_restore_item', { name: i.name })} onClick={() => void restore(i)}>
                {t('files.trash_restore')}
              </Button>
            </li>
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={emptying}
        onOpenChange={setEmptying}
        title={t('files.trash_empty_title')}
        description={t('files.trash_empty_body')}
        confirmLabel={t('files.trash_empty_action')}
        destructive
        onConfirm={async () => {
          try {
            await api.emptyTrash(box);
            trash.reload();
          } catch (e) {
            toast.error(fileErrorText(e));
            throw e;
          }
        }}
      />
      <ConfirmDialog
        open={conflict !== null}
        onOpenChange={(o) => !o && setConflict(null)}
        title={t('files.restore_exists_title')}
        description={conflict ? t('files.restore_exists_body', { name: restoredName(conflict.original, 'restored') }) : ''}
        confirmLabel={t('files.restore_as')}
        onConfirm={async () => {
          if (conflict) await restore(conflict, restoredName(conflict.original, 'restored'));
        }}
      />
    </section>
  );
}

function Browser({ box, api, root, maxUpload, trashDays, ideUrl }: { box: string; api: FilesApi; root: string; maxUpload: number; trashDays: number; ideUrl: string | null }) {
  const initial = (() => {
    const p = new URLSearchParams(window.location.search).get('path');
    return p && within(root, p) ? p : root;
  })();
  const [path, setPath] = useState(initial);
  const [view, setView] = useState<'list' | 'grid'>(readView);
  const [sort, setSort] = useState<SortKey>('name');
  const [order, setOrder] = useState<'asc' | 'desc'>('asc');
  const [hidden, setHidden] = useState(false);
  const [mode, setMode] = useState<'files' | 'trash'>('files');
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [sheet, setSheet] = useState<Sheet>(null);
  const [pendingDelete, setPendingDelete] = useState<FileEntry[] | null>(null);
  const [dragging, setDragging] = useState(false);
  const picker = useRef<HTMLInputElement>(null);

  const list = useAsync((s) => api.list(box, path, { sort, order, hidden, limit: 1000 }, s), [api, box, path, sort, order, hidden], 15000);
  const uploads = useUploads(api, box, () => list.reload());
  const entries = useMemo(() => list.data?.entries ?? [], [list.data]);

  const go = useCallback((p: string) => {
    setPath(p);
    setSelected(new Set());
    setMode('files');
  }, []);
  useEffect(() => {
    const u = new URL(window.location.href);
    if (path === root) u.searchParams.delete('path');
    else u.searchParams.set('path', path);
    window.history.replaceState(null, '', u);
  }, [path, root]);

  const chosen = useMemo(() => entries.filter((e) => selected.has(e.path)), [entries, selected]);

  function open(e: FileEntry) {
    if (e.blocked) return;
    if (e.kind === 'dir') go(e.path);
    else setSheet({ kind: 'preview', path: e.path });
  }
  async function act(a: RowAction, e: FileEntry) {
    if (a === 'open') open(e);
    if (a === 'rename') setSheet({ kind: 'move', entries: [e] });
    if (a === 'share') setSheet({ kind: 'share', entries: [e] });
    if (a === 'delete') setPendingDelete([e]);
    if (a === 'download') await download([e.path]);
  }
  async function download(paths: string[]) {
    try {
      await downloadPaths(api, box, paths);
      toast.success(t('files.download_started'));
    } catch (e) {
      toast.error(fileErrorText(e));
    }
  }
  function addFiles(files: File[]) {
    const { ok, tooLarge } = checkUploads(files, maxUpload);
    for (const f of tooLarge) toast.error(t('files.upload_too_large', { name: f.name, max: fmtBytes(maxUpload) }));
    if (ok.length > 0) uploads.add(path, ok);
  }
  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const files: File[] = [];
    let skippedFolder = false;
    for (const item of Array.from(e.dataTransfer.items)) {
      if (item.kind !== 'file') continue;
      if (item.webkitGetAsEntry?.()?.isDirectory) {
        skippedFolder = true;
        continue;
      }
      const f = item.getAsFile();
      if (f) files.push(f);
    }
    if (skippedFolder) toast.error(t('files.upload_no_folders'));
    addFiles(files);
  }

  if (mode === 'trash') return <TrashView api={api} box={box} onBack={() => setMode('files')} onRestored={list.reload} />;

  const hasSelection = chosen.length > 0;
  const selectable = entries.filter((e) => !(e.blocked && e.kind === 'other'));
  const canBulk = chosen.every((e) => !e.blocked);
  const btn = 'h-11 lg:h-9';
  return (
    <div
      className={cn('space-y-3 rounded-lg', dragging && 'outline-dashed outline-2 outline-offset-4 outline-primary')}
      onDragEnter={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragOver={(e) => e.preventDefault()}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="icon" className="h-11 w-11 lg:h-9 lg:w-9" aria-label={t('files.up')} disabled={path === root} onClick={() => go(parentOf(path))}>
          <HugeiconsIcon icon={ArrowUp01Icon} className="h-4 w-4" />
        </Button>
        <Breadcrumbs root={root} path={path} onGo={go} />
      </div>

      <div role="toolbar" aria-label={t('files.toolbar')} className="flex flex-wrap items-center gap-2">
        {hasSelection ? (
          <>
            <span className="mr-1 text-sm" aria-live="polite">{t('files.selected', { count: chosen.length })}</span>
            <Button type="button" variant="outline" className={btn} disabled={!canBulk} onClick={() => void download(chosen.map((e) => e.path))}>
              <HugeiconsIcon icon={Download01Icon} className="h-4 w-4" aria-hidden="true" /> {chosen.length > 1 || chosen[0]?.kind === 'dir' ? t('files.download_zip') : t('files.download')}
            </Button>
            <Button type="button" variant="outline" className={btn} disabled={!canBulk} onClick={() => setSheet({ kind: 'move', entries: chosen })}>
              <HugeiconsIcon icon={PencilEdit01Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.rename')}
            </Button>
            <Button type="button" variant="outline" className={btn} disabled={!canBulk} onClick={() => setSheet({ kind: 'share', entries: chosen })}>
              <HugeiconsIcon icon={Share01Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.share')}
            </Button>
            <Button type="button" variant="outline" className={cn(btn, 'text-destructive')} onClick={() => setPendingDelete(chosen)}>
              <HugeiconsIcon icon={Delete02Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.delete')}
            </Button>
            <Button type="button" variant="ghost" className={btn} onClick={() => setSelected(new Set())}>
              {t('files.clear_selection')}
            </Button>
          </>
        ) : (
          <>
            <input
              ref={picker}
              type="file"
              multiple
              className="hidden"
              aria-hidden="true"
              tabIndex={-1}
              onChange={(e) => {
                addFiles(Array.from(e.target.files ?? []));
                e.target.value = '';
              }}
            />
            <Button type="button" className={btn} onClick={() => picker.current?.click()}>
              <HugeiconsIcon icon={Upload01Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.upload')}
            </Button>
            <Button type="button" variant="outline" className={btn} onClick={() => setSheet({ kind: 'folder' })}>
              <HugeiconsIcon icon={FolderAddIcon} className="h-4 w-4" aria-hidden="true" /> {t('files.new_folder')}
            </Button>
            <Button type="button" variant="outline" className={btn} onClick={() => setSheet({ kind: 'search' })}>
              <HugeiconsIcon icon={Search01Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.search')}
            </Button>
            <Button type="button" variant="outline" className={btn} onClick={() => setMode('trash')}>
              <HugeiconsIcon icon={Delete02Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.trash')}
            </Button>
          </>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <div className="flex items-center">
            <TouchCheckbox id="files-hidden" checked={hidden} onCheckedChange={(v) => setHidden(v === true)} />
            <Label htmlFor="files-hidden" className="min-h-11 content-center pr-2 text-sm lg:min-h-0">{t('files.show_hidden')}</Label>
          </div>
          <div className="flex items-center gap-1">
            <Label htmlFor="files-sort" className="sr-only">{t('files.sort_label')}</Label>
            <Select value={sort} onValueChange={(v) => setSort(v as SortKey)}>
              <SelectTrigger id="files-sort" className="w-36 max-lg:h-11" aria-label={t('files.sort_label')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SORTS.map((s) => (
                  <SelectItem key={s} value={s}>{t(SORT_LABEL[s])}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button type="button" variant="outline" size="icon" className="h-11 w-11 lg:h-10 lg:w-10" aria-label={order === 'asc' ? t('files.order_asc') : t('files.order_desc')} onClick={() => setOrder(order === 'asc' ? 'desc' : 'asc')}>
              <span aria-hidden="true">{order === 'asc' ? '↑' : '↓'}</span>
            </Button>
          </div>
          <div role="group" aria-label={t('files.view_label')} className="flex">
            {(['list', 'grid'] as const).map((v) => (
              <Button
                key={v}
                type="button"
                variant={view === v ? 'default' : 'outline'}
                size="icon"
                aria-pressed={view === v}
                aria-label={v === 'list' ? t('files.view_list') : t('files.view_grid')}
                className="h-11 w-11 lg:h-10 lg:w-10"
                onClick={() => {
                  setView(v);
                  try {
                    window.localStorage.setItem(VIEW_KEY, v);
                  } catch {
                    // a remembered view is a convenience
                  }
                }}
              >
                <HugeiconsIcon icon={v === 'list' ? ListViewIcon : GridViewIcon} className="h-4 w-4" />
              </Button>
            ))}
          </div>
        </div>
      </div>

      {dragging && <p className="rounded border border-dashed p-3 text-center text-sm" role="status">{t('files.upload_drop', { folder: path })}</p>}
      <UploadsPanel uploads={uploads} api={api} />

      {list.error && list.data ? (
        <p role="alert" className="text-sm text-destructive" data-testid="files-refresh-error">
          {t('files.refresh_error', { reason: fileErrorText(list.error) })}
        </p>
      ) : null}

      {list.loading && !list.data ? (
        <div role="status" aria-label={t('files.loading')} className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : list.error && !list.data ? (
        <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm">
          {t('files.load_failed')} {fileErrorText(list.error)}
        </div>
      ) : entries.length === 0 ? (
        <EmptyState title={t('files.empty')}>{t('files.empty_hint')}</EmptyState>
      ) : (
        <FilesList
          entries={entries}
          view={view}
          selected={selected}
          sort={sort}
          order={order}
          onSort={(k) => {
            if (k === sort) setOrder(order === 'asc' ? 'desc' : 'asc');
            else {
              setSort(k);
              setOrder('asc');
            }
          }}
          onToggle={(p) =>
            setSelected((s) => {
              const n = new Set(s);
              if (n.has(p)) n.delete(p);
              else n.add(p);
              return n;
            })
          }
          onToggleAll={(all) => setSelected(all ? new Set(selectable.map((e) => e.path)) : new Set())}
          onOpen={open}
          onAction={(a, e) => void act(a, e)}
        />
      )}
      {list.data && list.data.total > entries.length && <p className="text-xs text-muted-foreground">{t('files.too_many', { count: entries.length })}</p>}

      {sheet?.kind === 'folder' && <NewFolderSheet api={api} box={box} dir={path} onClose={() => setSheet(null)} onDone={list.reload} />}
      {sheet?.kind === 'move' && (
        <MoveSheet
          api={api}
          box={box}
          root={root}
          dir={path}
          entries={sheet.entries}
          onClose={() => setSheet(null)}
          onDone={() => {
            setSelected(new Set());
            list.reload();
          }}
        />
      )}
      {sheet?.kind === 'share' && <ShareSheet api={api} box={box} entries={sheet.entries} onClose={() => setSheet(null)} />}
      {sheet?.kind === 'search' && (
        <SearchSheet
          api={api}
          box={box}
          dir={path}
          onClose={() => setSheet(null)}
          onPick={(h) => {
            if (h.kind === 'dir') {
              go(h.path);
              setSheet(null);
            } else {
              go(parentOf(h.path));
              setSheet({ kind: 'preview', path: h.path });
            }
          }}
        />
      )}
      {sheet?.kind === 'preview' && <PreviewSheet api={api} box={box} path={sheet.path} ideUrl={ideUrl} onClose={() => setSheet(null)} onEdit={(file) => setSheet({ kind: 'edit', file })} />}
      {sheet?.kind === 'edit' && <EditSheet api={api} box={box} file={sheet.file} onClose={() => setSheet(null)} onSaved={list.reload} />}

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => !o && setPendingDelete(null)}
        title={t('files.delete_title')}
        description={t('files.delete_body', { count: pendingDelete && pendingDelete.length === 1 ? (pendingDelete[0]?.name ?? '') : t('files.item_count', { count: pendingDelete?.length ?? 0 }), days: trashDays })}
        confirmLabel={t('files.delete_confirm')}
        destructive
        onConfirm={async () => {
          if (!pendingDelete) return;
          try {
            const r = await api.remove(box, pendingDelete.map((e) => e.path));
            if (r.failed.length > 0) toast.error(t('files.delete_partial'));
            else toast.success(t('files.deleted'));
            setSelected(new Set());
            list.reload();
          } catch (e) {
            toast.error(fileErrorText(e));
            throw e;
          }
        }}
      />
    </div>
  );
}

/** The file browser for one running box. Rendered as a tab on the box page and as its own page. */
export function FilesView({ box }: { box: BoxRecord }) {
  const { client, info } = useApp();
  const api = client.files;
  const name = box.spec.name;
  const roots = useAsync((s) => api.roots(name, s), [api, name]);
  if (box.state !== 'running') return <EmptyState title={t('files.title')}>{t('files.not_running')}</EmptyState>;
  if (roots.error && !roots.data) {
    return (
      <div role="alert" className="rounded-lg border border-destructive/40 p-4 text-sm">
        {fileErrorText(roots.error)}
      </div>
    );
  }
  const first = roots.data?.roots[0];
  if (!roots.data || !first) return <Skeleton className="h-40 w-full" />;
  return (
    <div className="space-y-3">
      <SourceNote source={roots.data.source} what="files" />
      <p className="text-sm text-muted-foreground">{t('files.intro', { root: first.path })}</p>
      <Browser box={name} api={api} root={first.path} maxUpload={roots.data.limits.max_upload} trashDays={roots.data.limits.trash_days} ideUrl={connectInfo(box, info?.domain ?? null).ideUrl} />
    </div>
  );
}
