import { useState, type FormEvent } from 'react';
import { ArrowUp01Icon, Folder01Icon } from '@hugeicons/core-free-icons';
import { HugeiconsIcon } from '@hugeicons/react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import type { CreatedToken, FileEntry, FilesApi, SearchResponse } from '../../api/files';
import { baseName, breadcrumbs, joinPath, SHARE_TTLS, validName } from '../../lib/files';
import { fmtRelative } from '../../lib/format';
import { t, type MessageKey } from '../../lib/i18n';
import { useAsync } from '../../lib/use-async';
import { fileErrorText } from './messages';

function Err({ msg }: { msg: string | null }) {
  return msg ? (
    <p role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

// ---- new folder -----------------------------------------------------------------------------------------------------

export function NewFolderSheet({ api, box, dir, onClose, onDone }: { api: FilesApi; box: string; dir: string; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!validName(name.trim())) {
      setError(t('files.err_bad_name'));
      return;
    }
    setBusy(true);
    try {
      await api.mkdir(box, joinPath(dir, name.trim()));
      toast.success(t('files.created_folder'));
      onDone();
      onClose();
    } catch (err) {
      setError(fileErrorText(err));
      setBusy(false);
    }
  }
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact">
        <form onSubmit={submit} className="flex min-h-0 flex-1 flex-col">
          <PanelSheetHeader>
            <PanelSheetTitle>{t('files.new_folder')}</PanelSheetTitle>
            <PanelSheetDescription>{t('files.new_folder_title', { folder: baseName(dir) || dir })}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-2">
            <Label htmlFor="files-new-folder">{t('files.new_folder_name')}</Label>
            <Input id="files-new-folder" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" autoFocus className="h-11 lg:h-9" />
            <Err msg={error} />
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy || name.trim() === ''}>
              {t('files.create')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

// ---- rename / move ----------------------------------------------------------------------------------------------------

function FolderPicker({ api, box, root, value, onChange }: { api: FilesApi; box: string; root: string; value: string; onChange: (p: string) => void }) {
  const list = useAsync((s) => api.list(box, value, { limit: 1000 }, s), [api, box, value]);
  const dirs = (list.data?.entries ?? []).filter((e) => e.kind === 'dir' && !e.blocked);
  const crumbs = breadcrumbs(root, value);
  return (
    <div className="space-y-2" role="group" aria-label={t('files.folder_picker')}>
      <p className="break-all text-sm text-muted-foreground">{t('files.move_here', { path: value })}</p>
      <div className="flex items-center gap-2">
        <Button type="button" variant="outline" className="h-11 lg:h-9" disabled={crumbs.length < 2} onClick={() => onChange(crumbs[crumbs.length - 2]?.path ?? root)}>
          <HugeiconsIcon icon={ArrowUp01Icon} className="h-4 w-4" aria-hidden="true" /> {t('files.folder_up')}
        </Button>
      </div>
      {list.loading && !list.data ? (
        <Skeleton className="h-24 w-full" />
      ) : list.error ? (
        <Err msg={fileErrorText(list.error)} />
      ) : dirs.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('files.no_subfolders')}</p>
      ) : (
        <ul className="max-h-64 divide-y overflow-y-auto rounded-md border">
          {dirs.map((d) => (
            <li key={d.path}>
              <button type="button" className="flex min-h-11 w-full items-center gap-2 px-3 text-left text-sm outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring lg:min-h-9" onClick={() => onChange(d.path)}>
                <HugeiconsIcon icon={Folder01Icon} className="h-4 w-4 text-primary" aria-hidden="true" />
                <span className="truncate">{d.name}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function MoveSheet({ api, box, root, dir, entries, onClose, onDone }: { api: FilesApi; box: string; root: string; dir: string; entries: FileEntry[]; onClose: () => void; onDone: () => void }) {
  const single = entries.length === 1 ? entries[0] : undefined;
  const [name, setName] = useState(single?.name ?? '');
  const [dest, setDest] = useState(dir);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (single && !validName(name.trim())) {
      setError(t('files.err_bad_name'));
      return;
    }
    setBusy(true);
    try {
      for (const entry of entries) await api.rename(box, entry.path, joinPath(dest, single ? name.trim() : entry.name));
      toast.success(t('files.moved'));
      onDone();
      onClose();
    } catch (err) {
      setError(fileErrorText(err));
      setBusy(false);
    }
  }
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent>
        <form onSubmit={submit} className="flex min-h-0 flex-1 flex-col">
          <PanelSheetHeader>
            <PanelSheetTitle>{single ? t('files.rename_title', { name: single.name }) : t('files.move_to')}</PanelSheetTitle>
            <PanelSheetDescription>{single ? t('files.move_to') : t('files.selected', { count: entries.length })}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            {single && (
              <div className="space-y-2">
                <Label htmlFor="files-rename">{t('files.rename_name')}</Label>
                <Input id="files-rename" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" className="h-11 lg:h-9" />
              </div>
            )}
            <FolderPicker api={api} box={box} root={root} value={dest} onChange={setDest} />
            <Err msg={error} />
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy || (single !== undefined && name.trim() === '')}>
              {t('files.move')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

// ---- search -------------------------------------------------------------------------------------------------------

export function SearchSheet({ api, box, dir, onClose, onPick }: { api: FilesApi; box: string; dir: string; onClose: () => void; onPick: (hit: { path: string; kind: 'file' | 'dir' | 'other' }) => void }) {
  const [q, setQ] = useState('');
  const [content, setContent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<SearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (q.trim() === '') return;
    setBusy(true);
    setError(null);
    try {
      setRes(await api.search(box, dir, q.trim(), content));
    } catch (err) {
      setError(fileErrorText(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent>
        <PanelSheetHeader>
          <PanelSheetTitle>{t('files.search')}</PanelSheetTitle>
          <PanelSheetDescription>{t('files.search_title', { folder: baseName(dir) || dir })}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          <form onSubmit={submit} className="space-y-3" role="search">
            <Label htmlFor="files-search">{t('files.search_label')}</Label>
            <div className="flex gap-2">
              <Input id="files-search" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('files.search_placeholder')} autoComplete="off" autoFocus className="h-11 lg:h-9" />
              <Button type="submit" className="h-11 lg:h-9" disabled={busy || q.trim() === ''}>
                {t('files.search_go')}
              </Button>
            </div>
            <div className="flex items-center gap-1">
              <TouchCheckbox id="files-search-content" checked={content} onCheckedChange={(v) => setContent(v === true)} />
              <Label htmlFor="files-search-content" className="min-h-11 flex-1 content-center lg:min-h-0">
                {t('files.search_content')}
              </Label>
            </div>
          </form>
          <Err msg={error} />
          {res && (
            <section aria-label={t('files.search_results')} className="space-y-2">
              {res.results.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('files.search_none')}</p>
              ) : (
                <ul className="divide-y rounded-md border">
                  {res.results.map((h) => (
                    <li key={h.path + String(h.line ?? '')}>
                      <button
                        type="button"
                        className="flex min-h-11 w-full flex-col items-start justify-center gap-0.5 px-3 py-2 text-left text-sm outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
                        onClick={() => onPick(h)}
                      >
                        <span className="break-all font-medium">{h.name}</span>
                        <span className="break-all text-xs text-muted-foreground">{h.path}</span>
                        {h.snippet !== undefined && (
                          <span className="break-all font-mono text-xs">
                            {t('files.search_line', { line: h.line ?? 0 })}: {h.snippet}
                          </span>
                        )}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {res.truncated && <p className="text-xs text-muted-foreground">{t('files.search_truncated')}</p>}
              {res.timed_out && <p className="text-xs text-muted-foreground">{t('files.search_timed_out')}</p>}
            </section>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t('files.close')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

// ---- share -------------------------------------------------------------------------------------------------------

const TTL_LABEL: Record<(typeof SHARE_TTLS)[number]['id'], MessageKey> = { '15m': 'files.share_ttl_15m', '1h': 'files.share_ttl_1h', '24h': 'files.share_ttl_24h' };

export function ShareSheet({ api, box, entries, onClose }: { api: FilesApi; box: string; entries: FileEntry[]; onClose: () => void }) {
  const [ttl, setTtl] = useState<(typeof SHARE_TTLS)[number]['id']>('1h');
  const [created, setCreated] = useState<{ token: CreatedToken; url: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tokens = useAsync((s) => api.tokens(box, s), [api, box, created]);
  async function create() {
    setBusy(true);
    setError(null);
    try {
      const seconds = SHARE_TTLS.find((x) => x.id === ttl)?.seconds ?? 3600;
      const token = await api.createToken(box, entries.map((e) => e.path), seconds);
      setCreated({ token, url: new URL(api.downloadUrl(box, token.token), window.location.origin).toString() });
    } catch (err) {
      setError(fileErrorText(err));
    } finally {
      setBusy(false);
    }
  }
  async function copy(url: string) {
    try {
      await navigator.clipboard.writeText(url);
      toast.success(t('files.share_copied'));
    } catch {
      toast.error(t('files.share_copy_failed'));
    }
  }
  async function revoke(id: string) {
    try {
      await api.revokeToken(box, id);
      toast.success(t('files.share_revoked'));
      if (created?.token.id === id) setCreated(null);
      else tokens.reload();
    } catch (err) {
      toast.error(fileErrorText(err));
    }
  }
  const label = entries.length === 1 ? (entries[0]?.name ?? '') : t('files.item_count', { count: entries.length });
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent>
        <PanelSheetHeader>
          <PanelSheetTitle>{t('files.share_title')}</PanelSheetTitle>
          <PanelSheetDescription>{label}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-5">
          <p className="text-sm text-muted-foreground">{t('files.share_intro')}</p>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">{t('files.share_for')}</legend>
            <div className="flex flex-wrap gap-2">
              {SHARE_TTLS.map((x) => (
                <Button key={x.id} type="button" variant={ttl === x.id ? 'default' : 'outline'} aria-pressed={ttl === x.id} className="h-11 lg:h-9" onClick={() => setTtl(x.id)}>
                  {t(TTL_LABEL[x.id])}
                </Button>
              ))}
            </div>
          </fieldset>
          <Err msg={error} />
          {created ? (
            <div className="space-y-2">
              <Label htmlFor="files-share-link">{t('files.share_link_label')}</Label>
              <div className="flex gap-2">
                <Input id="files-share-link" readOnly value={created.url} onFocus={(e) => e.currentTarget.select()} className="h-11 font-mono text-xs lg:h-9" />
                <Button type="button" className="h-11 lg:h-9" onClick={() => void copy(created.url)}>
                  {t('files.share_copy')}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                {t('files.share_expires', { when: new Date(created.token.expires_ms).toLocaleString() })} {t('files.share_local')}
              </p>
            </div>
          ) : (
            <Button type="button" className="h-11 w-full sm:w-auto lg:h-9" disabled={busy} onClick={() => void create()}>
              {t('files.share_create')}
            </Button>
          )}
          <section aria-label={t('files.share_active')} className="space-y-2">
            <h3 className="text-sm font-semibold">{t('files.share_active')}</h3>
            {tokens.data && tokens.data.tokens.length > 0 ? (
              <ul className="divide-y rounded-md border text-sm">
                {tokens.data.tokens.map((k) => (
                  <li key={k.id} className="flex items-center justify-between gap-2 px-3 py-1">
                    <div className="min-w-0">
                      <div className="truncate">{k.label}</div>
                      <div className="text-xs text-muted-foreground">{t('files.share_expires', { when: fmtRelative(new Date(k.expires_ms).toISOString()) })}</div>
                    </div>
                    <Button type="button" variant="outline" className="h-11 shrink-0 lg:h-8" aria-label={t('files.share_revoke_item', { label: k.label })} onClick={() => void revoke(k.id)}>
                      {t('files.share_revoke')}
                    </Button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t('files.share_none')}</p>
            )}
          </section>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t('files.close')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
