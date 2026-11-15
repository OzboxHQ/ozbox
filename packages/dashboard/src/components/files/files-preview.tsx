import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { ApiError } from '../../api/error';
import type { FilePreview, FilesApi } from '../../api/files';
import { collapseDiff, diffLines, diffStats, EDIT_MAX_BYTES } from '../../lib/files';
import { fmtBytes } from '../../lib/format';
import { t } from '../../lib/i18n';
import { useAsync } from '../../lib/use-async';
import { fileErrorText } from './messages';

/** Start a download of one or more paths through a fresh link, without leaving the page. */
export async function downloadPaths(api: FilesApi, box: string, paths: string[]): Promise<void> {
  const token = await api.createToken(box, paths, 15 * 60);
  const a = document.createElement('a');
  a.href = api.downloadUrl(box, token.token);
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function InlineFrame({ api, box, path, kind, name }: { api: FilesApi; box: string; path: string; kind: 'image' | 'pdf'; name: string }) {
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    api
      .createToken(box, [path], 10 * 60, true)
      .then((tok) => live && setUrl(api.downloadUrl(box, tok.token)))
      .catch((e: unknown) => live && setError(fileErrorText(e)));
    return () => {
      live = false;
    };
  }, [api, box, path]);
  if (error) return <p role="alert" className="text-sm text-destructive">{error}</p>;
  if (!url) return <Skeleton className="h-64 w-full" aria-label={t('files.preview_loading')} />;
  return kind === 'image' ? (
    <img src={url} alt={t('files.preview_image', { name })} className="mx-auto max-h-[60vh] max-w-full rounded border object-contain" />
  ) : (
    <iframe src={url} title={t('files.preview_pdf', { name })} className="h-[60vh] w-full rounded border" />
  );
}

export function PreviewSheet({ api, box, path, ideUrl, onClose, onEdit }: { api: FilesApi; box: string; path: string; ideUrl: string | null; onClose: () => void; onEdit: (p: FilePreview) => void }) {
  const pv = useAsync((s) => api.preview(box, path, s), [api, box, path]);
  const p = pv.data;
  const [busy, setBusy] = useState(false);
  async function download() {
    setBusy(true);
    try {
      await downloadPaths(api, box, [path]);
      toast.success(t('files.download_started'));
    } catch (e) {
      toast.error(fileErrorText(e));
    } finally {
      setBusy(false);
    }
  }
  const canEdit = p !== null && p.kind === 'text' && p.editable && p.truncated !== true && p.size <= EDIT_MAX_BYTES;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent>
        <PanelSheetHeader>
          <PanelSheetTitle className="break-all">{p?.name ?? path.slice(path.lastIndexOf('/') + 1)}</PanelSheetTitle>
          <PanelSheetDescription>{p ? fmtBytes(p.size) : t('files.preview_loading')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {pv.error && !p ? (
            <p role="alert" className="text-sm text-destructive">
              {fileErrorText(pv.error)}
            </p>
          ) : !p ? (
            <Skeleton className="h-48 w-full" aria-label={t('files.preview_loading')} />
          ) : p.kind === 'image' || p.kind === 'pdf' ? (
            <InlineFrame api={api} box={box} path={path} kind={p.kind} name={p.name} />
          ) : p.kind === 'text' ? (
            <>
              <pre tabIndex={0} aria-label={p.name} className="max-h-[60vh] overflow-auto rounded border bg-muted/30 p-3 font-mono text-xs leading-5">
                {p.text}
              </pre>
              {p.truncated === true && <p className="text-xs text-muted-foreground">{t('files.preview_truncated')}</p>}
              {!canEdit && <p className="text-xs text-muted-foreground">{t('files.preview_large')}</p>}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">{t('files.preview_binary')}</p>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            {t('files.close')}
          </Button>
          {p && !canEdit && (
            ideUrl ? (
              <Button asChild variant="outline">
                <a href={ideUrl} target="_blank" rel="noopener noreferrer">
                  {t('files.open_ide')}
                </a>
              </Button>
            ) : (
              <Button type="button" variant="outline" disabled title={t('files.ide_unavailable')}>
                {t('files.open_ide')}
              </Button>
            )
          )}
          {p && (
            <Button type="button" variant="outline" disabled={busy} onClick={() => void download()}>
              {t('files.download')}
            </Button>
          )}
          {canEdit && p && (
            <Button type="button" onClick={() => onEdit(p)}>
              {t('files.edit')}
            </Button>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

// ---- the quick editor, with a review of the changes before anything is saved ----------------------------------------------

function DiffView({ before, after }: { before: string; after: string }) {
  const rows = useMemo(() => collapseDiff(diffLines(before, after), 3), [before, after]);
  return (
    <div tabIndex={0} aria-label={t('files.edit_review')} className="max-h-[55vh] overflow-auto rounded border font-mono text-xs leading-5">
      {rows.map((r, i) =>
        r.kind === 'gap' ? (
          <div key={`g${i}`} className="bg-muted/40 px-3 py-0.5 text-muted-foreground">
            {t('files.diff_gap', { count: r.hidden })}
          </div>
        ) : (
          <div
            key={`${r.oldNo ?? 'n'}-${r.newNo ?? 'n'}-${i}`}
            className={cn('flex gap-2 whitespace-pre px-3', r.kind === 'add' && 'bg-emerald-500/15', r.kind === 'del' && 'bg-red-500/15')}
          >
            <span aria-hidden="true" className="w-4 shrink-0 select-none">{r.kind === 'add' ? '+' : r.kind === 'del' ? '−' : ' '}</span>
            {r.kind !== 'same' && <span className="sr-only">{r.kind === 'add' ? t('files.diff_added') : t('files.diff_removed')}</span>}
            <span>{r.text === '' ? ' ' : r.text}</span>
          </div>
        ),
      )}
    </div>
  );
}

export function EditSheet({ api, box, file, onClose, onSaved }: { api: FilesApi; box: string; file: FilePreview; onClose: () => void; onSaved: () => void }) {
  const [original, setOriginal] = useState({ text: file.text ?? '', hash: file.hash ?? '' });
  const [text, setText] = useState(original.text);
  const [step, setStep] = useState<'edit' | 'review'>('edit');
  const [saving, setSaving] = useState(false);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const dirty = text !== original.text;
  const stats = useMemo(() => diffStats(diffLines(original.text, text)), [original.text, text]);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await api.write(box, file.path, text, original.hash);
      toast.success(t('files.edit_saved'));
      onSaved();
      onClose();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'stale') setStale(true);
      else setError(fileErrorText(e));
      setSaving(false);
    }
  }
  async function reload() {
    try {
      const latest = await api.preview(box, file.path);
      setOriginal({ text: latest.text ?? '', hash: latest.hash ?? '' });
      setText(latest.text ?? '');
      setStale(false);
      setStep('edit');
      setSaving(false);
    } catch (e) {
      setError(fileErrorText(e));
    }
  }
  const tryClose = () => (dirty ? setConfirmDiscard(true) : onClose());
  return (
    <>
      <PanelSheet open onOpenChange={(o) => !o && tryClose()}>
        <PanelSheetContent>
          <PanelSheetHeader>
            <PanelSheetTitle className="break-all">{step === 'edit' ? t('files.edit_title', { name: file.name }) : t('files.edit_diff_title', { name: file.name })}</PanelSheetTitle>
            <PanelSheetDescription>{step === 'review' ? t('files.edit_diff_summary', { added: stats.added, removed: stats.removed }) : fmtBytes(file.size)}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-3">
            {stale && (
              <Alert variant="destructive" role="alert">
                <AlertTitle>{t('files.stale_title')}</AlertTitle>
                <AlertDescription className="space-y-2">
                  <p>{t('files.stale_body')}</p>
                  <Button type="button" variant="outline" className="h-11 lg:h-9" onClick={() => void reload()}>
                    {t('files.stale_reload')}
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            {step === 'edit' ? (
              <div className="space-y-2">
                <Label htmlFor="files-editor" className="sr-only">
                  {t('files.edit_label')}
                </Label>
                <textarea
                  id="files-editor"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  spellCheck={false}
                  className="h-[55vh] w-full resize-none rounded-md border bg-background p-3 font-mono text-xs leading-5 outline-none focus-visible:ring-2 focus-visible:ring-ring"
                />
              </div>
            ) : (
              <DiffView before={original.text} after={text} />
            )}
          </PanelSheetBody>
          <PanelSheetFooter>
            {step === 'edit' ? (
              <>
                <Button type="button" variant="outline" onClick={tryClose}>
                  {t('common.cancel')}
                </Button>
                <Button type="button" disabled={!dirty || stale} onClick={() => setStep('review')}>
                  {dirty ? t('files.edit_review') : t('files.edit_no_changes')}
                </Button>
              </>
            ) : (
              <>
                <Button type="button" variant="outline" disabled={saving} onClick={() => setStep('edit')}>
                  {t('files.edit_back')}
                </Button>
                <Button type="button" disabled={saving || stale} onClick={() => void save()}>
                  {t('files.edit_save')}
                </Button>
              </>
            )}
          </PanelSheetFooter>
        </PanelSheetContent>
      </PanelSheet>
      <ConfirmDialog
        open={confirmDiscard}
        onOpenChange={setConfirmDiscard}
        title={t('files.edit_discard_title')}
        description={t('files.edit_discard_body')}
        confirmLabel={t('files.edit_discard')}
        cancelLabel={t('files.edit_back')}
        destructive
        onConfirm={onClose}
      />
    </>
  );
}
