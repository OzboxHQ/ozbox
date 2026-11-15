import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { TAP_ACTION, TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../App';
import { ApiError } from '../api/client';
import type { MemNote, NoteState } from '../api/memory';
import { EmptyState, PageHeader, AppPage } from '../components/page';
import { CannotNote } from '../components/role-scope';
import { StoreNote } from '../components/store-note';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { mayWrite, PAGE_CANNOT, PAGE_CAPABILITY } from '../lib/role-gates';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const iso = (ms: number) => new Date(ms).toISOString();
const message = (e: unknown) => (e instanceof ApiError ? e.message : t('mem.failed'));

/** Memory: the notes agents may read, and the proposals waiting for a person. */
export function MemoryPage() {
  const { client } = useApp();
  const { can } = useCan();
  const write = mayWrite('memory', can);
  const [q, setQ] = useState('');
  const [state, setState] = useState<NoteState | 'all'>('all');
  const [editing, setEditing] = useState<MemNote | 'new' | null>(null);
  const [forgetting, setForgetting] = useState<MemNote | null>(null);
  const list = useAsync((s) => client.memory.list({ q, state }, s), [client, q, state], 6000);
  const notes = list.data?.notes ?? [];

  const approve = async (n: MemNote) => {
    try {
      await client.memory.approve(n.id);
      toast.success(t('mem.approved_toast'));
      list.reload();
    } catch (e) {
      toast.error(message(e));
    }
  };

  return (
    <AppPage>
      <PageHeader
        title={t('mem.title')}
        description={t('mem.desc')}
        actions={
          write ? (
            <Button className={`w-full sm:w-auto ${TAP_ACTION}`} onClick={() => setEditing('new')}>
              {t('mem.add')}
            </Button>
          ) : undefined
        }
      />
      {write ? null : <CannotNote cap={PAGE_CAPABILITY.memory} what={PAGE_CANNOT.memory} />}
      <StoreNote what="memory" store={list.data?.store} />
      <div className="grid gap-3 sm:grid-cols-[1fr_14rem]">
        <div className="space-y-1">
          <Label htmlFor="mem-search">{t('mem.search')}</Label>
          <Input id="mem-search" className="max-lg:h-11" value={q} onChange={(e) => setQ(e.target.value)} autoComplete="off" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="mem-state">{t('mem.filter_state')}</Label>
          <Select value={state} onValueChange={(v) => setState(v as NoteState | 'all')}>
            <SelectTrigger id="mem-state" className="max-lg:h-11">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('mem.state_all')}</SelectItem>
              <SelectItem value="pending">{t('mem.state_pending')}</SelectItem>
              <SelectItem value="approved">{t('mem.state_approved')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      {list.data ? <p className="text-xs text-muted-foreground" data-testid="mem-stats">{t('mem.stats', { approved: list.data.stats.approved, pending: list.data.stats.pending })}</p> : null}
      {!list.data && !list.error ? <Skeleton className="h-32 w-full" /> : null}
      {list.error ? <Alert variant="destructive" role="alert"><AlertDescription>{message(list.error)}</AlertDescription></Alert> : null}
      {list.data && notes.length === 0 ? <EmptyState title={t('mem.none')}>{t('mem.none_body')}</EmptyState> : null}
      <ul className="space-y-3" aria-label={t('mem.list_label')} data-testid="mem-list">
        {notes.map((n) => (
          <li key={n.id}>
            <Card className="space-y-2 p-4" data-testid="mem-note" data-state={n.state}>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-semibold">{n.title}</h2>
                <Badge variant="outline">{n.scope}</Badge>
                {n.state === 'pending' ? <Badge>{t('mem.pending_badge')}</Badge> : null}
                {n.by_agent ? <Badge variant="outline">{t('mem.agent_badge')}</Badge> : null}
                {n.expired ? <Badge variant="outline">{t('mem.expired_badge')}</Badge> : null}
              </div>
              <p className="whitespace-pre-wrap text-sm">{n.body}</p>
              {n.tags.length > 0 ? <p className="text-xs text-muted-foreground">{n.tags.map((x) => `#${x}`).join(' ')}</p> : null}
              <p className="text-xs text-muted-foreground">
                {t('mem.by', { who: n.written_by })}
                {n.reviewed_by ? ` · ${t('mem.reviewed', { who: n.reviewed_by })}` : ''}
                {n.expires_ms ? ` · ${t('mem.expires', { when: fmtRelative(iso(n.expires_ms)) })}` : ''}
                {` · ${t('mem.revision', { n: n.revision })}`}
              </p>
              <div className="flex flex-wrap gap-2">
                {write && n.state === 'pending' ? (
                  <Button className={TAP_ACTION_DEFAULT} onClick={() => void approve(n)}>
                    {t('mem.approve')}
                  </Button>
                ) : null}
                {write ? (
                  <>
                    <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setEditing(n)}>
                      {t('mem.edit')}
                    </Button>
                    <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setForgetting(n)}>
                      {t('mem.forget')}
                    </Button>
                  </>
                ) : null}
              </div>
            </Card>
          </li>
        ))}
      </ul>
      {editing ? (
        <NoteSheet
          note={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            toast.success(t('mem.saved_toast'));
            list.reload();
          }}
        />
      ) : null}
      <ConfirmDialog
        open={forgetting !== null}
        onOpenChange={(o) => !o && setForgetting(null)}
        title={t('mem.forget_title')}
        description={t('mem.forget_body')}
        confirmLabel={t('mem.forget_go')}
        destructive
        onConfirm={async () => {
          if (!forgetting) return;
          try {
            await client.memory.forget(forgetting.id);
          } catch (e) {
            // the dialog stays open, so the person sees what they were forgetting when it did not work
            toast.error(message(e));
            throw e;
          }
          setForgetting(null);
          toast.success(t('mem.forgotten_toast'));
          list.reload();
        }}
      />
    </AppPage>
  );
}

function NoteSheet({ note, onClose, onSaved }: { note: MemNote | null; onClose: () => void; onSaved: () => void }) {
  const { client } = useApp();
  const [scope, setScope] = useState(note?.scope ?? 'project:');
  const [title, setTitle] = useState(note?.title ?? '');
  const [body, setBody] = useState(note?.body ?? '');
  const [tags, setTags] = useState(note?.tags.join(', ') ?? '');
  const [days, setDays] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const tagList = tags
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
  const daysN = days.trim() === '' ? undefined : Number(days);

  const save = async () => {
    setErr(null);
    setBusy(true);
    try {
      if (note) {
        await client.memory.edit(note.id, { title, body, tags: tagList, ...(daysN !== undefined && Number.isFinite(daysN) ? { expires_days: daysN } : {}) });
      } else {
        await client.memory.add({ scope, title, body, tags: tagList, ...(daysN !== undefined && Number.isFinite(daysN) ? { expires_days: daysN } : {}) });
      }
      onSaved();
    } catch (e) {
      setErr(message(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="mem-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{note ? t('mem.sheet_edit') : t('mem.sheet_add')}</PanelSheetTitle>
          <PanelSheetDescription>{t('mem.sheet_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="mem-scope">{t('mem.f_scope')}</Label>
            <Input id="mem-scope" className="max-lg:h-11" value={scope} onChange={(e) => setScope(e.target.value)} disabled={note !== null} autoComplete="off" aria-describedby="mem-scope-help" />
            <p id="mem-scope-help" className="text-xs text-muted-foreground">{t('mem.f_scope_help')}</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor="mem-title">{t('mem.f_title')}</Label>
            <Input id="mem-title" className="max-lg:h-11" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={120} autoComplete="off" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="mem-body">{t('mem.f_body')}</Label>
            <Textarea id="mem-body" rows={6} value={body} onChange={(e) => setBody(e.target.value)} aria-describedby="mem-body-help" />
            <p id="mem-body-help" className="text-xs text-muted-foreground">{t('mem.no_secrets')}</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor="mem-tags">{t('mem.f_tags')}</Label>
            <Input id="mem-tags" className="max-lg:h-11" value={tags} onChange={(e) => setTags(e.target.value)} autoComplete="off" aria-describedby="mem-tags-help" />
            <p id="mem-tags-help" className="text-xs text-muted-foreground">{t('mem.f_tags_help')}</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor="mem-days">{t('mem.f_days')}</Label>
            <Input id="mem-days" className="max-lg:h-11" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value.replace(/[^0-9]/g, ''))} autoComplete="off" aria-describedby="mem-days-help" />
            <p id="mem-days-help" className="text-xs text-muted-foreground">{t('mem.f_days_help')}</p>
          </div>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button className={TAP_ACTION_DEFAULT} disabled={busy || !title.trim() || !body.trim()} onClick={() => void save()}>
            {t('mem.save')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
