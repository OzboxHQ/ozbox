import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { ApiError } from '../../api/error';
import { CHAT_ACTS } from '../../api/chat-acts';
import { useApp } from '../../App';
import { t } from '../../lib/i18n';
import { useAsync } from '../../lib/use-async';
import { TelegramLinkSheet } from './link-sheet';

const TIER_KEY = {
  read: 'tg.tier_read',
  converse: 'tg.tier_converse',
  power: 'tg.tier_power',
  run: 'tg.tier_run',
  handoff: 'tg.tier_handoff',
  refused: 'tg.tier_refused',
} as const;

const NEEDS_KEY = {
  nothing: 'tg.needs_nothing',
  converse: 'tg.needs_converse',
  power: 'tg.needs_power',
  run: 'tg.needs_run',
} as const;

/** What a chat can do: the one table every message is read against, as the server holds it. */
export function ActTable() {
  return (
    <section className="space-y-2" aria-labelledby="tg-acts-h" data-testid="tg-acts">
      <h3 id="tg-acts-h" className="text-xs font-medium">{t('tg.acts_title')}</h3>
      <p className="text-xs text-muted-foreground">{t('tg.acts_help')}</p>
      <ul className="space-y-1">
        {CHAT_ACTS.map((r) => (
          <li key={r.id} className="rounded-md border p-2 text-xs" data-testid={`tg-act-${r.id}`}>
            <p className="break-words font-mono">{r.command}</p>
            <p className="text-muted-foreground">
              {t(TIER_KEY[r.tier])} · {t(NEEDS_KEY[r.needs])}
              {r.built ? '' : ` · ${t('tg.not_built')}`}
            </p>
            <p>{r.about}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Production boxes and the hub: an owner marks them, with a passkey shown a moment ago. */
function Marks({ production, hub, reload }: { production: string[]; hub: string | null; reload: () => void }) {
  const { client } = useApp();
  const [text, setText] = useState(production.join('\n'));
  const [hubName, setHubName] = useState(hub ?? '');
  const [busy, setBusy] = useState(false);
  async function save() {
    setBusy(true);
    try {
      const names = text.split('\n').map((x) => x.trim()).filter(Boolean);
      await client.telegram.setMarks(names, hubName.trim() || null);
      toast.success(t('tg.marks_save'));
      reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('tg.failed'));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="space-y-2" aria-labelledby="tg-marks-h" data-testid="tg-marks">
      <h3 id="tg-marks-h" className="text-xs font-medium">{t('tg.marks_title')}</h3>
      <p className="text-xs text-muted-foreground">{t('tg.marks_help')}</p>
      <div className="space-y-1.5">
        <Label htmlFor="tg-marks-production">{t('tg.marks_production')}</Label>
        <Textarea id="tg-marks-production" value={text} rows={3} onChange={(e) => setText(e.target.value)} data-testid="tg-marks-production" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="tg-marks-hub">{t('tg.marks_hub')}</Label>
        <Input id="tg-marks-hub" value={hubName} onChange={(e) => setHubName(e.target.value)} data-testid="tg-marks-hub" className="max-lg:h-11" />
      </div>
      <Button size="sm" className="max-lg:h-11" disabled={busy} onClick={() => void save()} data-testid="tg-marks-save">{t('tg.marks_save')}</Button>
    </section>
  );
}

/**
 * The Telegram guided setup inside Settings, Apps: the preview mark, what a chat can and cannot do, the bridge's stops, the marks
 * and the way to link an account. Linking itself is the sheet in `link-sheet.tsx`.
 */
export function TelegramSetup({ open, onOpenChange, reload }: { open: boolean; onOpenChange: (o: boolean) => void; reload: () => void }) {
  const { client } = useApp();
  const status = useAsync((s) => client.telegram.status(s), [open]);
  const boxes = useAsync((s) => client.listBoxes(s).then((b) => b.map((x) => x.spec.name)), []);
  const s = status.data;
  const refresh = () => {
    status.reload();
    reload();
  };
  if (!s) return status.error ? <Alert variant="destructive" role="alert"><AlertDescription>{status.error.message}</AlertDescription></Alert> : <Skeleton className="h-12 w-full" />;
  return (
    <div className="space-y-3" data-testid="tg-setup">
      <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground" data-testid="tg-preview-note">
        <Badge variant="outline">{t('tg.preview')}</Badge>
        <span className="min-w-0 flex-1 break-words">{t('tg.preview_note')}</span>
      </p>
      <p className="text-xs text-muted-foreground">{t('tg.never')}</p>
      {s.needs_sign_in ? <Alert role="status" data-testid="tg-needs-sign-in"><AlertDescription>{t('tg.needs_sign_in')}</AlertDescription></Alert> : null}
      {!s.public_address ? <Alert role="status" data-testid="tg-no-address"><AlertDescription>{t('tg.no_address')}</AlertDescription></Alert> : null}
      {s.halted ? (
        <Alert variant="destructive" role="alert" data-testid="tg-halted">
          <AlertDescription className="space-y-2">
            <span className="block font-medium">{t('tg.halted')}</span>
            <span className="block">{s.halted.message}</span>
            <Button size="sm" className="max-lg:h-11" onClick={() => void client.telegram.resume().then(refresh).catch((e: unknown) => toast.error(e instanceof ApiError ? e.message : t('tg.failed')))} data-testid="tg-resume">{t('tg.resume')}</Button>
          </AlertDescription>
        </Alert>
      ) : null}
      <Marks key={`${s.marks.production.join(',')}|${s.marks.hub ?? ''}`} production={s.marks.production} hub={s.marks.hub} reload={refresh} />
      <ActTable />
      <TelegramLinkSheet open={open} onOpenChange={onOpenChange} status={s} boxes={boxes.data ?? []} reload={refresh} />
    </div>
  );
}
