import { useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import { t } from '../../lib/i18n';
import { VIA_KEY } from '../../lib/skills';
import { useAsync } from '../../lib/use-async';

/** The versions of a skill of your own that the library keeps: read one, or make it current again (it then needs approval). */
export function HistorySheet({ name, write, onClose, onRead, onRestored }: { name: string; write: boolean; onClose: () => void; onRead: (hash: string) => void; onRestored: () => void }) {
  const { client } = useApp();
  const h = useAsync((s) => client.memory.skillHistory(name, s), [client, name]);
  const [err, setErr] = useState<string | null>(null);
  const rows = h.data?.revisions ?? [];
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="skill-history-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('skills.history_title', { name })}</PanelSheetTitle>
          <PanelSheetDescription>{t('skills.history_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          {!h.data && !h.error ? <Skeleton className="h-16 w-full" /> : null}
          {h.error ? <Alert variant="destructive" role="alert"><AlertDescription>{h.error.message}</AlertDescription></Alert> : null}
          {h.data && rows.length === 0 ? <p className="text-sm">{t('skills.history_none')}</p> : null}
          <ul className="space-y-2">
            {rows.map((r) => (
              <li key={r.hash} className="space-y-1 rounded-md border p-3" data-testid="skill-revision">
                <p className="break-words text-sm">
                  {t('skills.history_row', {
                    v: r.version,
                    hash: r.hash.slice(0, 12),
                    how: r.by === 'unknown' ? t('skills.via_folder') : `${r.by} ${t(VIA_KEY[r.via as keyof typeof VIA_KEY] ?? 'skills.via_folder')}`,
                    when: r.ms ? new Date(r.ms).toLocaleString() : '-',
                  })}
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  {r.current ? <Badge variant="outline">{t('skills.history_current')}</Badge> : null}
                  <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => onRead(r.hash)}>{t('skills.history_read')}</Button>
                  {write && !r.current ? (
                    <Button
                      variant="outline"
                      className={TAP_ACTION_DEFAULT}
                      onClick={async () => {
                        try {
                          await client.memory.restoreSkill(name, r.hash);
                          onRestored();
                        } catch (e) {
                          setErr(e instanceof ApiError ? e.message : t('skills.failed'));
                        }
                      }}
                    >
                      {t('skills.history_restore')}
                    </Button>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>{t('common.close')}</Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
