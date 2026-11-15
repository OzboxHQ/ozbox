import { useMemo, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Skeleton } from '@/components/ui/skeleton';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../App';
import { ApiError } from '../api/client';
import type { BoxHold, BoxSkills, InstallStatus, SkillItem } from '../api/memory';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { CannotNote } from '../components/role-scope';
import { AddSkillSheet } from '../components/skills/add-sheet';
import { HistorySheet } from '../components/skills/history-sheet';
import { InstallSheet } from '../components/skills/install-sheet';
import { ProvenanceLine } from '../components/skills/provenance';
import { ReviewSheet } from '../components/skills/review-sheet';
import { SourceNote } from '../components/source-badge';
import { StoreNote } from '../components/store-note';
import { t, type MessageKey } from '../lib/i18n';
import { mayWrite, PAGE_CANNOT, PAGE_CAPABILITY } from '../lib/role-gates';
import { holdKey, originKey, skillScopeLabel } from '../lib/skills';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const STATUS_KEY: Record<InstallStatus, MessageKey> = {
  approved: 'skills.status_approved',
  needs_review: 'skills.status_needs_review',
  modified: 'skills.status_modified',
};

const SOURCE_KEY = { bundled: 'skills.source_bundled', library: 'skills.source_library', removed: 'skills.source_removed' } as const;

const message = (e: unknown) => (e instanceof ApiError ? e.message : t('skills.failed'));
const scopeLabel = (s: string) => skillScopeLabel(s, t);

interface Held {
  box: string;
  hold: BoxHold;
  folder: string;
  /** This dashboard can take a skill off that box (it runs on it). */
  canWrite: boolean;
}

/** What each box holds of one skill, read from the boxes themselves. */
function heldOf(name: string, boxes: BoxSkills[]): Held[] {
  const out: Held[] = [];
  for (const b of boxes) {
    if (b.state !== 'ok') continue;
    const places = b.skills?.find((s) => s.name === name)?.places ?? [];
    for (const hold of places) out.push({ box: b.box, hold, folder: b.agents?.find((a) => a.id === hold.agent)?.label ?? hold.agent, canWrite: b.can_write !== false });
  }
  return out;
}

/** Skills: the library, where each is installed or kept on a box's disk, and the review that makes one usable. */
export function SkillsPage() {
  const { client } = useApp();
  const { can } = useCan();
  const write = mayWrite('skills', can);
  const list = useAsync((s) => client.memory.skills(s), [client], 8000);
  const hold = useAsync((s) => client.memory.holdings(s), [client], 15000);
  const [adding, setAdding] = useState(false);
  const [installing, setInstalling] = useState<SkillItem | null>(null);
  const [reviewing, setReviewing] = useState<{ name: string; hash?: string } | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  const [removing, setRemoving] = useState<{ name: string; scope: string } | null>(null);
  const [pulling, setPulling] = useState<{ name: string; box: string } | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const skills = list.data?.skills ?? [];
  const boxes = useMemo(() => hold.data?.boxes ?? [], [hold.data]);
  const unknown = boxes.filter((b) => b.state !== 'ok');

  return (
    <AppPage>
      <PageHeader
        title={t('skills.title')}
        description={t('skills.desc')}
        actions={
          write ? (
            <Button className={TAP_ACTION_DEFAULT} onClick={() => setAdding(true)} data-testid="skill-add">
              {t('skills.add')}
            </Button>
          ) : null
        }
      />
      {write ? null : <CannotNote cap={PAGE_CAPABILITY.skills} what={PAGE_CANNOT.skills} />}
      <StoreNote what="skills" store={list.data?.store} />
      <SourceNote source={hold.data?.source} what="skills" />
      <p className="text-xs text-muted-foreground" data-testid="skills-own">
        {t('store.skills_own')} {list.data?.store?.folder ? t('store.skills_folder', { folder: list.data.store.folder }) : ''}
      </p>
      {!list.data && !list.error ? <Skeleton className="h-32 w-full" /> : null}
      {list.error ? <Alert variant="destructive" role="alert"><AlertDescription>{message(list.error)}</AlertDescription></Alert> : null}
      {hold.error ? <Alert variant="destructive" role="alert" data-testid="skills-holdings-error"><AlertDescription>{t('skills.holdings_failed', { why: message(hold.error) })}</AlertDescription></Alert> : null}
      {unknown.length > 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="skills-holdings-unknown">
          {t('skills.holdings_unknown', { boxes: unknown.map((b) => `${b.box} (${b.reason ?? b.state})`).join('; ') })}
        </p>
      ) : null}
      {list.data && skills.length === 0 ? <EmptyState title={t('skills.none')} /> : null}
      <ul className="space-y-3" aria-label={t('skills.list_label')} data-testid="skills-list">
        {skills.map((s) => {
          const held = heldOf(s.name, boxes);
          return (
            <li key={s.name}>
              <Card className="space-y-2 p-4" data-testid="skill-card" data-skill={s.name}>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-sm font-semibold">{s.name}</h2>
                  <Badge variant="outline">{t('skills.version', { v: s.version })}</Badge>
                  <Badge variant="outline">{t(SOURCE_KEY[s.source])}</Badge>
                  {s.files.some((f) => f.kind === 'script') ? <Badge variant="outline" data-testid="skill-has-scripts">{t('skills.has_scripts')}</Badge> : null}
                  {s.asks.length > 0 ? <Badge variant="outline" data-testid="skill-runs-commands">{t('skills.runs_badge')}</Badge> : null}
                </div>
                <p className="text-sm">{s.description}</p>
                <p className="text-xs text-muted-foreground" data-testid="skill-provenance">
                  <ProvenanceLine p={s.provenance} />
                  {s.shadows_bundled ? ` ${t('skills.shadows')}` : ''}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t('skills.files_n', { n: s.files.length })} · {t('skills.hash', { hash: s.hash.slice(0, 12) })}
                </p>
                {s.installs.length === 0 && held.length === 0 ? <p className="text-xs text-muted-foreground">{t('skills.not_installed')}</p> : null}
                <ul className="space-y-2">
                  {s.installs.map((i) => (
                    <li key={i.scope} className="flex flex-wrap items-center gap-2" data-testid="skill-install">
                      <span className="text-sm">{scopeLabel(i.scope)}</span>
                      <Badge variant={i.status === 'approved' ? 'default' : 'outline'}>{t(STATUS_KEY[i.status])}</Badge>
                      {i.update_available ? <span className="text-xs text-muted-foreground">{t('skills.update_available')}</span> : null}
                      {write ? (
                        <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setRemoving({ name: s.name, scope: i.scope })}>
                          {t('skills.remove')}
                        </Button>
                      ) : null}
                    </li>
                  ))}
                </ul>
                {held.length > 0 ? (
                  <div className="space-y-1" data-testid="skill-on-boxes">
                    <p className="text-xs font-medium">{t('skills.on_boxes')}</p>
                    <ul className="space-y-2">
                      {held.map((h) => (
                        <li key={`${h.box}/${h.hold.agent}`} className="flex flex-wrap items-center gap-2" data-testid="skill-box-hold" data-box={h.box} data-state={h.hold.state}>
                          <span className="text-sm">{t('skills.hold_place', { box: h.box, agent: h.folder })}</span>
                          <Badge variant={holdKey(h.hold) === 'skills.hold_matches' ? 'default' : 'outline'}>{t(holdKey(h.hold))}</Badge>
                          <Badge variant="outline" data-testid="skill-hold-origin" data-origin={h.hold.origin}>{t(originKey(h.hold))}</Badge>
                          {write && h.canWrite && h.hold.origin === 'dashboard' ? (
                            <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setPulling({ name: s.name, box: h.box })}>
                              {t('skills.hold_remove', { box: h.box })}
                            </Button>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <div className="flex flex-wrap gap-2">
                  {/* a viewer may still read what an agent would be told: the review sheet shows the files and, for them, no approve */}
                  {write ? (
                    <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setInstalling(s)}>
                      {t('skills.install')}
                    </Button>
                  ) : null}
                  <Button className={TAP_ACTION_DEFAULT} variant={write ? 'default' : 'outline'} onClick={() => setReviewing({ name: s.name })}>
                    {write ? t('skills.review') : t('skills.read')}
                  </Button>
                  {s.revisions > 0 ? (
                    <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setHistory(s.name)}>
                      {t('skills.history', { n: s.revisions })}
                    </Button>
                  ) : null}
                  {write && s.approved ? (
                    <Button
                      variant="outline"
                      className={TAP_ACTION_DEFAULT}
                      onClick={async () => {
                        try {
                          await client.memory.revoke(s.name);
                          list.reload();
                        } catch (e) {
                          toast.error(message(e));
                        }
                      }}
                    >
                      {t('skills.withdraw')}
                    </Button>
                  ) : null}
                  {write && s.source === 'library' ? (
                    <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setDeleting(s.name)}>
                      {t('skills.delete')}
                    </Button>
                  ) : null}
                </div>
              </Card>
            </li>
          );
        })}
      </ul>
      {adding ? (
        <AddSkillSheet
          skills={skills}
          store={list.data?.store}
          onClose={() => setAdding(false)}
          onDone={(item) => {
            setAdding(false);
            toast.success(t('skills.added_toast'));
            list.reload();
            setReviewing({ name: item.name });
          }}
        />
      ) : null}
      {installing ? (
        <InstallSheet
          skill={installing}
          holdings={boxes}
          onClose={() => setInstalling(null)}
          onDone={(m) => {
            setInstalling(null);
            toast.success(m);
            list.reload();
            hold.reload();
          }}
        />
      ) : null}
      {reviewing ? (
        <ReviewSheet
          name={reviewing.name}
          {...(reviewing.hash ? { hash: reviewing.hash } : {})}
          write={write}
          onClose={() => setReviewing(null)}
          onDone={() => {
            setReviewing(null);
            toast.success(t('skills.approved_toast'));
            list.reload();
          }}
        />
      ) : null}
      {history ? (
        <HistorySheet
          name={history}
          write={write}
          onClose={() => setHistory(null)}
          onRead={(hash) => setReviewing({ name: history, hash })}
          onRestored={() => {
            const n = history;
            setHistory(null);
            toast.success(t('skills.restored_toast'));
            list.reload();
            setReviewing({ name: n });
          }}
        />
      ) : null}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('skills.remove_title')}
        description={t('skills.remove_body', { scope: removing ? scopeLabel(removing.scope) : '' })}
        confirmLabel={t('skills.remove_go')}
        destructive
        onConfirm={async () => {
          if (!removing) return;
          try {
            await client.memory.uninstall(removing.name, removing.scope);
          } catch (e) {
            toast.error(message(e));
            throw e;
          }
          setRemoving(null);
          list.reload();
        }}
      />
      <ConfirmDialog
        open={pulling !== null}
        onOpenChange={(o) => !o && setPulling(null)}
        title={t('skills.hold_remove_title', { box: pulling?.box ?? '' })}
        description={t('skills.hold_remove_body', { box: pulling?.box ?? '' })}
        confirmLabel={t('skills.hold_remove_go')}
        destructive
        onConfirm={async () => {
          if (!pulling) return;
          try {
            await client.memory.pullSkill(pulling.box, pulling.name);
          } catch (e) {
            toast.error(message(e));
            throw e;
          }
          setPulling(null);
          toast.success(t('skills.hold_removed_toast'));
          list.reload();
          hold.reload();
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('skills.delete_title')}
        description={t('skills.delete_body')}
        confirmLabel={t('skills.delete_go')}
        destructive
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await client.memory.deleteSkill(deleting);
          } catch (e) {
            toast.error(message(e));
            throw e;
          }
          setDeleting(null);
          toast.success(t('skills.deleted_toast'));
          list.reload();
        }}
      />
    </AppPage>
  );
}
