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
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { useApp } from '../App';
import { ApiError } from '../api/client';
import type { InstallStatus, SkillItem, SkillReview } from '../api/memory';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { CannotNote } from '../components/role-scope';
import { StoreNote } from '../components/store-note';
import { t, type MessageKey } from '../lib/i18n';
import { mayWrite, PAGE_CANNOT, PAGE_CAPABILITY } from '../lib/role-gates';
import { skillScopeLabel } from '../lib/skills';
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

/** Skills: the catalog, where each is installed, and the review that makes one usable. */
export function SkillsPage() {
  const { client } = useApp();
  const { can } = useCan();
  const write = mayWrite('skills', can);
  const list = useAsync((s) => client.memory.skills(s), [client], 8000);
  const [installing, setInstalling] = useState<SkillItem | null>(null);
  const [reviewing, setReviewing] = useState<SkillItem | null>(null);
  const [removing, setRemoving] = useState<{ name: string; scope: string } | null>(null);
  const skills = list.data?.skills ?? [];

  return (
    <AppPage>
      <PageHeader title={t('skills.title')} description={t('skills.desc')} />
      {write ? null : <CannotNote cap={PAGE_CAPABILITY.skills} what={PAGE_CANNOT.skills} />}
      <StoreNote what="skills" store={list.data?.store} />
      <p className="text-xs text-muted-foreground" data-testid="skills-own">{t('store.skills_own')}</p>
      {!list.data && !list.error ? <Skeleton className="h-32 w-full" /> : null}
      {list.error ? <Alert variant="destructive" role="alert"><AlertDescription>{message(list.error)}</AlertDescription></Alert> : null}
      {list.data && skills.length === 0 ? <EmptyState title={t('skills.none')} /> : null}
      <ul className="space-y-3" aria-label={t('skills.list_label')} data-testid="skills-list">
        {skills.map((s) => (
          <li key={s.name}>
            <Card className="space-y-2 p-4" data-testid="skill-card" data-skill={s.name}>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-semibold">{s.name}</h2>
                <Badge variant="outline">{t('skills.version', { v: s.version })}</Badge>
                <Badge variant="outline">{t(SOURCE_KEY[s.source])}</Badge>
              </div>
              <p className="text-sm">{s.description}</p>
              <p className="text-xs text-muted-foreground">
                {t('skills.files_n', { n: s.files.length })} · {t('skills.hash', { hash: s.hash.slice(0, 12) })}
              </p>
              {s.installs.length === 0 ? <p className="text-xs text-muted-foreground">{t('skills.not_installed')}</p> : null}
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
              <div className="flex flex-wrap gap-2">
                {/* a viewer may still read what an agent would be told: the review sheet shows the files and, for them, no approve */}
                {write ? (
                  <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => setInstalling(s)}>
                    {t('skills.install')}
                  </Button>
                ) : null}
                <Button className={TAP_ACTION_DEFAULT} variant={write ? 'default' : 'outline'} onClick={() => setReviewing(s)}>
                  {write ? t('skills.review') : t('skills.read')}
                </Button>
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
              </div>
            </Card>
          </li>
        ))}
      </ul>
      {installing ? (
        <InstallSheet
          skill={installing}
          onClose={() => setInstalling(null)}
          onDone={() => {
            setInstalling(null);
            toast.success(t('skills.installed_toast'));
            list.reload();
          }}
        />
      ) : null}
      {reviewing ? (
        <ReviewSheet
          skill={reviewing}
          write={write}
          onClose={() => setReviewing(null)}
          onDone={() => {
            setReviewing(null);
            toast.success(t('skills.approved_toast'));
            list.reload();
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
    </AppPage>
  );
}

function InstallSheet({ skill, onClose, onDone }: { skill: SkillItem; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const [kind, setKind] = useState<'fleet' | 'box' | 'project'>('fleet');
  const [target, setTarget] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const scope = kind === 'fleet' ? 'fleet' : `${kind}:${target.trim()}`;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="skill-install-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('skills.install_title', { name: skill.name })}</PanelSheetTitle>
          <PanelSheetDescription>{t('skills.install_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="skill-scope">{t('skills.install_scope')}</Label>
            <Select value={kind} onValueChange={(v) => { setKind(v as 'fleet' | 'box' | 'project'); setTarget(''); }}>
              <SelectTrigger id="skill-scope" className="max-lg:h-11" aria-describedby="skill-scope-help">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="fleet">{t('skills.scope_fleet')}</SelectItem>
                <SelectItem value="box">{t('skills.scope_kind_box')}</SelectItem>
                <SelectItem value="project">{t('skills.scope_kind_project')}</SelectItem>
              </SelectContent>
            </Select>
            <p id="skill-scope-help" className="text-xs text-muted-foreground">{t('skills.install_scope_help')}</p>
          </div>
          {kind === 'box' && boxes.error ? <Alert variant="destructive" role="alert" data-testid="skill-boxes-error"><AlertDescription>{message(boxes.error)}</AlertDescription></Alert> : null}
          {kind === 'box' ? (
            <div className="space-y-1">
              <Label htmlFor="skill-scope-box">{t('skills.scope_box_label')}</Label>
              <Select value={target} onValueChange={setTarget}>
                <SelectTrigger id="skill-scope-box" className="max-lg:h-11">
                  <SelectValue placeholder={t('skills.scope_box_pick')} />
                </SelectTrigger>
                <SelectContent>
                  {(boxes.data ?? []).map((b) => (
                    <SelectItem key={b.spec.name} value={b.spec.name}>
                      {b.spec.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : null}
          {kind === 'project' ? (
            <div className="space-y-1">
              <Label htmlFor="skill-scope-project">{t('skills.scope_project_label')}</Label>
              <Input id="skill-scope-project" className="max-lg:h-11" value={target} onChange={(e) => setTarget(e.target.value)} autoComplete="off" />
            </div>
          ) : null}
          <p className="text-sm" data-testid="skill-scope-says">{t('skills.scope_says', { where: skillScopeLabel(scope, t) })}</p>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            className={TAP_ACTION_DEFAULT}
            disabled={kind !== 'fleet' && !target.trim()}
            onClick={async () => {
              try {
                await client.memory.install(skill.name, scope);
                onDone();
              } catch (e) {
                setErr(message(e));
              }
            }}
          >
            {t('skills.install_go')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function ReviewSheet({ skill, write, onClose, onDone }: { skill: SkillItem; write: boolean; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const review = useAsync<SkillReview>((s) => client.memory.review(skill.name, s), [client, skill.name]);
  const [err, setErr] = useState<string | null>(null);
  const r = review.data;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="skill-review-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('skills.review_title', { name: skill.name })}</PanelSheetTitle>
          <PanelSheetDescription>{t('skills.review_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          {!r && !review.error ? <Skeleton className="h-24 w-full" /> : null}
          {review.error ? <Alert variant="destructive" role="alert" data-testid="skill-review-error"><AlertDescription>{message(review.error)}</AlertDescription></Alert> : null}
          {r?.files.map((f) => (
            <section key={f.path} className="space-y-1" aria-label={f.path}>
              <h3 className="text-xs font-semibold">{f.path}</h3>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border p-3 text-xs" tabIndex={0}>{f.text}</pre>
            </section>
          ))}
          {r ? <p className="text-xs text-muted-foreground">{t('skills.review_hash', { hash: r.hash.slice(0, 12) })}</p> : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {write ? t('common.cancel') : t('common.close')}
          </Button>
          {write ? (
          <Button
            className={TAP_ACTION_DEFAULT}
            disabled={!r}
            onClick={async () => {
              if (!r) return;
              try {
                await client.memory.approveSkill(skill.name, r.hash);
                onDone();
              } catch (e) {
                setErr(e instanceof ApiError && e.status === 409 ? t('skills.stale') : message(e));
              }
            }}
          >
            {t('skills.approve_go')}
          </Button>
          ) : null}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
