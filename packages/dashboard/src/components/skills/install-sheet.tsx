import { useEffect, useMemo, useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { BoxSkills, PushResult, SkillItem } from '../../api/memory';
import { t } from '../../lib/i18n';
import { skillScopeLabel } from '../../lib/skills';
import { useAsync } from '../../lib/use-async';

type Kind = 'fleet' | 'box' | 'project' | 'disk';

const message = (e: unknown) => (e instanceof ApiError ? e.message : t('skills.failed'));

/** Where an approved skill goes: a scope the tool host reads from, or the folders a box's own coding agents read. */
export function InstallSheet({ skill, holdings, onClose, onDone }: { skill: SkillItem; holdings: BoxSkills[]; onClose: () => void; onDone: (toast: string) => void }) {
  const { client } = useApp();
  const [kind, setKind] = useState<Kind>('fleet');
  const [target, setTarget] = useState('');
  const [agents, setAgents] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const boxes = useAsync((s) => client.listBoxes(s), [client]);
  const scope = kind === 'fleet' ? 'fleet' : `${kind}:${target.trim()}`;
  const running = useMemo(() => (boxes.data ?? []).filter((b) => b.state === 'running'), [boxes.data]);
  const known = holdings.find((h) => h.box === target);
  const folders = known?.agents ?? [];
  const presentKey = folders.filter((a) => a.present).map((a) => a.id).join(',');

  // the folders a box has set up are chosen for it; one with none set up gets Claude Code's
  useEffect(() => {
    if (kind !== 'disk' || !target) return;
    const present = presentKey ? presentKey.split(',') : [];
    setAgents(present.length > 0 ? present : ['claude-code']);
  }, [kind, target, presentKey]);

  const go = async () => {
    setBusy(true);
    try {
      if (kind === 'disk') {
        const r: PushResult = await client.memory.pushSkill(target, skill.name, skill.hash, agents);
        const bad = r.results.filter((x) => !x.ok);
        if (bad.length > 0) {
          setErr(t('skills.disk_partial', { box: target, why: bad.map((x) => x.message ?? x.agent).join(' ') }));
          setBusy(false);
          return;
        }
        onDone(t('skills.disk_done', { box: target }));
      } else {
        await client.memory.install(skill.name, scope);
        onDone(t('skills.installed_toast'));
      }
    } catch (e) {
      setErr(message(e));
      setBusy(false);
    }
  };

  const labels = agents.map((id) => folders.find((a) => a.id === id)?.label ?? id).join(', ');
  const blocked = kind === 'disk' && !skill.approved;
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="skill-install-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('skills.install_title', { name: skill.name })}</PanelSheetTitle>
          <PanelSheetDescription>{t('skills.install_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert" data-testid="skill-install-error"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="skill-scope">{t('skills.install_scope')}</Label>
            <Select value={kind} onValueChange={(v) => { setKind(v as Kind); setTarget(''); setErr(null); }}>
              <SelectTrigger id="skill-scope" className="max-lg:h-11" aria-describedby="skill-scope-help">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="fleet">{t('skills.scope_fleet')}</SelectItem>
                <SelectItem value="box">{t('skills.scope_kind_box')}</SelectItem>
                <SelectItem value="project">{t('skills.scope_kind_project')}</SelectItem>
                <SelectItem value="disk">{t('skills.scope_kind_disk')}</SelectItem>
              </SelectContent>
            </Select>
            <p id="skill-scope-help" className="text-xs text-muted-foreground">{kind === 'disk' ? t('skills.disk_help') : t('skills.install_scope_help')}</p>
          </div>
          {(kind === 'box' || kind === 'disk') && boxes.error ? <Alert variant="destructive" role="alert" data-testid="skill-boxes-error"><AlertDescription>{message(boxes.error)}</AlertDescription></Alert> : null}
          {kind === 'box' || kind === 'disk' ? (
            <div className="space-y-1">
              <Label htmlFor="skill-scope-box">{t(kind === 'disk' ? 'skills.disk_box_label' : 'skills.scope_box_label')}</Label>
              <Select value={target} onValueChange={setTarget}>
                <SelectTrigger id="skill-scope-box" className="max-lg:h-11">
                  <SelectValue placeholder={t('skills.scope_box_pick')} />
                </SelectTrigger>
                <SelectContent>
                  {(kind === 'disk' ? running : boxes.data ?? []).map((b) => (
                    <SelectItem key={b.spec.name} value={b.spec.name}>
                      {b.spec.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {kind === 'disk' && boxes.data && running.length === 0 ? <p className="text-xs text-muted-foreground" data-testid="skill-disk-no-boxes">{t('skills.disk_no_boxes')}</p> : null}
            </div>
          ) : null}
          {kind === 'project' ? (
            <div className="space-y-1">
              <Label htmlFor="skill-scope-project">{t('skills.scope_project_label')}</Label>
              <Input id="skill-scope-project" className="max-lg:h-11" value={target} onChange={(e) => setTarget(e.target.value)} autoComplete="off" />
            </div>
          ) : null}
          {kind === 'disk' && target && folders.length > 0 ? (
            <fieldset className="space-y-1" data-testid="skill-disk-folders">
              <legend className="text-sm font-medium">{t('skills.disk_agents_label')}</legend>
              {folders.map((a) => (
                <div key={a.id} className="flex items-start gap-1">
                  <TouchCheckbox id={`sk-agent-${a.id}`} checked={agents.includes(a.id)} onCheckedChange={(c) => setAgents(c === true ? [...agents, a.id] : agents.filter((x) => x !== a.id))} />
                  <Label htmlFor={`sk-agent-${a.id}`} className="pt-3 lg:pt-0.5">
                    {a.label} ({a.folder}): {t('skills.agent_codex', { who: a.reaches })} {a.present ? t('skills.disk_present') : t('skills.disk_absent')}
                  </Label>
                </div>
              ))}
            </fieldset>
          ) : null}
          {blocked ? <Alert data-testid="skill-disk-not-approved"><AlertDescription>{t('skills.disk_not_approved')}</AlertDescription></Alert> : null}
          {kind === 'disk' ? (
            <p className="text-sm" data-testid="skill-scope-says">{target && labels ? t('skills.disk_says', { name: skill.name, where: labels, box: target }) : ''}</p>
          ) : (
            <p className="text-sm" data-testid="skill-scope-says">{t('skills.scope_says', { where: skillScopeLabel(scope, t) })}</p>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button className={TAP_ACTION_DEFAULT} disabled={busy || blocked || (kind !== 'fleet' && !target.trim()) || (kind === 'disk' && agents.length === 0)} onClick={go}>
            {kind === 'disk' ? t('skills.disk_go') : t('skills.install_go')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
